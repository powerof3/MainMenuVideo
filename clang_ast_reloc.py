"""Relocation ID collection via clang.exe JSON AST.

Drop-in replacement for `_collect_relocations_from_tu(tu, addr_lib, is_ae)` and
`_collect_src_relocations(src_dir, addr_lib, ...)` in parse_commonlib_types.py.
Runs clang.exe with full function bodies + `-ast-dump=json -ast-dump-filter=RE::`
and stream-parses the output to find:

  - REL::Relocation<T>     VarDecls → function symbols (SE or AE offset)
  - const REL::ID          VarDecls in RE::Offset::... → offset_id_map
  - RTTI_* / VTABLE_*      VarDecls → label symbols
  - CXXMethodDecl with     storageClass == "static" → static_methods set

Because `RELOCATION_ID(SE, AE)` is a preprocessor macro that strips one arg,
the AST sees exactly one integer literal per site (either the SE or AE value
depending on whether SKYRIM_SUPPORT_AE was defined).  To collect both, we run
two passes (one per build mode) and merge by symbol name.

Offset:: references in src/.cpp files are resolved via the target VarDecl's
clang-assigned `id` (stable within a TU).  For cross-TU resolution we also
accept a pre-built qualified-name → id map via `extra_offset_map`.
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from clangd_template_layouts import find_clang_binary


def _build_driver_args(parse_args):
    """Convert libclang-style parse_args to clang driver args."""
    out = []
    i = 0
    while i < len(parse_args):
        a = parse_args[i]
        if a in ('-x', '--language'):
            i += 2
            continue
        if a in ('-isystem', '-include', '-MF'):
            if i + 1 < len(parse_args):
                out.append(a)
                out.append(parse_args[i + 1])
                i += 2
                continue
        if any(a.startswith(p) for p in ('-I', '-D', '-std', '-f', '-W', '-m')):
            out.append(a)
        i += 1
    return out


def _iter_toplevel_objects(stream):
    """Yield each top-level JSON object from a concatenated-JSON stream."""
    decoder = json.JSONDecoder()
    buf = ''
    CHUNK = 1 << 20
    while True:
        data = stream.read(CHUNK)
        if not data:
            break
        buf += data
        i = 0
        n = len(buf)
        while i < n:
            while i < n and buf[i].isspace():
                i += 1
            if i >= n:
                break
            try:
                obj, j = decoder.raw_decode(buf, i)
            except json.JSONDecodeError:
                break
            yield obj
            i = j
        buf = buf[i:]
    buf = buf.strip()
    if buf:
        obj = json.loads(buf)
        yield obj


# Variable names too generic to use as the symbol (we use the enclosing
# method's name instead).  Matches the libclang walker's behavior.
_GENERIC_VAR_NAMES = frozenset({
    'func', 'fn', 'function', 'call', 'impl', 'f', 'thunk', 'trampoline',
    'orig', 'detour', 'hook', 'target', 'addr', 'address',
})


# ---------------------------------------------------------------------------
# Tree helpers
# ---------------------------------------------------------------------------

def _collect_int_literals(node: dict, depth: int = 0, limit: int = 15) -> List[int]:
    """Return all IntegerLiteral values in `node`'s subtree (in traversal order)."""
    if depth > limit:
        return []
    vals: List[int] = []
    if node.get('kind') == 'IntegerLiteral':
        v = node.get('value')
        if v is not None:
            try:
                vals.append(int(v))
            except (TypeError, ValueError):
                pass
    for c in node.get('inner', []) or []:
        vals.extend(_collect_int_literals(c, depth + 1, limit))
    return vals


def _first_declref_id(node: dict, depth: int = 0, limit: int = 15) -> Optional[str]:
    """First DeclRefExpr.referencedDecl.id in `node`'s subtree, or None."""
    if depth > limit:
        return None
    if node.get('kind') == 'DeclRefExpr':
        ref = node.get('referencedDecl') or {}
        rid = ref.get('id')
        if rid:
            return rid
    for c in node.get('inner', []) or []:
        r = _first_declref_id(c, depth + 1, limit)
        if r:
            return r
    return None


def _first_declref_name(node: dict, depth: int = 0, limit: int = 15) -> Optional[str]:
    if depth > limit:
        return None
    if node.get('kind') == 'DeclRefExpr':
        ref = node.get('referencedDecl') or {}
        nm = ref.get('name')
        if nm:
            return nm
    for c in node.get('inner', []) or []:
        r = _first_declref_name(c, depth + 1, limit)
        if r:
            return r
    return None


# ---------------------------------------------------------------------------
# Type spelling helpers
# ---------------------------------------------------------------------------

_RELOC_TYPE_RE = re.compile(r'^REL::Relocation<(.+)>$')


def _parse_reloc_spelling(type_sp: str) -> Optional[Tuple[str, Optional[str], str]]:
    """Parse 'REL::Relocation<T>' to (ret, class_or_None, params) as C++ strings."""
    m = _RELOC_TYPE_RE.match(type_sp.strip())
    if not m:
        return None
    inner = m.group(1).strip()
    # Member function pointer: 'ret (Ns::Cls::*)(params)'
    mfp = re.match(r'^(.+?)\s*\(([\w:]+)::\*\)\s*\(([^)]*)\)', inner)
    if mfp:
        return mfp.group(1).strip(), mfp.group(2), mfp.group(3).strip()
    # Plain function type: 'ret (params)' — find outermost trailing parens
    depth_p = 0
    last_open = -1
    for i in range(len(inner) - 1, -1, -1):
        if inner[i] == ')':
            depth_p += 1
        elif inner[i] == '(':
            depth_p -= 1
            if depth_p == 0:
                last_open = i
                break
    if last_open < 0:
        return None
    return inner[:last_open].strip(), None, inner[last_open + 1:-1].strip()


_WS_RE = re.compile(r'[\s\xa0]+')


def _norm_type(s: str) -> str:
    return _WS_RE.sub(' ', s).strip()


def _method_signature(qual_type: str, param_names: List[str]) -> Tuple[str, str]:
    """Split a CXXMethodDecl qualType 'ret (p1, p2)' into (ret, params_str).

    `param_names` is the list of ParmVarDecl names to merge into the params.
    """
    qt = qual_type.strip()
    # Trailing-return-type `auto (...) -> T` is not parseable by Ghidra's C
    # parser (both `auto` and the `->` syntax choke it).  Drop the signature
    # entirely so the symbol's name is still applied without a prototype.
    if qt.startswith('auto ') and ' -> ' in qt:
        return '', ''
    # Find the last top-level ')' (skipping trailing cv/ref/noexcept qualifiers).
    depth = 0
    last_close = -1
    for i in range(len(qt) - 1, -1, -1):
        if qt[i] == ')':
            if depth == 0:
                last_close = i
                break
    if last_close < 0:
        return _norm_type(qt), ''
    # Walk back from last_close to matching '('.
    depth = 1
    last_open = -1
    for i in range(last_close - 1, -1, -1):
        if qt[i] == ')':
            depth += 1
        elif qt[i] == '(':
            depth -= 1
            if depth == 0:
                last_open = i
                break
    if last_open < 0:
        return _norm_type(qt), ''
    ret = _norm_type(qt[:last_open])
    params_raw = qt[last_open + 1:last_close]
    # Split params at top level commas
    parts: List[str] = []
    depth = 0
    buf = ''
    for ch in params_raw:
        if ch == '<' or ch == '(' or ch == '[':
            depth += 1
        elif ch == '>' or ch == ')' or ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(buf.strip())
            buf = ''
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    out_parts: List[str] = []
    for i, p in enumerate(parts):
        ptype = _norm_type(p)
        pname = param_names[i] if i < len(param_names) else ''
        if pname:
            out_parts.append(f'{ptype} {pname}'.strip())
        else:
            out_parts.append(ptype)
    return ret, ', '.join(out_parts)


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------

class _Walker:
    """Stateful JSON AST walker for relocation scanning.

    Builds two outputs in a single pass:
      - Maps of Offset::... → (int_id, var_clang_id) for DeclRefExpr resolution
      - func_syms / label_syms / static_methods

    Nested functions / classes are supported via context stacks.
    """

    def __init__(self, addr_lib, is_ae: bool, strip_re: bool = True):
        self.addr_lib = addr_lib
        self.is_ae = is_ae
        self.strip_re = strip_re

        # Outputs
        self.func_syms: List[dict] = []
        self.label_syms: List[dict] = []
        self.static_methods: set = set()
        self.offset_id_map: Dict[str, int] = {}   # qualified_name → int
        self.id_to_int: Dict[str, int] = {}       # clang VarDecl id → int (any REL::ID with literal)
        self.id_to_qualname: Dict[str, str] = {}  # clang VarDecl id → qualified name
        self.missed: List[tuple] = []

        # Dedup
        self._seen_se: set = set()
        self._seen_ae: set = set()

    # ------------------------------------------------------------------
    # Entry: walk a top-level decl
    # ------------------------------------------------------------------
    def walk_toplevel(self, node: dict, scope: List[str]):
        """scope is the parent namespace/class stack (e.g. ['RE'])."""
        self._walk(node, ns=scope, cls=[], method=None)

    # ------------------------------------------------------------------
    # Core recursion
    # ------------------------------------------------------------------
    def _walk(
        self,
        node: dict,
        ns: List[str],
        cls: List[str],
        method: Optional[dict],
    ):
        k = node.get('kind')
        nm = node.get('name') or ''

        # Scope tracking
        if k == 'NamespaceDecl':
            new_ns = ns + [nm] if nm else ns
            for c in node.get('inner', []) or []:
                self._walk(c, new_ns, cls, method)
            return
        if k in ('ClassTemplateDecl', 'FunctionTemplateDecl',
                 'CXXDeductionGuideDecl'):
            # Pass through — the inner CXXRecordDecl/FunctionDecl handles
            # its own scope push, avoiding double-count.
            for c in node.get('inner', []) or []:
                self._walk(c, ns, cls, method)
            return
        if k in ('CXXRecordDecl', 'ClassTemplatePartialSpecializationDecl'):
            if k == 'CXXRecordDecl' and not node.get('completeDefinition'):
                return
            # Avoid double-pushing: if `nm` equals the last cls entry
            # (e.g. a self-referential injected class name) skip.
            if nm and (not cls or cls[-1] != nm):
                new_cls = cls + [nm]
            else:
                new_cls = cls
            for c in node.get('inner', []) or []:
                self._walk(c, ns, new_cls, method)
            return

        # Method / function definition: capture context for contained VarDecls
        if k in ('CXXMethodDecl', 'FunctionDecl', 'CXXConstructorDecl', 'CXXDestructorDecl'):
            storage = node.get('storageClass')
            is_static = (storage == 'static')
            mangled = node.get('mangledName')
            # Prefer the FULL qualified scope parsed from mangledName — this
            # gives the authoritative class for out-of-line definitions in
            # .cpp files (where the syntactic cls stack is empty).
            fcls: Optional[str] = None
            if k == 'CXXMethodDecl' and mangled:
                full = _scope_from_mangled(mangled)
                if full:
                    fcls = self._strip_re(full)
            if fcls is None and k == 'CXXMethodDecl' and cls:
                fcls = self._format_qual(ns + cls)
            elif fcls is None and k == 'FunctionDecl' and ns:
                inner_ns = [n for n in ns if n != 'RE' and n != 'detail' and n]
                if inner_ns:
                    fcls = '::'.join(inner_ns)
            if k == 'CXXMethodDecl' and is_static and nm and fcls:
                self.static_methods.add((fcls, nm))
            # Only descend into definitions that have bodies
            has_body = any(
                (c.get('kind') or '').endswith('Stmt')
                for c in node.get('inner', []) or []
            )
            if not has_body:
                return
            # Build method context
            pnames: List[str] = []
            for i, c in enumerate(node.get('inner', []) or []):
                if c.get('kind') == 'ParmVarDecl':
                    pnames.append(c.get('name') or f'p{i}')
            qt = (node.get('type') or {}).get('qualType') or ''
            ret, params = _method_signature(qt, pnames)
            new_method = {
                'name': nm,
                'class': fcls,
                'ret': ret,
                'params': params,
                'static': is_static,
            }
            for c in node.get('inner', []) or []:
                self._walk(c, ns, cls, new_method)
            return

        # VarDecl — main target
        if k == 'VarDecl':
            self._handle_vardecl(node, ns, cls, method)
            # VarDecls can themselves contain children (init exprs, etc.) but
            # those aren't VarDecls so no need to recurse for reloc purposes.
            return

        # Generic recursion
        for c in node.get('inner', []) or []:
            self._walk(c, ns, cls, method)

    # ------------------------------------------------------------------
    # VarDecl handler
    # ------------------------------------------------------------------
    def _handle_vardecl(self, node: dict, ns: List[str], cls: List[str],
                        method: Optional[dict]):
        var_name = node.get('name') or ''
        vid = node.get('id')
        type_sp = (node.get('type') or {}).get('qualType') or ''
        type_sp_n = _norm_type(type_sp)

        # Bookkeeping: index every VarDecl by id with qualified name
        if vid:
            qname_parts = ns + cls + [var_name]
            self.id_to_qualname[vid] = '::'.join(p for p in qname_parts if p)

        # ------------------------------------------------------------------
        # const REL::ID → offset_id_map + id_to_int (any scope, not just Offset::)
        # ------------------------------------------------------------------
        if type_sp_n in ('REL::ID', 'const REL::ID') and not var_name.startswith(('RTTI_', 'VTABLE_')):
            ids = _collect_int_literals(node)
            if ids:
                if vid:
                    self.id_to_int[vid] = ids[0]
                # Build qualified name (strip RE:: and Offset:: prefixes to
                # match libclang's _scan_offset_ids).  This is what
                # DeclRefExpr resolution looks up for Offset:: references.
                parts = ns + cls + [var_name]
                # Strip 'RE::Offset::' or 'Offset::' prefix if present
                if parts[:2] == ['RE', 'Offset']:
                    key_parts = parts[2:]
                elif parts[:1] == ['Offset']:
                    key_parts = parts[1:]
                else:
                    key_parts = parts
                key = '::'.join(p for p in key_parts if p)
                if key:
                    self.offset_id_map[key] = ids[0]

        # ------------------------------------------------------------------
        # REL::Relocation<T> → function symbol
        # ------------------------------------------------------------------
        if 'REL::Relocation<' in type_sp:
            self._handle_reloc_var(node, var_name, type_sp_n, method)
            return

        # ------------------------------------------------------------------
        # RTTI_* / VTABLE_* labels
        # ------------------------------------------------------------------
        if var_name.startswith(('RTTI_', 'VTABLE_')):
            ids = _collect_int_literals(node)
            if ids:
                the_id = ids[0]
                if self.is_ae:
                    off = self.addr_lib.ae_db.get(the_id)
                    if off and the_id not in self._seen_ae:
                        self._seen_ae.add(the_id)
                        self.label_syms.append(
                            {'name': var_name, 'se_off': None, 'ae_off': off}
                        )
                else:
                    off = self.addr_lib.se_db.get(the_id)
                    if off and the_id not in self._seen_se:
                        self._seen_se.add(the_id)
                        self.label_syms.append(
                            {'name': var_name, 'se_off': off, 'ae_off': None}
                        )

    # ------------------------------------------------------------------
    # REL::Relocation<T> var handler
    # ------------------------------------------------------------------
    def _handle_reloc_var(self, node: dict, var_name: str, type_sp: str,
                          method: Optional[dict]):
        # Prefer an IntegerLiteral in the subtree (most common case: header-level
        # or inline-method-level vars with RELOCATION_ID(n) or REL::ID(n)).
        ids = _collect_int_literals(node)
        se_id = ae_id = None
        if ids:
            if self.is_ae:
                ae_id = ids[0]
            else:
                se_id = ids[0]
        else:
            # Fall back to DeclRefExpr resolution (Offset:: reference).
            ref_id = _first_declref_id(node)
            the_id: Optional[int] = None
            if ref_id and ref_id in self.id_to_int:
                the_id = self.id_to_int[ref_id]
            if the_id is None:
                # Name-based fallback for cross-TU src/ parsing where the
                # id map lacks an entry (use the first qualified target).
                ref_name = _first_declref_name(node)
                if ref_name and ref_name in self.offset_id_map:
                    the_id = self.offset_id_map[ref_name]
            if the_id is not None:
                if self.is_ae:
                    ae_id = the_id
                else:
                    se_id = the_id

        se_off = self.addr_lib.se_db.get(se_id) if se_id else None
        ae_off = self.addr_lib.ae_db.get(ae_id) if ae_id else None

        if not se_off and not ae_off:
            if not self.is_ae:
                self.missed.append((method and method.get('name'),
                                    method and method.get('class'),
                                    var_name, se_id, ae_id))
            return

        # Choose symbol name/class/signature
        enc_name = method and method.get('name')
        if enc_name and enc_name.lower() not in _GENERIC_VAR_NAMES:
            sym_name = enc_name
            sym_class = method.get('class') if method else None
            sym_ret = method.get('ret') if method else ''
            sym_params = method.get('params') if method else ''
            sym_static = method.get('static') if method else False
        else:
            sym_name = var_name
            sym_class = None
            sig = _parse_reloc_spelling(type_sp)
            sym_ret = sig[0] if sig else ''
            sym_params = sig[2] if sig else ''
            sym_static = False

        # Dedup by SE, then AE
        if se_off and se_off not in self._seen_se:
            self._seen_se.add(se_off)
            if ae_off:
                self._seen_ae.add(ae_off)
            self.func_syms.append({
                'name': sym_name, 'class_': sym_class,
                'ret': sym_ret, 'params': sym_params,
                'is_static': sym_static,
                'se_off': se_off, 'ae_off': ae_off,
            })
        elif ae_off and ae_off not in self._seen_ae:
            self._seen_ae.add(ae_off)
            self.func_syms.append({
                'name': sym_name, 'class_': sym_class,
                'ret': sym_ret, 'params': sym_params,
                'is_static': sym_static,
                'se_off': None, 'ae_off': ae_off,
            })

    # ------------------------------------------------------------------
    # Qualified name formatting (strip RE:: prefix for libclang compat)
    # ------------------------------------------------------------------
    def _format_qual(self, parts: List[str]) -> str:
        if not parts:
            return ''
        s = '::'.join(p for p in parts if p)
        return self._strip_re(s)

    def _strip_re(self, s: str) -> str:
        if not s:
            return s
        if self.strip_re and s.startswith('RE::'):
            return s[4:]
        if self.strip_re and s == 'RE':
            return ''
        return s


# ---------------------------------------------------------------------------
# Top-level-scope derivation
# ---------------------------------------------------------------------------

_MANGLE_RE = re.compile(
    r'^\?(\?[_0-9A-Z])?([A-Za-z_][A-Za-z0-9_]*)?((?:@[^@]+)+)@@'
)

def _scope_from_mangled(mangled):
    """Given a method's mangledName, return its containing class qualified name."""
    m = _MANGLE_RE.match(mangled)
    if not m:
        return None
    special = m.group(1)
    name = m.group(2) or ''
    scope_chain = m.group(3)
    parts = [p for p in scope_chain.split('@') if p]
    parts = [p for p in parts if not p.startswith('?$')]
    if not parts and not name:
        return None
    if special and name:
        return '::'.join(list(reversed(parts)) + [name])
    return '::'.join(reversed(parts))


def _derive_toplevel_scope(node: dict, root_ns: str) -> List[str]:
    """Derive the ns/class stack for a filter-emitted top-level decl.

    Returns the stack, ENDING with the decl's own simple name if it's a
    NamespaceDecl / CXXRecordDecl (so that inner decls see the right scope).
    """
    k = node.get('kind')
    nm = node.get('name') or ''

    if k == 'NamespaceDecl':
        # Top-level NamespaceDecl under `-ast-dump-filter=RE::` — nm is the
        # inner namespace.  Assume it's rooted at root_ns unless nm == root_ns.
        if nm == root_ns:
            return [root_ns]
        if nm:
            return [root_ns, nm]
        return [root_ns]

    if k in ('CXXRecordDecl', 'ClassTemplateDecl'):
        # Walk method children to find one with a mangledName and derive scope.
        for c in node.get('inner', []) or []:
            if c.get('kind') not in (
                'CXXMethodDecl', 'FunctionDecl',
                'CXXConstructorDecl', 'CXXDestructorDecl',
            ):
                continue
            mng = c.get('mangledName')
            if not mng:
                continue
            full = _scope_from_mangled(mng)
            if not full:
                continue
            parts = full.split('::')
            if parts and parts[0] != root_ns:
                parts = [root_ns] + parts
            # parts ends with the class name; pop it so caller prepends cls=[]
            # and _walk re-pushes during CXXRecordDecl entry.
            return parts[:-1] if parts else [root_ns]
        # No derivable scope — fall back to root_ns
        return [root_ns]

    # FunctionDecl / VarDecl at top level — just root
    return [root_ns]


# ---------------------------------------------------------------------------
# Clang invocation + orchestration
# ---------------------------------------------------------------------------

def _json_cmd(clang_binary: str, driver: List[str], input_path: str, ns: str) -> List[str]:
    """Build the clang command line for a single-namespace JSON AST dump.

    Keeps function bodies (omits `-skip-function-bodies`) so that VarDecls
    inside method / function bodies are visible.
    """
    return [clang_binary, '-x', 'c++'] + driver + [
        '-fsyntax-only',
        '-Xclang', '-ast-dump=json',
        '-Xclang', f'-ast-dump-filter={ns}::',
        input_path,
    ]


def _run_to_tempfile(cmd: List[str], verbose: bool = False) -> str:
    """Run `cmd` and spool stdout to a tempfile; return its path."""
    fd, path = tempfile.mkstemp(suffix='.json', prefix='clang_reloc_')
    os.close(fd)
    if verbose:
        print(f'    spool: {os.path.basename(path)}')
    with open(path, 'w', encoding='utf-8') as f:
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL, text=True)
        p.wait()
    if verbose:
        sz = os.path.getsize(path) / 1024 / 1024
        print(f'    {os.path.basename(path)}: {sz:.1f} MB')
    return path


def _walk_spool(walker: _Walker, spool_path: str, root_ns: str):
    """Stream-parse the spool and drive the walker."""
    with open(spool_path, 'r', encoding='utf-8') as f:
        for obj in _iter_toplevel_objects(f):
            scope = _derive_toplevel_scope(obj, root_ns)
            # If the top-level is a NamespaceDecl/CXXRecordDecl, we want the
            # walker's own scope-tracking (in _walk) to manage the push.  But
            # _derive_toplevel_scope has already included the decl's own name
            # for namespaces (we strip that back off here by one level).
            k = obj.get('kind')
            if k == 'NamespaceDecl':
                # The derived scope ends with this namespace's name; pop it so
                # walker's NamespaceDecl handler re-pushes.
                scope_for_walk = scope[:-1] if scope else []
            else:
                scope_for_walk = scope
            walker.walk_toplevel(obj, scope_for_walk)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_relocations(
    skyrim_h: str,
    parse_args: List[str],
    addr_lib,
    is_ae: bool,
    extra_offset_map: Optional[Dict[str, int]] = None,
    clang_binary: Optional[str] = None,
    verbose: bool = False,
    root_namespaces: Tuple[str, ...] = ('RE',),
) -> Tuple[List[dict], List[dict], Dict[str, int], set]:
    """Main entry: replaces `_collect_relocations_from_tu(tu, addr_lib, is_ae)`.

    Returns (func_syms, label_syms, offset_id_map, static_methods).
    """
    if clang_binary is None:
        clang_binary = find_clang_binary()
    if not clang_binary:
        raise RuntimeError('clang.exe not found')

    driver = _build_driver_args(parse_args)
    if verbose:
        print(f'  [clang-ast-reloc] spooling JSON AST '
              f'({"AE" if is_ae else "SE"}) for {root_namespaces}...')

    # Spool each namespace's JSON AST in parallel
    with ThreadPoolExecutor(max_workers=len(root_namespaces)) as ex:
        spool_futures = {
            ns: ex.submit(_run_to_tempfile,
                          _json_cmd(clang_binary, driver, skyrim_h, ns), verbose)
            for ns in root_namespaces
        }
        spool_paths = {ns: fut.result() for ns, fut in spool_futures.items()}

    # Run the walker once, sharing state across all namespace spools.
    walker = _Walker(addr_lib, is_ae)
    if extra_offset_map:
        walker.offset_id_map.update(extra_offset_map)

    try:
        for ns in root_namespaces:
            _walk_spool(walker, spool_paths[ns], ns)
    finally:
        for p in spool_paths.values():
            try:
                os.unlink(p)
            except OSError:
                pass

    mode = 'AE' if is_ae else 'SE'
    print('  {} relocation scan: {} func symbols, {} labels, {} static methods'.format(
        mode, len(walker.func_syms), len(walker.label_syms),
        len(walker.static_methods)))

    if not is_ae and walker.missed:
        print('  Missed REL::Relocation<> VAR_DECLs (no address resolved):')
        for enc_nm, enc_cls, var_nm, se_id, ae_id in sorted(
                walker.missed, key=lambda x: (x[1] or '', x[0] or '', x[2])):
            print('    {}::{} ({}) se_id={} ae_id={}'.format(
                enc_cls or '', enc_nm or var_nm, var_nm, se_id, ae_id))

    return walker.func_syms, walker.label_syms, walker.offset_id_map, walker.static_methods


# ---------------------------------------------------------------------------
# src/ unity parse
# ---------------------------------------------------------------------------

def collect_src_relocations(
    src_dir: str,
    parse_args_se: List[str],
    parse_args_ae: List[str],
    addr_lib,
    se_offset_map: Optional[Dict[str, int]] = None,
    ae_offset_map: Optional[Dict[str, int]] = None,
    clang_binary: Optional[str] = None,
    skyrim_h: Optional[str] = None,
    verbose: bool = False,
) -> List[dict]:
    """Parse CommonLibSSE src/*.cpp via clang.exe and collect function symbols.

    Builds a unity .cpp that #includes Skyrim.h and every src/**/*.cpp, writes
    it to a tempfile, and runs the same `collect_relocations` pipeline for
    both SE and AE.  Merges results (AE entries have both se_off + ae_off;
    SE-only entries are appended).
    """
    cpp_files = sorted(glob.glob(os.path.join(src_dir, '**', '*.cpp'), recursive=True))
    if not cpp_files:
        return []

    # Unity source content
    unity_lines = [
        '// clang-ast unity reloc parse — auto-generated\n',
        '#include "RE/Skyrim.h"\n',
    ]
    for p in cpp_files:
        unity_lines.append('#include "{}"\n'.format(p.replace('\\', '/')))
    unity_content = ''.join(unity_lines)

    # Must live in src_dir so relative includes inside .cpp resolve.
    unity_path = os.path.join(src_dir, '_unity_reloc_parse.cpp')
    with open(unity_path, 'w', encoding='utf-8') as f:
        f.write(unity_content)

    try:
        se_funcs, _, _, _ = collect_relocations(
            unity_path, parse_args_se, addr_lib, is_ae=False,
            extra_offset_map=se_offset_map, clang_binary=clang_binary,
            verbose=verbose,
        )
        ae_funcs, _, _, _ = collect_relocations(
            unity_path, parse_args_ae, addr_lib, is_ae=True,
            extra_offset_map=ae_offset_map, clang_binary=clang_binary,
            verbose=verbose,
        )
    finally:
        try:
            os.unlink(unity_path)
        except OSError:
            pass

    # Merge SE and AE func_syms.
    #
    # In clang-ast mode, `RELOCATION_ID(se, ae)` is preprocessor-stripped to a
    # single int per build mode, so SE funcs have only se_off and AE funcs
    # have only ae_off.  We need to re-pair them per symbol.
    #
    # Key: (class, name, params).  Params disambiguate overloads within the
    # same class.  Fall back to sequential match if the params keyed set has
    # unequal counts on each side (shouldn't happen in practice).
    from collections import defaultdict

    def key_of(f):
        return (f.get('class_') or '', f.get('name') or '', f.get('params') or '')

    ae_by_key = defaultdict(list)
    for f in ae_funcs:
        ae_by_key[key_of(f)].append(f)

    merged: List[dict] = []
    for f in se_funcs:
        k = key_of(f)
        ae_candidates = ae_by_key.get(k)
        if ae_candidates:
            af = ae_candidates.pop(0)
            merged.append({
                **f,
                'ae_off': af.get('ae_off'),
            })
        else:
            merged.append(dict(f))
    # Append any AE entries not paired to an SE entry
    for lst in ae_by_key.values():
        for af in lst:
            merged.append(dict(af))

    print('  src/ merged: {} func symbols from {} cpp files'.format(
        len(merged), len(cpp_files)))
    return merged
