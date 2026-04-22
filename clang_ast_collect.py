"""JSON AST-based type collection.

Drop-in replacement for `_collect_types(tu)` + `_map_type(type)` from
parse_commonlib_types.py.  Uses `clang.exe -Xclang -ast-dump=json` plus
`-Xclang -fdump-record-layouts` in a single subprocess and stream-parses
the combined output to produce the same (enums, structs) shape without
requiring the libclang Python bindings.

Rationale: libclang omits information the project needs (inherited template
fields, full record layouts).  The full clang driver emits everything we
want via these two flags.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from clangd_template_layouts import (
    _parse_record_layouts,
    _qualify_re,
    _record_type_to_pipeline,
    find_clang_binary,
)


# ---------------------------------------------------------------------------
# qualType string → pipeline type descriptor
# ---------------------------------------------------------------------------

# Enum type names are harvested during the walk; any field whose type matches
# a name in this set gets emitted as 'enum:<name>' rather than 'struct:<name>'.
_ENUM_NAMES: set = set()

# Simple names → set of source files where that name appears as a NESTED
# CXXRecordDecl (with completeDefinition).  Used in pass 2 to skip standalone
# dumps of those nested types — BUT only when the standalone dump's own file
# matches a known nested file, because some names appear both nested AND at
# namespace scope (e.g. RE::BoneData in TESObjectTREE.h vs
# RE::NiSkinData::BoneData in NiSkinData.h).
_NESTED_STRUCT_NAMES: Dict[str, set] = {}

# Primitive/stdint name → byte size.  Shared by enum and typedef sizing.
_PRIM_SIZES: Dict[str, int] = {
    'bool': 1, 'char': 1, 'signed char': 1, 'unsigned char': 1,
    'short': 2, 'unsigned short': 2, 'wchar_t': 2, 'char16_t': 2,
    'int': 4, 'unsigned int': 4, 'long': 4, 'unsigned long': 4,
    'char32_t': 4, 'float': 4,
    'std::uint8_t': 1, 'std::int8_t': 1, 'uint8_t': 1, 'int8_t': 1,
    'std::uint16_t': 2, 'std::int16_t': 2, 'uint16_t': 2, 'int16_t': 2,
    'std::uint32_t': 4, 'std::int32_t': 4, 'uint32_t': 4, 'int32_t': 4,
    'std::uint64_t': 8, 'std::int64_t': 8, 'uint64_t': 8, 'int64_t': 8,
    'long long': 8, 'unsigned long long': 8, 'double': 8,
    'size_t': 8, 'ptrdiff_t': 8, 'intptr_t': 8, 'uintptr_t': 8,
    'std::size_t': 8, 'std::ptrdiff_t': 8,
    'std::intptr_t': 8, 'std::uintptr_t': 8,
}


def _qualtype_to_pipeline(qual: str, enum_names: set) -> str:
    """Map a JSON AST `type.qualType` string to our pipeline descriptor.

    Delegates to `_record_type_to_pipeline` which handles pointers, arrays,
    primitives, stdint typedefs, and struct name qualification.  After that,
    swaps struct: → enum: for names that are actually enums.
    """
    # Strip cv-qualifiers at the top level — the record-layout parser doesn't
    # handle them since record dumps omit cv-quals.
    stripped = re.sub(r'^(?:const|volatile)\s+', '', qual.strip())
    stripped = re.sub(r'\s+(?:const|volatile)$', '', stripped).strip()

    pipe = _record_type_to_pipeline(stripped)

    # Swap struct:RE::FooEnum → enum:RE::FooEnum when applicable.
    if pipe.startswith('struct:') and pipe[7:] in enum_names:
        return 'enum:' + pipe[7:]
    if pipe.startswith('ptr:struct:') and pipe[11:] in enum_names:
        return 'ptr:enum:' + pipe[11:]
    return pipe


# ---------------------------------------------------------------------------
# Qualified name extraction
# ---------------------------------------------------------------------------

# Mangled-name scope extractor.  MSVC mangling patterns we need to handle:
#   `?Name@Cls@NS@@...`      — regular method  (scope = [Cls, NS])
#   `??_DActor@RE@@...`      — deleting dtor   (special = ?_D, name = class)
#   `??1Actor@RE@@...`       — destructor      (special = ?1, name = class)
#   `??0Actor@RE@@...`       — constructor     (special = ?0, name = class)
#   `??4Base@RE@@...`        — operator=       (special = ?4, name = class)
# For the special prefixes, the first identifier after them IS the class name
# rather than a method name; scope chain to its right is namespace-only.
_MANGLE_RE = re.compile(
    r'^\?(\?[_0-9A-Z])?([A-Za-z_][A-Za-z0-9_]*)?((?:@[^@]+)+)@@'
)


def _class_scope_from_mangled(mangled: str) -> Optional[str]:
    """Given a method's mangledName, return its containing class qualified name."""
    m = _MANGLE_RE.match(mangled)
    if not m:
        return None
    special = m.group(1)   # like '?_D', '?1', '?0'; None for regular methods
    name = m.group(2) or ''
    scope_chain = m.group(3)
    parts = [p for p in scope_chain.split('@') if p]
    # Skip MSVC template-arg scopes (prefixed with '?$')
    parts = [p for p in parts if not p.startswith('?$')]
    if not parts and not name:
        return None
    if special and name:
        # Destructor / constructor / operator: `name` is the class itself;
        # the scope chain is namespace-only.
        return '::'.join(list(reversed(parts)) + [name])
    # Regular method: scope chain is [class, ns1, ns2, ...]
    return '::'.join(reversed(parts))


# ---------------------------------------------------------------------------
# JSON streaming (concatenated top-level objects)
# ---------------------------------------------------------------------------

def _iter_toplevel_objects(stream):
    """Yield each top-level JSON object from a concatenated-JSON stream.

    clang's `-ast-dump=json -ast-dump-filter=X` output is a sequence of
    independent top-level objects (not an array).  We read in chunks and feed
    a `JSONDecoder.raw_decode` to peel them off one at a time.
    """
    decoder = json.JSONDecoder()
    buf = ''
    CHUNK = 1 << 20  # 1 MiB read chunks
    while True:
        data = stream.read(CHUNK)
        if not data:
            break
        buf += data
        i = 0
        n = len(buf)
        while i < n:
            # Skip leading whitespace
            while i < n and buf[i].isspace():
                i += 1
            if i >= n:
                break
            try:
                obj, j = decoder.raw_decode(buf, i)
            except json.JSONDecodeError:
                # Incomplete object — wait for more bytes
                break
            yield obj
            i = j
        buf = buf[i:]
    # Final flush
    buf = buf.strip()
    if buf:
        obj = json.loads(buf)
        yield obj


# ---------------------------------------------------------------------------
# File-location filter: is the decl in the RE include directory?
# ---------------------------------------------------------------------------

def _loc_file(node) -> Optional[str]:
    """Return the decl's source file path (or None)."""
    loc = node.get('loc', {})
    f = loc.get('file')
    if f:
        return f
    # Fallback: look at range.begin.file (some nodes only have range info)
    rg = node.get('range', {})
    b = rg.get('begin', {})
    return b.get('file')


def _in_re_include(path: Optional[str], re_dir: str) -> bool:
    if not path:
        return False
    pp = path.replace('\\', '/').lower()
    rd = re_dir.replace('\\', '/').lower()
    return pp.startswith(rd)


# ---------------------------------------------------------------------------
# Enum + struct collection from a CXXRecordDecl / EnumDecl node
# ---------------------------------------------------------------------------

def _collect_enum(node, full_name: str, ns_path: List[str],
                  resolved_name: Optional[str] = None) -> Optional[dict]:
    """Convert an EnumDecl JSON node to our enum entry.

    `resolved_name` overrides node['name'] — callers pass it for anonymous
    enums where the name has been synthesized from the source location.
    """
    node_name = resolved_name if resolved_name is not None else node.get('name')
    if not node_name:
        return None
    # Size: prefer desugaredQualType (typedefs resolved) over qualType.
    # e.g. `enum : UPInt` — qualType='UPInt', desugaredQualType='unsigned long long'.
    fut = node.get('fixedUnderlyingType', {}) or {}
    under = fut.get('desugaredQualType') or fut.get('qualType', 'int')
    size = _PRIM_SIZES.get(under.strip(), 4)

    values: List[Tuple[str, int]] = []
    for child in node.get('inner', []) or []:
        if child.get('kind') != 'EnumConstantDecl':
            continue
        name = child.get('name')
        if not name:
            continue
        # Value is in inner[0] ConstantExpr's `value` field
        val = 0
        for sub in child.get('inner', []) or []:
            if sub.get('kind') == 'ConstantExpr' and 'value' in sub:
                try:
                    val = int(sub['value'])
                except (TypeError, ValueError):
                    val = 0
                break
        values.append((name, val))

    category = '/CommonLibSSE/' + '/'.join(ns_path) if ns_path else '/CommonLibSSE'
    return {
        'name': node_name,
        'full_name': full_name,
        'size': size,
        'category': category,
        'values': values,
    }


def _collect_struct(node, full_name: str, ns_path: List[str], enum_names: set) -> Optional[dict]:
    """Convert a CXXRecordDecl JSON node to our struct entry.

    Size and field offsets are left at zero; they must be merged in from the
    -fdump-record-layouts pass.  What we extract here: base list, field names
    + typed descriptors, virtual method signatures.
    """
    if not node.get('name'):
        return None
    if not node.get('completeDefinition'):
        return None

    tag = node.get('tagUsed', '')
    if tag == 'union':
        # Treat unions as opaque bytes for now — PDB usually gives us sizes.
        pass

    bases: List[str] = []
    for b in node.get('bases', []) or []:
        ty = b.get('type', {})
        # Prefer desugaredQualType (fully-qualified when present); otherwise
        # store raw qualType and let _resolve_bases() patch it up once all
        # structs are known.  _qualify_re() isn't used here because it
        # unconditionally prefixes 'RE::' which is wrong for bases that live
        # in nested (RE::BSResource::StreamBase) or sibling (REX::W32::IUnknown)
        # namespaces.
        qual = ty.get('desugaredQualType') or ty.get('qualType', '')
        qual = re.sub(r'\b(?:class|struct|union|enum)\s+', '', qual).strip()
        if qual:
            bases.append(qual)

    fields: List[dict] = []
    field_type_hints: Dict[str, str] = {}
    has_vtable = False
    vmethods: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {}

    for child in node.get('inner', []) or []:
        k = child.get('kind')
        if k == 'FieldDecl':
            fname = child.get('name')
            if not fname:
                continue
            ty = child.get('type', {}) or {}
            # Prefer desugaredQualType when present (it chases typedefs the way
            # libclang's canonical-type path does) so our descriptors match.
            ftype_raw = ty.get('desugaredQualType') or ty.get('qualType', '')
            ftype = _qualtype_to_pipeline(ftype_raw, enum_names)
            if ftype and ftype not in ('ptr', 'bytes:0'):
                field_type_hints[fname] = ftype
            # Offset/size come from record layouts later; placeholder 0/0 here.
            fields.append({
                'name': fname,
                'type': ftype,
                'offset': 0,
                'size': 0,
            })
        elif k == 'CXXMethodDecl':
            # Clang JSON only sets `virtual: true` when the keyword appears on
            # THIS declaration.  Overrides inherit virtualness but are emitted
            # with `virtual=null` + an OverrideAttr inner node, so we check both.
            # (Destructors are CXXDestructorDecl and get handled by the
            # -fdump-vtable-layouts path, matching libclang's exclusion here.)
            inners = child.get('inner', []) or []
            is_override = any(ic.get('kind') == 'OverrideAttr' for ic in inners)
            if child.get('virtual') or is_override:
                has_vtable = True
                mname = child.get('name')
                if mname and '<' not in mname and mname not in vmethods:
                    qt = child.get('type', {}).get('qualType', '')
                    # qualType: 'ret (params)' or 'ret (params) const' etc.
                    m = re.match(r'^(.+?)\s*\(([^)]*)\)', qt)
                    if m:
                        ret_raw = m.group(1).strip()
                        ret = _qualtype_to_pipeline(ret_raw, enum_names)
                        params: List[Tuple[str, str]] = []
                        for i, p in enumerate(inners):
                            if p.get('kind') != 'ParmVarDecl':
                                continue
                            pname = p.get('name') or f'p{i}'
                            ptype_raw = p.get('type', {}).get('qualType', '')
                            ptype = _qualtype_to_pipeline(ptype_raw, enum_names)
                            params.append((pname, ptype))
                        vmethods[mname] = (ret, params)

    category = '/CommonLibSSE/' + '/'.join(ns_path) if ns_path else '/CommonLibSSE'
    return {
        'name': node['name'],
        'full_name': full_name,
        'size': 0,           # filled in from record layouts
        'category': category,
        'fields': fields,
        'field_type_hints': field_type_hints,
        'bases': bases,
        'has_vtable': has_vtable,
        'vmethods': vmethods,
    }


# ---------------------------------------------------------------------------
# Walk a single top-level decl (may contain nested namespaces / classes)
# ---------------------------------------------------------------------------

def _walk(node, ns_stack: List[str], re_dir: str,
          enums: dict, structs: dict, pass_num: int,
          inherited_file: Optional[str] = None) -> None:
    """Recursively walk a top-level decl.

    pass_num == 1: collect enum names only.
    pass_num == 2: collect full enum/struct definitions (needs enum_names from pass 1).

    Clang JSON AST omits `loc.file` on children when it matches the parent's
    file — so we thread `inherited_file` down so nested decls can still be
    filtered by path.
    """
    kind = node.get('kind')
    node_file = _loc_file(node) or inherited_file

    if kind == 'NamespaceDecl':
        name = node.get('name') or ''
        new_stack = ns_stack + [name] if name else list(ns_stack)
        for c in node.get('inner', []) or []:
            _walk(c, new_stack, re_dir, enums, structs, pass_num, node_file)
        return

    if kind == 'EnumDecl':
        if not _in_re_include(node_file, re_dir):
            return
        name = node.get('name')
        if not name:
            # Anonymous enum — synthesize the name libclang would use
            # ('(unnamed enum at <file>:<line>:<col>)') so our keys match.
            # libclang emits all-backslash paths on Windows; clang's JSON AST
            # uses mixed separators (backslashes for the install prefix,
            # forward slashes for user paths) so normalize here.
            loc = node.get('loc', {}) or {}
            line = loc.get('line')
            col = loc.get('col')
            if node_file and line and col:
                norm = node_file.replace('/', '\\') if os.sep == '\\' else node_file
                name = f'(unnamed enum at {norm}:{line}:{col})'
            else:
                return
        full_name = '::'.join(ns_stack + [name]) if ns_stack else name
        if pass_num == 1:
            _ENUM_NAMES.add(full_name)
            return
        if full_name in enums:
            return
        entry = _collect_enum(node, full_name, ns_stack, name)
        if entry:
            enums[full_name] = entry
        return

    if kind in ('CXXRecordDecl', 'ClassTemplateSpecializationDecl'):
        if not _in_re_include(node_file, re_dir):
            return
        name = node.get('name')
        if not name:
            return
        # Recurse into nested types FIRST so inner enum names are collected.
        for c in node.get('inner', []) or []:
            ck = c.get('kind')
            if ck in ('EnumDecl', 'CXXRecordDecl', 'ClassTemplateSpecializationDecl'):
                # Pass 1 also records simple names seen nested (with a complete
                # definition — not implicit forward decls) so pass 2 can skip
                # standalone dumps of those types.
                if (pass_num == 1
                        and ck in ('CXXRecordDecl', 'ClassTemplateSpecializationDecl')
                        and c.get('completeDefinition')
                        and not c.get('isImplicit')):
                    cn = c.get('name')
                    if cn:
                        cf = _loc_file(c) or node_file
                        _NESTED_STRUCT_NAMES.setdefault(cn, set()).add(cf)
                _walk(c, ns_stack + [name], re_dir, enums, structs, pass_num, node_file)
        if pass_num == 1:
            return
        full_name = '::'.join(ns_stack + [name]) if ns_stack else name
        if not node.get('completeDefinition'):
            # Forward decls are not tracked here.  Most RE-include forward decls
            # are `friend class X;` / `friend struct X;` inside class bodies,
            # where X refers to a type in the enclosing namespace — not a nested
            # type of the current class.  Recording them at nested scope
            # produces misleading qualified names (e.g. RE::Actor::BSLight vs
            # the real RE::BSLight).
            return
        if full_name in structs:
            return
        entry = _collect_struct(node, full_name, ns_stack, _ENUM_NAMES)
        if entry:
            structs[full_name] = entry
        return

    if kind in ('TypedefDecl', 'TypeAliasDecl'):
        if not _in_re_include(node_file, re_dir):
            return
        name = node.get('name')
        if not name:
            return
        if pass_num == 1:
            return
        full_name = '::'.join(ns_stack + [name]) if ns_stack else name
        if full_name in structs or full_name in enums:
            return
        ty = node.get('type', {}) or {}
        desugared = (ty.get('desugaredQualType') or ty.get('qualType') or '').strip()
        if not desugared:
            return
        # Pointer types → 8 bytes.  Primitive/stdint → _PRIM_SIZES lookup.
        # Anything else (struct/template instantiation) → skip; it'll come in
        # via the record-layouts pass or template_types.
        if desugared.endswith('*'):
            size = 8
        else:
            stripped = re.sub(r'^(?:const|volatile)\s+', '', desugared)
            stripped = re.sub(r'\s+(?:const|volatile)$', '', stripped).strip()
            size = _PRIM_SIZES.get(stripped, 0)
        if size <= 0:
            return
        category = '/CommonLibSSE/' + '/'.join(ns_stack) if ns_stack else '/CommonLibSSE'
        structs[full_name] = {
            'name': name, 'full_name': full_name, 'size': size,
            'category': category, 'fields': [], 'bases': [],
            'has_vtable': False,
        }
        return


# ---------------------------------------------------------------------------
# Top-level qualified-name recovery for unfiltered dumps
# ---------------------------------------------------------------------------

def _derive_scope_for_toplevel(node) -> List[str]:
    """Derive the namespace path for a top-level CXXRecordDecl / EnumDecl.

    When we're processing `-ast-dump-filter=RE::` output, each matched decl is
    emitted as a top-level JSON object without its enclosing namespace decls.
    We recover the scope by decoding the mangledName of any method child.
    """
    for c in node.get('inner', []) or []:
        if c.get('kind') in ('CXXMethodDecl', 'CXXDestructorDecl', 'CXXConstructorDecl'):
            mn = c.get('mangledName')
            if mn:
                scope = _class_scope_from_mangled(mn)
                if scope:
                    # Drop the final component (class name itself); keep namespace parts.
                    parts = scope.split('::')
                    if len(parts) > 1:
                        return parts[:-1]
                    return parts
    return []


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _build_driver_args(parse_args: List[str]) -> List[str]:
    """Convert libclang-style parse_args to clang driver args."""
    out: List[str] = []
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


def collect_types(skyrim_h: str, parse_args: List[str], re_dir: str,
                  clang_binary: Optional[str] = None,
                  verbose: bool = False,
                  root_namespaces: Tuple[str, ...] = ('RE', 'REX', 'REL')) -> Tuple[dict, dict]:
    """Drop-in replacement for libclang _collect_types(tu).

    Runs clang in parallel: one JSON AST pass per root namespace (with
    -ast-dump-filter=<ns>::) + one record-layouts pass.  Multiple filters are
    required because `-ast-dump-filter` uses substring matching — 'RE::' won't
    match 'REX::' or 'REL::'.
    """
    if clang_binary is None:
        clang_binary = find_clang_binary()
    if not clang_binary:
        raise RuntimeError('clang.exe not found')

    driver = _build_driver_args(parse_args)

    def _json_cmd(ns: str) -> List[str]:
        return [clang_binary, '-x', 'c++'] + driver + [
            '-fsyntax-only',
            '-Xclang', '-skip-function-bodies',
            '-Xclang', '-ast-dump=json',
            '-Xclang', f'-ast-dump-filter={ns}::',
            skyrim_h,
        ]

    layouts_cmd = [clang_binary, '-x', 'c++'] + driver + [
        '-fsyntax-only',
        '-Xclang', '-fdump-record-layouts-complete',
        skyrim_h,
    ]
    if verbose:
        print(f'  [clang-ast] launching {len(root_namespaces)} JSON passes + 1 layouts pass in parallel...')

    layouts_proc = subprocess.Popen(
        layouts_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1 << 16)
    json_procs = [
        (ns, subprocess.Popen(_json_cmd(ns), stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True,
                              bufsize=1 << 16))
        for ns in root_namespaces
    ]

    enums: Dict[str, dict] = {}
    structs: Dict[str, dict] = {}

    import tempfile
    # Drain each JSON pass into its own spool, then two-pass-walk it.
    for ns, proc in json_procs:
        assert proc.stdout is not None
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as spool:
            for chunk in iter(lambda: proc.stdout.read(1 << 16), ''):
                spool.write(chunk)
            proc.wait()

            # Pass 1: harvest enum full names + nested struct names.
            spool.seek(0)
            _ENUM_NAMES.clear()
            _NESTED_STRUCT_NAMES.clear()
            tmp_e: Dict[str, dict] = {}
            tmp_s: Dict[str, dict] = {}
            _stream_json(spool, re_dir, tmp_e, tmp_s, pass_num=1, root_ns=ns)

            # Pass 2: collect definitions.
            spool.seek(0)
            _stream_json(spool, re_dir, enums, structs, pass_num=2, root_ns=ns)
        if verbose:
            print(f'  [clang-ast] {ns}:: pass done (running totals: {len(enums)}e, {len(structs)}s)')

    # Collect record layouts output (may still be running).
    assert layouts_proc.stdout is not None
    layouts_text = layouts_proc.stdout.read()
    layouts_proc.wait()
    if layouts_text:
        _apply_record_layouts(layouts_text, structs, verbose=verbose)

    # Resolve bare-name bases (e.g. 'StreamBase' -> 'RE::BSResource::StreamBase')
    # using the enclosing struct's namespace scope.
    _resolve_bases(structs, verbose=verbose)

    return enums, structs


_TEMPLATE_RE = re.compile(r'^([^<]+)(<.*>)?$')


def _resolve_bases(structs: Dict[str, dict], verbose: bool = False) -> None:
    """Qualify bare/partial base names against the collected struct index.

    Clang's JSON AST emits base-class types in their source-level spelling —
    e.g. `StreamBase` for a base that's actually `RE::BSResource::StreamBase`.
    To match what libclang gives us (canonical fully-qualified names), we walk
    up each struct's enclosing namespace chain looking for a match.
    """
    # Index: simple (last-component) name -> list of full names.
    short_index: Dict[str, List[str]] = {}
    for full in structs:
        short = full.split('::')[-1]
        short_index.setdefault(short, []).append(full)

    patched = 0
    for full, st in structs.items():
        ns_stack = full.split('::')[:-1]
        new_bases: List[str] = []
        for base in st.get('bases', []):
            m = _TEMPLATE_RE.match(base)
            core = m.group(1).strip() if m else base
            targs = m.group(2) or ''

            resolved: Optional[str] = None
            # 1. Exact hit (already fully-qualified).
            if core in structs:
                resolved = core
            else:
                # 2. Walk enclosing namespace chain inside -> outside.
                for i in range(len(ns_stack), -1, -1):
                    cand = '::'.join(ns_stack[:i] + [core]) if ns_stack[:i] else core
                    if cand in structs:
                        resolved = cand
                        break
                # 3. Last-component unique-short-name fallback.
                if not resolved:
                    short = core.split('::')[-1]
                    hits = short_index.get(short, [])
                    if len(hits) == 1:
                        resolved = hits[0]

            final = (resolved + targs) if resolved else base
            if final != base:
                patched += 1
            new_bases.append(final)
        st['bases'] = new_bases

    if verbose and patched:
        print(f'  [clang-ast] _resolve_bases: patched {patched} base names')


_TOPLEVEL_SCOPED_KINDS = (
    'CXXRecordDecl', 'ClassTemplateSpecializationDecl', 'EnumDecl',
)


def _toplevel_scope(obj, pass_num: int, root_ns: str) -> Optional[List[str]]:
    """Decide scope for a filter-emitted top-level decl.

    `root_ns` is the namespace the clang filter is pinned to (e.g. 'RE').
    Returns None to indicate "skip this node entirely" (nested type already
    processed via parent recursion).  Otherwise returns the namespace stack to
    use, falling back to [root_ns] since `-ast-dump-filter=<root_ns>::`
    guarantees every emitted decl lives inside that namespace.
    """
    kind = obj.get('kind')
    # NamespaceDecls nested inside root_ns (e.g. RE::ActiveEffectFactory) get
    # dumped at top level with their short name and no outer scope info.
    # Treat them as rooted at [root_ns] — except the root namespace itself.
    if kind == 'NamespaceDecl':
        name = obj.get('name') or ''
        if name == root_ns or not name:
            return []
        return [root_ns]
    if kind not in _TOPLEVEL_SCOPED_KINDS:
        return []
    scope = _derive_scope_for_toplevel(obj)
    if scope:
        return scope
    # Scope couldn't be derived (no methods to mangle-parse).  If this simple
    # name was already seen as a nested type in pass 1, its parent handles it.
    if pass_num == 2 and kind in ('CXXRecordDecl', 'ClassTemplateSpecializationDecl'):
        name = obj.get('name')
        if name:
            nested_files = _NESTED_STRUCT_NAMES.get(name)
            if nested_files and _loc_file(obj) in nested_files:
                return None
    return [root_ns]


def _stream_json(spool, re_dir: str,
                 enums: dict, structs: dict,
                 pass_num: int, root_ns: str = 'RE') -> None:
    """Stream-parse concatenated top-level JSON objects from spool and walk them."""
    decoder = json.JSONDecoder()
    buf = ''
    CHUNK = 1 << 20
    while True:
        data = spool.read(CHUNK)
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
                obj, j2 = decoder.raw_decode(buf, i)
            except json.JSONDecodeError:
                # Incomplete trailing object; wait for more bytes
                break
            ns_stack = _toplevel_scope(obj, pass_num, root_ns)
            if ns_stack is not None:
                _walk(obj, ns_stack, re_dir, enums, structs, pass_num)
            i = j2
        buf = buf[i:]
    # Drain any trailing JSON
    if buf.strip():
        j = 0
        m = len(buf)
        while j < m:
            while j < m and buf[j].isspace():
                j += 1
            if j >= m:
                break
            try:
                obj, j2 = decoder.raw_decode(buf, j)
            except json.JSONDecodeError:
                break
            ns_stack = _toplevel_scope(obj, pass_num, root_ns)
            if ns_stack is not None:
                _walk(obj, ns_stack, re_dir, enums, structs, pass_num)
            j = j2


def _apply_record_layouts(layouts_text: str, structs: dict, verbose: bool = False) -> None:
    """Merge sizes + field offsets from `-fdump-record-layouts` into structs."""
    raw = _parse_record_layouts(layouts_text)
    applied = 0
    for clang_name, (size, fields) in raw.items():
        # Normalize: strip class/struct/union/enum keywords
        qname = re.sub(r'\b(?:class|struct|union|enum)\s+', '', clang_name).strip()
        st = structs.get(qname)
        if st is None:
            # Try stripping RE:: prefix
            if qname.startswith('RE::'):
                st = structs.get(qname[4:])
        if st is None:
            continue
        st['size'] = size
        # Merge field offsets into existing fields (match by name).
        by_name = {f['name']: f for f in fields}
        for f in st.get('fields', []):
            match = by_name.get(f['name'])
            if match:
                f['offset'] = match['offset']
                f['size'] = match['size']
                if not f.get('type') or f['type'] in ('ptr', 'bytes:0'):
                    f['type'] = match['type']
        applied += 1
    if verbose:
        print(f'  [clang-ast] Record layouts applied to {applied} structs')
