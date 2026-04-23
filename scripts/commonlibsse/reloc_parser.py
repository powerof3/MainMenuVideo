"""Regex-based relocation/symbol scanner for CommonLibSSE.

Parses raw source files with regex to extract:
  - REL::Relocation<T> VarDecls with RELOCATION_ID(SE, AE) → function symbols
  - RTTI_* / VTABLE_* labels
  - Offset:: namespace IDs
  - Static method detection

Key advantage: RELOCATION_ID(SE, AE) is parsed before preprocessor expansion,
giving both SE and AE IDs in a single pass (no two-pass build + merge needed).

Root namespace is configurable (default 'RE') for project-agnostic use.
"""
from __future__ import annotations

import glob
import os
import re
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# RELOCATION_ID(se_id, ae_id) — captures both IDs before macro expansion
_RELOC_ID_RE = re.compile(r'RELOCATION_ID\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)')

# REL::ID(integer) — single ID (used in RTTI/VTABLE/Offset headers)
_REL_ID_RE = re.compile(r'REL::ID\s*\(\s*(?:static_cast<std::uint64_t>\(\s*)?(\d+)\s*\)?\s*\)')

# REL::Relocation<T> variable declaration
# Matches: [static] [const] REL::Relocation<...> varname { init } or ( init )
_RELOC_VAR_RE = re.compile(
    r'(?:static\s+)?(?:const\s+)?REL::Relocation<[^>]+>\s+(\w+)\s*[\{(]'
)

# RTTI label: inline constexpr REL::ID RTTI_Name{ id };
_RTTI_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+(RTTI_\w+)\s*\{\s*(\d+)\s*\}'
)

# VTABLE label: inline constexpr std::array<REL::ID, N> VTABLE_Name{ REL::ID(x), ... };
_VTABLE_RE = re.compile(
    r'inline\s+constexpr\s+std::array<REL::ID,\s*(\d+)>\s+(VTABLE_\w+)\s*\{([^}]+)\}'
)

# Offset namespace: inline constexpr REL::ID Name(static_cast<...>(id));
_OFFSET_ID_RE = re.compile(
    r'inline\s+constexpr\s+REL::ID\s+(\w+)\s*\(\s*static_cast<std::uint64_t>\s*\(\s*(\d+)\s*\)\s*\)'
)

# Namespace opening
_NS_OPEN_RE = re.compile(r'\bnamespace\s+(\w+)\s*\{')

# Class/struct opening (captures name)
_CLASS_RE = re.compile(r'\b(?:class|struct)\s+(\w+)\s*(?:final\s*)?(?::\s*[^{]*?)?\{')

# Static method in class
_STATIC_METHOD_RE = re.compile(
    r'static\s+(?!constexpr\s+auto\s+RTTI|constexpr\s+auto\s+VTABLE).*?\b(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?;'
)

# Function/method definition (for enclosing context of REL::Relocation vars)
# Matches: ReturnType ClassName::MethodName(params) { or ReturnType FuncName(params) {
_FUNC_DEF_RE = re.compile(
    r'(?:[\w:*&<>,\s]+?)\s+((?:\w+::)*\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{'
)

# ifdef SKYRIM_SUPPORT_AE tracking
_IFDEF_AE_RE = re.compile(r'#\s*ifn?def\s+SKYRIM_SUPPORT_AE')
_ELSE_RE = re.compile(r'#\s*else\b')
_ENDIF_RE = re.compile(r'#\s*endif\b')


# ---------------------------------------------------------------------------
# Brace-tracking context parser
# ---------------------------------------------------------------------------

class _ContextTracker:
    """Track namespace/class/method context via brace counting."""

    def __init__(self):
        self.scope_stack: List[Tuple[str, str, int]] = []  # (kind, name, brace_depth)
        self.brace_depth = 0

    def feed_line(self, line: str):
        """Update brace depth and scope from a line of code."""
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('#'):
            return

        opens = line.count('{')
        closes = line.count('}')

        # Check for namespace/class openings before counting braces
        for m in _NS_OPEN_RE.finditer(line):
            self.scope_stack.append(('ns', m.group(1), self.brace_depth))
        for m in _CLASS_RE.finditer(line):
            self.scope_stack.append(('class', m.group(1), self.brace_depth))

        self.brace_depth += opens - closes

        # Pop scopes that have been closed
        while self.scope_stack and self.scope_stack[-1][2] >= self.brace_depth:
            self.scope_stack.pop()

    @property
    def namespace_path(self) -> List[str]:
        return [name for kind, name, _ in self.scope_stack if kind == 'ns']

    @property
    def class_name(self) -> Optional[str]:
        for kind, name, _ in reversed(self.scope_stack):
            if kind == 'class':
                return name
        return None

    @property
    def full_class(self) -> Optional[str]:
        """Full qualified class name (ns1::ns2::Class)."""
        parts = []
        for kind, name, _ in self.scope_stack:
            if kind in ('ns', 'class'):
                parts.append(name)
        classes = [name for kind, name, _ in self.scope_stack if kind == 'class']
        if not classes:
            return None
        ns = [name for kind, name, _ in self.scope_stack if kind == 'ns']
        return '::'.join(ns + classes)


# ---------------------------------------------------------------------------
# Header file scanner
# ---------------------------------------------------------------------------

def _scan_header_relocations(
    file_path: str,
    addr_lib,
    offset_id_map: Dict[str, int],
    se_offset_map: Dict[str, int] = None,
    ae_offset_map: Dict[str, int] = None,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Set[Tuple[str, str]]]:
    """Scan a single header file for REL::Relocation, RTTI, VTABLE declarations.

    Returns (func_syms, label_syms, static_methods).
    """
    if se_offset_map is None:
        se_offset_map = offset_id_map
    if ae_offset_map is None:
        ae_offset_map = offset_id_map
    func_syms: List[dict] = []
    label_syms: List[dict] = []
    static_methods: Set[Tuple[str, str]] = set()

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return func_syms, label_syms, static_methods

    lines = content.split('\n')
    ctx = _ContextTracker()

    for line in lines:
        ctx.feed_line(line)
        cls = ctx.class_name

        # Static methods
        if cls:
            for m in _STATIC_METHOD_RE.finditer(line):
                method_name = m.group(1)
                full_cls = ctx.full_class
                if full_cls:
                    bare = full_cls
                    _ns_pre = root_namespace + '::'
                    if bare.startswith(_ns_pre):
                        bare = bare[len(_ns_pre):]
                    static_methods.add((bare, method_name))

    # Now do content-level (multi-line-aware) regex scans

    # RELOCATION_ID with enclosing REL::Relocation context
    # We do a line-by-line scan for REL::Relocation vars containing RELOCATION_ID
    ctx2 = _ContextTracker()
    for line in lines:
        ctx2.feed_line(line)

        reloc_id_match = _RELOC_ID_RE.search(line)
        if reloc_id_match and 'REL::Relocation' in line:
            se_id = int(reloc_id_match.group(1))
            ae_id = int(reloc_id_match.group(2))

            se_off = addr_lib.se_db.get(se_id)
            ae_off = addr_lib.ae_db.get(ae_id)
            if not se_off and not ae_off:
                continue

            # Extract variable name
            var_match = _RELOC_VAR_RE.search(line)
            var_name = var_match.group(1) if var_match else 'func'

            # Symbol name = enclosing class method or var name
            sym_class = ctx2.full_class
            _ns_pre2 = root_namespace + '::'
            if sym_class and sym_class.startswith(_ns_pre2):
                sym_class = sym_class[len(_ns_pre2):]

            func_syms.append({
                'name': var_name,
                'class_': sym_class,
                'ret': '', 'params': '',
                'is_static': False,
                'se_off': se_off, 'ae_off': ae_off,
            })

        # REL::Relocation using Offset:: reference (no RELOCATION_ID)
        elif 'REL::Relocation' in line and 'Offset::' in line and not _RELOC_ID_RE.search(line):
            var_match = _RELOC_VAR_RE.search(line)
            if not var_match:
                continue
            var_name = var_match.group(1)

            # Extract the Offset:: reference
            off_match = re.search(r'Offset::(\w+(?:::\w+)*)', line)
            if not off_match:
                continue
            offset_key = off_match.group(1)
            se_id = se_offset_map.get(offset_key)
            ae_id = ae_offset_map.get(offset_key)
            if se_id is None and ae_id is None:
                continue

            se_off = addr_lib.se_db.get(se_id) if se_id else None
            ae_off = addr_lib.ae_db.get(ae_id) if ae_id else None
            if not se_off and not ae_off:
                continue

            sym_class = ctx2.full_class
            if sym_class and sym_class.startswith(_ns_pre2):
                sym_class = sym_class[len(_ns_pre2):]

            func_syms.append({
                'name': var_name,
                'class_': sym_class,
                'ret': '', 'params': '',
                'is_static': False,
                'se_off': se_off, 'ae_off': ae_off,
            })

    return func_syms, label_syms, static_methods


def _scan_offsets_file(file_path: str) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Parse Offsets.h to build offset_id_maps: 'Class::Method' → integer ID.

    Handles #ifdef SKYRIM_SUPPORT_AE / #else / #endif sections.
    Returns (se_offset_map, ae_offset_map).
    """
    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return {}, {}

    has_ifdef = 'SKYRIM_SUPPORT_AE' in content

    if has_ifdef:
        lines = content.split('\n')
        section = None
        ae_lines = []
        se_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#ifdef') and 'SKYRIM_SUPPORT_AE' in stripped:
                section = 'ae'
                continue
            elif stripped.startswith('#else') and section == 'ae':
                section = 'se'
                continue
            elif stripped.startswith('#endif') and section == 'se':
                section = None
                continue
            if section == 'ae':
                ae_lines.append(line)
            elif section == 'se':
                se_lines.append(line)

        ae_map = _parse_offset_section('\n'.join(ae_lines))
        se_map = _parse_offset_section('\n'.join(se_lines))
        return se_map, ae_map
    else:
        m = _parse_offset_section(content)
        return m, {}


_NS_DECL_RE = re.compile(r'\bnamespace\s+(\w+)')


def _parse_offset_section(text: str) -> Dict[str, int]:
    """Parse a single section of Offsets.h for namespace::ID entries."""
    offset_map: Dict[str, int] = {}
    ns_stack: List[str] = []
    brace_depth = 0
    ns_at_depth: Dict[int, str] = {}
    pending_ns = None

    for line in text.split('\n'):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue

        ns_m = _NS_DECL_RE.search(line)
        if ns_m:
            ns_name = ns_m.group(1)
            if ns_name not in ('RE', 'Offset'):
                if '{' in line[ns_m.end():]:
                    ns_at_depth[brace_depth] = ns_name
                    ns_stack.append(ns_name)
                else:
                    pending_ns = ns_name

        opens = line.count('{')
        closes = line.count('}')

        if pending_ns and opens > 0:
            ns_at_depth[brace_depth] = pending_ns
            ns_stack.append(pending_ns)
            pending_ns = None

        off_m = _OFFSET_ID_RE.search(line)
        if off_m:
            name = off_m.group(1)
            the_id = int(off_m.group(2))
            key = '::'.join(ns_stack + [name])
            offset_map[key] = the_id

        brace_depth += opens - closes

        while ns_at_depth:
            max_depth = max(ns_at_depth.keys())
            if max_depth >= brace_depth:
                ns_at_depth.pop(max_depth)
                if ns_stack:
                    ns_stack.pop()
            else:
                break

    return offset_map


def _scan_rtti_vtable_file(
    file_path: str,
    addr_lib,
) -> List[dict]:
    """Parse Offsets_RTTI.h or Offsets_VTABLE.h for label symbols.

    These files have the structure:
        #ifdef SKYRIM_SUPPORT_AE   (AE IDs)
        #else                      (SE IDs)
        #endif
    We need to track which section each entry is in.
    """
    labels: Dict[str, dict] = {}

    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return list(labels.values())

    has_ifdef = 'SKYRIM_SUPPORT_AE' in content

    if has_ifdef:
        lines = content.split('\n')
        section = None  # None until we hit the ifdef
        ae_chunk = []
        se_chunk = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#ifdef') and 'SKYRIM_SUPPORT_AE' in stripped:
                section = 'ae'
                continue
            elif stripped.startswith('#else') and section == 'ae':
                section = 'se'
                continue
            elif stripped.startswith('#endif') and section == 'se':
                section = None
                continue

            if section == 'ae':
                ae_chunk.append(line)
            elif section == 'se':
                se_chunk.append(line)

        ae_text = '\n'.join(ae_chunk)
        se_text = '\n'.join(se_chunk)

        for m in _RTTI_RE.finditer(ae_text):
            name = m.group(1)
            off = addr_lib.ae_db.get(int(m.group(2)))
            if off:
                labels.setdefault(name, {'name': name, 'se_off': None, 'ae_off': None})
                labels[name]['ae_off'] = off

        for m in _RTTI_RE.finditer(se_text):
            name = m.group(1)
            off = addr_lib.se_db.get(int(m.group(2)))
            if off:
                labels.setdefault(name, {'name': name, 'se_off': None, 'ae_off': None})
                labels[name]['se_off'] = off

        for m in _VTABLE_RE.finditer(ae_text):
            name = m.group(2)
            ids = [int(x) for x in _REL_ID_RE.findall(m.group(3))]
            if ids:
                off = addr_lib.ae_db.get(ids[0])
                if off:
                    labels.setdefault(name, {'name': name, 'se_off': None, 'ae_off': None})
                    labels[name]['ae_off'] = off

        for m in _VTABLE_RE.finditer(se_text):
            name = m.group(2)
            ids = [int(x) for x in _REL_ID_RE.findall(m.group(3))]
            if ids:
                off = addr_lib.se_db.get(ids[0])
                if off:
                    labels.setdefault(name, {'name': name, 'se_off': None, 'ae_off': None})
                    labels[name]['se_off'] = off
    else:
        for m in _RTTI_RE.finditer(content):
            name = m.group(1)
            off = addr_lib.se_db.get(int(m.group(2)))
            if off:
                labels.setdefault(name, {'name': name, 'se_off': None, 'ae_off': None})
                labels[name]['se_off'] = off

        for m in _VTABLE_RE.finditer(content):
            name = m.group(2)
            ids = [int(x) for x in _REL_ID_RE.findall(m.group(3))]
            if ids:
                off = addr_lib.se_db.get(ids[0])
                if off:
                    labels.setdefault(name, {'name': name, 'se_off': None, 'ae_off': None})
                    labels[name]['se_off'] = off

    return list(labels.values())


# ---------------------------------------------------------------------------
# Source file scanner (.cpp)
# ---------------------------------------------------------------------------

def _scan_src_relocations(
    src_dir: str,
    addr_lib,
    offset_id_map: Dict[str, int],
    se_offset_map: Dict[str, int] = None,
    ae_offset_map: Dict[str, int] = None,
    root_namespace: str = 'RE',
) -> List[dict]:
    """Scan CommonLibSSE src/**/*.cpp for REL::Relocation + RELOCATION_ID."""
    if se_offset_map is None:
        se_offset_map = offset_id_map
    if ae_offset_map is None:
        ae_offset_map = offset_id_map
    func_syms: List[dict] = []

    cpp_files = sorted(glob.glob(os.path.join(src_dir, '**', '*.cpp'), recursive=True))
    for cpp_path in cpp_files:
        try:
            with open(cpp_path, encoding='utf-8', errors='replace') as f:
                content = f.read()
        except OSError:
            continue

        # Quick check — skip files without REL references
        if 'RELOCATION_ID' not in content and 'REL::Relocation' not in content:
            continue

        lines = content.split('\n')
        current_func_class = None
        current_func_name = None
        pending_func = None

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            # Track function definitions for context.
            # Handles both "RetType Class::Method(...) {" (same line)
            # and "RetType Class::Method(...)\n{" (brace on next line).
            func_m = re.match(r'.*?\b((?:\w+::)+)(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:->.*?)?\s*\{?', line)
            if func_m and '::' in func_m.group(1):
                qual = func_m.group(1).rstrip(':')
                fname = func_m.group(2)
                _ns_pre = root_namespace + '::'
                if qual.startswith(_ns_pre):
                    qual = qual[len(_ns_pre):]
                if '{' in line[func_m.end()-1:]:
                    current_func_class = qual
                    current_func_name = fname
                    pending_func = None
                else:
                    pending_func = (qual, fname)
            elif pending_func and stripped == '{':
                current_func_class, current_func_name = pending_func
                pending_func = None

            # RELOCATION_ID in this line
            reloc_m = _RELOC_ID_RE.search(line)
            if reloc_m:
                se_id = int(reloc_m.group(1))
                ae_id = int(reloc_m.group(2))
                se_off = addr_lib.se_db.get(se_id)
                ae_off = addr_lib.ae_db.get(ae_id)
                if not se_off and not ae_off:
                    continue

                var_match = _RELOC_VAR_RE.search(line)
                var_name = var_match.group(1) if var_match else 'func'

                sym_name = current_func_name or var_name
                sym_class = current_func_class

                func_syms.append({
                    'name': sym_name,
                    'class_': sym_class,
                    'ret': '', 'params': '',
                    'is_static': False,
                    'se_off': se_off, 'ae_off': ae_off,
                })

            # Offset:: reference
            elif 'REL::Relocation' in line and 'Offset::' in line:
                var_match = _RELOC_VAR_RE.search(line)
                if not var_match:
                    continue
                off_match = re.search(r'Offset::(\w+(?:::\w+)*)', line)
                if not off_match:
                    continue
                offset_key = off_match.group(1)
                se_id = se_offset_map.get(offset_key)
                ae_id = ae_offset_map.get(offset_key)
                if se_id is None and ae_id is None:
                    continue
                se_off = addr_lib.se_db.get(se_id) if se_id else None
                ae_off = addr_lib.ae_db.get(ae_id) if ae_id else None
                if not se_off and not ae_off:
                    continue

                sym_name = current_func_name or var_match.group(1)
                sym_class = current_func_class

                func_syms.append({
                    'name': sym_name,
                    'class_': sym_class,
                    'ret': '', 'params': '',
                    'is_static': False,
                    'se_off': se_off, 'ae_off': ae_off,
                })

    return func_syms


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_relocations(
    re_include: str,
    addr_lib,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Dict[str, int], Set[Tuple[str, str]]]:
    """Scan headers for relocation symbols.

    Returns (func_syms, label_syms, offset_id_map, static_methods).
    Each func_sym has both se_off and ae_off (from RELOCATION_ID).
    """
    all_func_syms: List[dict] = []
    all_label_syms: List[dict] = []
    all_static_methods: Set[Tuple[str, str]] = set()

    # 1. Parse Offsets.h for offset_id_map (SE and AE sections)
    commonlib_include = os.path.dirname(re_include)
    offsets_h = os.path.join(re_include, 'Offsets.h')
    se_offset_map, ae_offset_map = _scan_offsets_file(offsets_h)
    offset_id_map = dict(se_offset_map)
    for k, v in ae_offset_map.items():
        offset_id_map.setdefault(k, v)
    if verbose:
        print(f'  Parsed {len(se_offset_map)} SE + {len(ae_offset_map)} AE offset IDs from Offsets.h')

    # 2. Parse RTTI/VTABLE offset headers
    for fname in ('Offsets_RTTI.h', 'Offsets_VTABLE.h'):
        fpath = os.path.join(re_include, fname)
        if os.path.isfile(fpath):
            labels = _scan_rtti_vtable_file(fpath, addr_lib)
            all_label_syms.extend(labels)
            if verbose:
                print(f'  Parsed {len(labels)} labels from {fname}')

    # 3. Scan all RE/ header files for REL::Relocation + static methods
    h_files = sorted(glob.glob(os.path.join(re_include, '**', '*.h'), recursive=True))
    for h_path in h_files:
        basename = os.path.basename(h_path)
        if basename in ('Offsets.h', 'Offsets_RTTI.h', 'Offsets_VTABLE.h'):
            continue
        funcs, labels, statics = _scan_header_relocations(h_path, addr_lib, offset_id_map,
                                                            se_offset_map=se_offset_map,
                                                            ae_offset_map=ae_offset_map,
                                                            root_namespace=root_namespace)
        all_func_syms.extend(funcs)
        all_label_syms.extend(labels)
        all_static_methods |= statics

    if verbose:
        print(f'  Header scan: {len(all_func_syms)} func symbols, '
              f'{len(all_label_syms)} labels, {len(all_static_methods)} static methods')

    # Dedup by (se_off, ae_off)
    seen = set()
    deduped_funcs = []
    for f in all_func_syms:
        key = (f.get('se_off'), f.get('ae_off'))
        if key not in seen:
            seen.add(key)
            deduped_funcs.append(f)
    all_func_syms = deduped_funcs

    seen_labels = set()
    deduped_labels = []
    for l in all_label_syms:
        key = (l['name'], l.get('se_off'), l.get('ae_off'))
        if key not in seen_labels:
            seen_labels.add(key)
            deduped_labels.append(l)
    all_label_syms = deduped_labels

    return all_func_syms, all_label_syms, offset_id_map, all_static_methods, se_offset_map, ae_offset_map


def collect_src_relocations(
    src_dir: str,
    addr_lib,
    offset_id_map: Dict[str, int],
    se_offset_map: Dict[str, int] = None,
    ae_offset_map: Dict[str, int] = None,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> List[dict]:
    """Scan src/**/*.cpp for relocation symbols.

    Returns func_syms with both se_off and ae_off populated.
    """
    func_syms = _scan_src_relocations(src_dir, addr_lib, offset_id_map,
                                       se_offset_map=se_offset_map,
                                       ae_offset_map=ae_offset_map,
                                       root_namespace=root_namespace)

    # Dedup
    seen = set()
    deduped = []
    for f in func_syms:
        key = (f.get('se_off'), f.get('ae_off'))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if verbose:
        print(f'  src/ scan: {len(deduped)} func symbols from '
              f'{len(glob.glob(os.path.join(src_dir, "**", "*.cpp"), recursive=True))} cpp files')

    return deduped
