"""
Clang subprocess-based template instantiation layout extractor.

Uses the clang compiler binary with -fdump-record-layouts to get accurate
struct field layouts for C++ template instantiations.  This is the
"clangd method" — it uses the same LLVM/Clang toolchain that clangd is
built on, giving full compiler-grade template instantiation accuracy.

This approach:
  - Invokes the full clang compiler, which handles all C++ edge cases
  - Gets inherited/base-class fields inlined into the layout dump
  - Parses the -fdump-record-layouts text format for structured output

Usage:
    from clangd_template_layouts import extract_layouts, find_clang_binary

    clang_bin = find_clang_binary()   # auto-detects from registry/PATH/llvm
    layouts = extract_layouts(
        template_names,   # list[str] — PDB template names without RE::
        parse_args,       # list[str] — same as PARSE_ARGS_BASE (include/define flags)
        skyrim_h,         # str — path to RE/Skyrim.h
        clang_binary=clang_bin,
        map_type_fn=None, # optional callable(type_string) -> pipeline_type_str
        batch_size=100,
        verbose=False,
    )
    # Returns: dict[str, (int, list[dict])]
"""

from __future__ import annotations

import os
import re as _re
import subprocess
import tempfile
import winreg
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Primitive / stdlib type sets (must NOT receive a RE:: prefix)
# ---------------------------------------------------------------------------

_PRIM_BARE: frozenset = frozenset({
    'void', 'bool', 'char', 'wchar_t', 'float', 'double', 'auto',
    'short', 'int', 'long',
    'signed', 'unsigned', '__int64', '__int32', '__int16', '__int8',
    'nullptr_t',
    'uint8_t',  'uint16_t',  'uint32_t',  'uint64_t',
    'int8_t',   'int16_t',   'int32_t',   'int64_t',
    'size_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t',
})

_PRIM_MULTI: frozenset = frozenset({
    'signed char', 'unsigned char',
    'signed short', 'unsigned short',
    'signed int',   'unsigned int',
    'signed long',  'unsigned long',
    'long long',    'signed long long', 'unsigned long long',
    'long double',
    'unsigned __int64', 'signed __int64',
})

_PRIM_ALL: frozenset = _PRIM_BARE | _PRIM_MULTI


def _split_tmpl_args(inner: str) -> List[str]:
    """Split a template argument string at commas at depth 0."""
    args: List[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(inner):
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth -= 1
        elif ch == ',' and depth == 0:
            args.append(inner[start:i].strip())
            start = i + 1
    tail = inner[start:].strip()
    if tail:
        args.append(tail)
    return args


def _qualify_bare(name: str) -> str:
    """
    Qualify a simple (non-template, no cv/ptr qualifiers) name.
    Adds RE:: prefix unless the name is a primitive, a numeric literal,
    or already prefixed with RE:: / std::.
    """
    name = name.strip()
    if not name:
        return name
    for prefix in ('RE::', 'REX::', 'REL::', 'std::', 'fmt::', 'WinAPI::', 'SKSE::'):
        if name.startswith(prefix):
            return name
    if name in _PRIM_ALL:
        return name
    if _re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]*)?[uUlLfF]*', name):
        return name
    return 'RE::' + name


def _qualify_re(name: str) -> str:
    """
    Recursively qualify a C++ type name string with RE:: namespace prefix.

    Examples:
      'Actor *'              → 'RE::Actor *'
      'BSTArray<Actor *>'    → 'RE::BSTArray<RE::Actor *>'
      'unsigned int'         → 'unsigned int'
      'std::equal_to<int>'   → 'std::equal_to<int>'
      'const TESForm *'      → 'const RE::TESForm *'
    """
    name = name.strip()
    if not name:
        return name

    leading = ''
    for q in ('const ', 'volatile '):
        while name.startswith(q):
            leading += q
            name = name[len(q):]

    trailing = ''
    _changed = True
    while _changed:
        _changed = False
        for t in (' const', ' *', ' &', '*', '&'):
            if name.endswith(t):
                trailing = t + trailing
                name = name[: -len(t)].rstrip()
                _changed = True
                break

    name = name.strip()

    lt = name.find('<')
    if lt >= 0 and name.endswith('>'):
        outer = name[:lt].strip()
        inner_str = name[lt + 1 : -1]
        qual_outer = _qualify_bare(outer)
        inner_args = _split_tmpl_args(inner_str)
        qual_args = ', '.join(_qualify_re(a) for a in inner_args)
        return f'{leading}{qual_outer}<{qual_args}>{trailing}'

    if name in _PRIM_ALL:
        return f'{leading}{name}{trailing}'

    parts = name.split('::')
    first = parts[0].strip()
    if first in _PRIM_BARE or first in ('std', 'RE', 'REX', 'REL', 'WinAPI', 'SKSE', 'fmt'):
        return f'{leading}{name}{trailing}'

    return f'{leading}RE::{name}{trailing}'

# ---------------------------------------------------------------------------
# Clang binary discovery
# ---------------------------------------------------------------------------

def find_clang_binary() -> Optional[str]:
    """
    Locate clang.exe, searching:
      1. Windows registry HKLM\\SOFTWARE\\LLVM\\LLVM (Install_Dir)
      2. Common install paths
      3. PATH
    Returns None if not found.
    """
    # Registry
    for hive, key in [
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\LLVM\LLVM'),
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\LLVM\LLVM'),
    ]:
        try:
            with winreg.OpenKey(hive, key) as k:
                install_dir, _ = winreg.QueryValueEx(k, '')
                candidate = os.path.join(install_dir, 'bin', 'clang.exe')
                if os.path.isfile(candidate):
                    return candidate
        except OSError:
            pass

    # Common paths
    for path in [
        r'C:\Program Files\LLVM\bin\clang.exe',
        r'C:\Program Files (x86)\LLVM\bin\clang.exe',
    ]:
        if os.path.isfile(path):
            return path

    # PATH
    import shutil
    found = shutil.which('clang')
    return found


# ---------------------------------------------------------------------------
# Layout dump output parser
# ---------------------------------------------------------------------------

def _parse_record_layouts(text: str) -> Dict[str, Tuple[int, List[dict]]]:
    """
    Parse the output of clang -fdump-record-layouts.

    Returns a dict: type_name → (sizeof, [{'name', 'offset', 'size', 'type'}, ...])
    where type_name is the full qualified name as printed by clang.

    Indentation handling: clang indents nested records by 2 spaces per depth.
    The outer record header has 1 space after '|'; direct fields / base class
    markers have 3 spaces; fields inside a base class have 5 spaces (they are
    FLATTENED into the outer record and we want them), while sub-fields inside
    a nested value-struct field (like Color 'max' at offset 0 containing
    u8 red/green/blue/alpha) also have 5 spaces — but we must NOT include them
    because the outer record just has the single struct field by value.

    Distinction: a line at indent N marked '(base)' is a base-class wrapper —
    its sub-fields at indent N+2 belong to the outer record via inheritance.
    A line at indent N that IS a field (record-typed, no '(base)') pushes a
    skip frame: subsequent lines at indent > N are its sub-fields and are
    skipped until we return to indent <= N.
    """
    results: Dict[str, Tuple[int, List[dict]]] = {}

    for block in _re.split(r'\*\*\* Dumping AST Record Layout', text)[1:]:
        m_sz = _re.search(r'\[sizeof=(\d+)', block)
        if not m_sz:
            continue
        sizeof_bytes = int(m_sz.group(1))

        type_name = ''
        fields: List[dict] = []
        first_seen = False
        value_field_indents: List[int] = []   # stack of indent levels of active value-field parents

        for line in block.splitlines():
            line = line.rstrip()
            if not line or line.lstrip().startswith('['):
                continue
            bar = line.find('|')
            if bar < 0:
                continue
            rest = line[bar + 1:]
            indent = len(rest) - len(rest.lstrip())
            content = rest.strip()
            if not content:
                continue

            # Pop value-field frames whose depth we have exited
            while value_field_indents and indent <= value_field_indents[-1]:
                value_field_indents.pop()

            # Still inside a nested value field — skip this sub-field
            if value_field_indents:
                continue

            # Record header (indent=1, first line)
            if not first_seen and indent == 1:
                m_rec = _re.match(r'(?:class|struct|union)\s+(.+?)\s*$', content)
                if m_rec:
                    first_seen = True
                    type_name = m_rec.group(1).strip()
                    # Strip trailing annotations like '(empty)' that appear after
                    # the name on the header line for empty records.
                    type_name = _re.sub(r'\s*\((?:empty|base)\)\s*$', '', type_name)
                continue

            # Base-class wrapper: skip the marker line itself, do NOT push frame,
            # so the sub-fields (at indent+2) get included as inherited fields.
            if '(base)' in content:
                continue
            if '(empty)' in content:
                continue

            # Parse offset + field decl
            m_off = _re.match(r'^\s*(\d+)\s+\|', line)
            if not m_off:
                continue

            # Detect record-typed field (nested value struct/class/union):
            # these lines begin with 'class '/'struct '/'union ' AND have no (base)
            is_record_field = bool(_re.match(r'^(?:class|struct|union)\s+', content))

            m_tn = _re.match(
                r'^(?:(?:class|struct|union|enum)\s+)?(.+?)\s+(\w+)\s*$', content)
            if not m_tn:
                continue
            ftype_raw = m_tn.group(1).strip()
            fname = m_tn.group(2)
            if fname.startswith('_vptr') or fname == '':
                continue

            fields.append({
                'name': fname,
                'offset': int(m_off.group(1)),
                'size': 0,
                'type': _record_type_to_pipeline(ftype_raw),
            })
            # If this field is a record type, its sub-fields follow at deeper indent
            # and must be skipped (they belong to the nested record, not to us).
            if is_record_field:
                value_field_indents.append(indent)

        if type_name:
            _backfill_sizes(fields, sizeof_bytes)
            results[type_name] = (sizeof_bytes, fields)

    return results


_TYPE_NATURAL_SIZE: Dict[str, int] = {
    'bool': 1, 'i8': 1, 'u8': 1,
    'i16': 2, 'u16': 2,
    'i32': 4, 'u32': 4, 'f32': 4,
    'i64': 8, 'u64': 8, 'f64': 8,
    'ptr': 8,  # 64-bit pointer
}


def _backfill_sizes(fields: List[dict], total_size: int) -> None:
    """
    Set each field's size from offset differences, then cap to the natural
    size of the field's type to remove trailing padding from the calculation.
    """
    for i, f in enumerate(fields):
        next_off = fields[i + 1]['offset'] if i + 1 < len(fields) else total_size
        computed = max(next_off - f['offset'], 0)
        # Use natural type size when it's smaller than the computed (padding-inflated) size
        ftype = f.get('type', '')
        natural = _TYPE_NATURAL_SIZE.get(ftype, 0)
        if natural and natural < computed:
            f['size'] = natural
        else:
            f['size'] = computed


_CLANG_TYPE_MAP: Dict[str, str] = {
    # Primitive C types
    'bool': 'bool',
    'char': 'i8', 'signed char': 'i8', 'unsigned char': 'u8',
    'short': 'i16', 'signed short': 'i16', 'unsigned short': 'u16',
    'int': 'i32', 'signed int': 'i32', 'unsigned int': 'u32',
    'long': 'i32', 'signed long': 'i32', 'unsigned long': 'u32',
    'long long': 'i64', 'signed long long': 'i64', 'unsigned long long': 'u64',
    '__int64': 'i64', 'unsigned __int64': 'u64',
    'float': 'f32', 'double': 'f64',
    'void': 'void',
    # Stdint (with and without std:: prefix)
    'std::uint8_t': 'u8',  'uint8_t': 'u8',
    'std::uint16_t': 'u16','uint16_t': 'u16',
    'std::uint32_t': 'u32','uint32_t': 'u32',
    'std::uint64_t': 'u64','uint64_t': 'u64',
    'std::int8_t': 'i8',   'int8_t': 'i8',
    'std::int16_t': 'i16', 'int16_t': 'i16',
    'std::int32_t': 'i32', 'int32_t': 'i32',
    'std::int64_t': 'i64', 'int64_t': 'i64',
    'std::size_t': 'u64',  'size_t': 'u64',
    'std::ptrdiff_t': 'i64','ptrdiff_t': 'i64',
    'std::uintptr_t': 'u64','uintptr_t': 'u64',
    'std::intptr_t': 'i64', 'intptr_t': 'i64',
    # Template parameter names — emit as bare ptr (type not known at dump time)
    'element_type': 'ptr',   # NiPointer<T>, BSTSmartPointer<T>
    'value_type': 'ptr',
    'key_type': 'ptr',
    'mapped_type': 'ptr',
    'first_type': 'ptr',
    'second_type': 'ptr',
    'T': 'ptr',
}


_KW_ANYWHERE_RE = _re.compile(r'\b(?:class|struct|union|enum)\s+')


def _strip_type_keywords(raw: str) -> str:
    """Strip all 'class '/'struct '/'union '/'enum ' keyword tokens anywhere in the string."""
    return _KW_ANYWHERE_RE.sub('', raw)


def _record_type_to_pipeline(raw: str) -> str:
    """
    Convert a raw type string from -fdump-record-layouts to a pipeline type string.

    Clang's record layout dump omits the RE:: prefix on nested template arguments
    (prints 'RE::NiPointer<TESObjectREFR>' instead of 'RE::NiPointer<RE::TESObjectREFR>'),
    so inner template args must be re-qualified before emitting the struct reference.

    Examples:
        'RE::Actor *'                  → 'ptr:struct:RE::Actor'
        'unsigned int'                 → 'i32'
        'std::uint32_t'                → 'u32'
        'float'                        → 'f32'
        'element_type *'               → 'ptr'   (template param placeholder)
        'RE::NiPointer<TESObjectREFR>' → 'struct:RE::NiPointer<RE::TESObjectREFR>'
    """
    raw = _strip_type_keywords(raw.strip()).strip()

    # Pointer / reference
    if raw.endswith('*') or raw.endswith('&'):
        pointee = raw[:-1].strip()
        # Recurse to get the inner type
        inner = _record_type_to_pipeline(pointee)
        if inner.startswith('struct:') or inner.startswith('enum:'):
            return 'ptr:' + inner
        return 'ptr'

    # Check full name map (covers primitives, stdint, template param placeholders)
    if raw in _CLANG_TYPE_MAP:
        return _CLANG_TYPE_MAP[raw]

    # Array type: 'T[N]'
    m_arr = _re.match(r'^(.+)\[(\d+)\]$', raw)
    if m_arr:
        elem_type = _record_type_to_pipeline(m_arr.group(1).strip())
        count = int(m_arr.group(2))
        return f'arr:{elem_type}:{count}'

    # Qualified struct/class name — re-qualify nested template args (RE:: prefix)
    if raw:
        return 'struct:' + _qualify_re(raw)
    return 'ptr'


# ---------------------------------------------------------------------------
# Synthetic TU generation
# ---------------------------------------------------------------------------

def _gen_tu_content(skyrim_h: str, names: List[str]) -> str:
    lines = [
        f'#include "{skyrim_h}"\n',
        'namespace _tmpl_probe {\n',
    ]
    for i, name in enumerate(names):
        cpp_name = _qualify_re(name)
        # Force template instantiation via sizeof
        lines.append(f'using _T{i} = {cpp_name};\n')
        lines.append(f'static_assert(sizeof(_T{i}) >= 0);\n')
    lines.append('}\n')
    return ''.join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_layouts(
    template_names: List[str],
    parse_args: List[str],
    skyrim_h: str,
    clang_binary: Optional[str] = None,
    map_type_fn=None,    # ignored — type strings come from the dump text
    batch_size: int = 100,
    verbose: bool = False,
    timeout: int = 120,
) -> Dict[str, Tuple[int, List[dict]]]:
    """
    Run clang -fdump-record-layouts on batches of template instantiations and
    return their layouts.

    Parameters
    ----------
    template_names:
        List of type name strings WITHOUT RE:: prefix
        (e.g. ['BSTArray<Actor *>', 'NiPointer<NiAVObject>']).
    parse_args:
        Compiler flags (includes, defines, -std, etc.).
        Pass PARSE_ARGS_BASE from parse_commonlib_types.py, filtering out
        any Python-only flags.
    skyrim_h:
        Absolute path to RE/Skyrim.h.
    clang_binary:
        Path to clang.exe.  Auto-detected via find_clang_binary() if None.
    map_type_fn:
        Unused in this implementation (type strings are parsed from the
        -fdump-record-layouts text output).  Accepted for API compatibility
        with clang_template_layouts.extract_layouts().
    batch_size:
        Templates per clang invocation.
    verbose:
        Print per-batch status.
    timeout:
        Seconds to allow each clang invocation.

    Returns
    -------
    dict mapping original name → (size_bytes, fields_list), same format as
    clang_template_layouts.extract_layouts().
    """
    if clang_binary is None:
        clang_binary = find_clang_binary()
    if not clang_binary or not os.path.isfile(clang_binary):
        print('  [clangd-tmpl] ERROR: clang binary not found — '
              'set clang_binary or install LLVM')
        return {name: (0, []) for name in template_names}

    # Convert libclang parse_args to clang driver flags.
    # Libclang uses '-x', 'c++' which the driver handles differently.
    # Paired flags like '-isystem' '/path' must be kept together.
    clang_parse_args: List[str] = []
    _i = 0
    while _i < len(parse_args):
        a = parse_args[_i]
        # '-x c++' — skip both the flag and its value (driver infers from extension)
        if a in ('-x', '--language'):
            _i += 2   # consume flag + its value
            continue
        # Paired include flags: keep flag AND its path argument
        if a in ('-isystem', '-include', '-MF'):
            if _i + 1 < len(parse_args):
                clang_parse_args.append(a)
                clang_parse_args.append(parse_args[_i + 1])
                _i += 2
                continue
        # Single-argument flags that are safe to pass through
        if any(a.startswith(p) for p in ('-I', '-D', '-std', '-f', '-W', '-m')):
            clang_parse_args.append(a)
        _i += 1

    results: Dict[str, Tuple[int, List[dict]]] = {}
    unique_names = list(dict.fromkeys(template_names))

    for batch_start in range(0, len(unique_names), batch_size):
        batch = unique_names[batch_start : batch_start + batch_size]
        _process_batch(batch, clang_parse_args, skyrim_h, clang_binary,
                       results, verbose, timeout)

    for name in template_names:
        if name not in results:
            results[name] = (0, [])

    return results


def _process_batch(
    names: List[str],
    clang_args: List[str],
    skyrim_h: str,
    clang_bin: str,
    results: Dict,
    verbose: bool,
    timeout: int,
) -> None:
    src = _gen_tu_content(skyrim_h, names)
    vpath = os.path.join(tempfile.gettempdir(), '_clangd_tmpl_probe.cpp')

    with open(vpath, 'w', encoding='utf-8') as f:
        f.write(src)

    cmd = [clang_bin] + clang_args + [
        '-fsyntax-only',
        '-Xclang', '-fdump-record-layouts',
        vpath,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = proc.stderr + proc.stdout  # record layouts go to stderr on some builds
    except subprocess.TimeoutExpired:
        if verbose:
            print(f'  [clangd-tmpl] TIMEOUT for batch of {len(names)} types')
        for name in names:
            results[name] = (0, [])
        return
    except Exception as e:
        if verbose:
            print(f'  [clangd-tmpl] ERROR: {e}')
        for name in names:
            results[name] = (0, [])
        return

    # Parse all record layouts from the combined output
    raw_layouts = _parse_record_layouts(combined)

    # --- Name matching strategy ---
    # The dump uses fully-qualified names like 'RE::BSTArray<RE::Actor *>' while
    # our input uses unqualified names like 'BSTArray<Actor *>'.
    #
    # Matching passes (in priority order):
    #   1. Exact match after RE-qualification
    #   2. Match ignoring class/struct/union/enum keywords in dump names
    #   3. Match ignoring all RE:: prefixes (normalised comparison)
    #   4. Outer-template match: any instantiation of the same template.
    #      This works because all template instantiations with the same
    #      allocator/structure have identical field names and offsets
    #      (field types may differ only where a template parameter is used).

    def _outer(name: str) -> str:
        """Return the outer template name, stripping args and RE:: prefix."""
        lt = name.find('<')
        base = name[:lt].strip() if lt >= 0 else name.strip()
        return base.replace('RE::', '').replace('class ', '').replace('struct ', '')

    def _norm_clang_name(n: str) -> str:
        """Normalise a clang dump name for comparison."""
        return (n.replace('class ', '').replace('struct ', '')
                 .replace('union ', '').replace('enum ', '')
                 .replace('RE::', '').replace(' ', ''))

    # Build forward mapping from qualified names to their data
    qual_to_data: Dict[str, Tuple[int, List[dict]]] = {}
    outer_to_data: Dict[str, Tuple[int, List[dict]]] = {}
    for clang_name, layout in raw_layouts.items():
        norm = _norm_clang_name(clang_name)
        qual_to_data[norm] = layout
        outer_to_data.setdefault(_outer(clang_name), layout)

    for orig_name in names:
        if orig_name in results:
            continue

        qualified = _qualify_re(orig_name)
        norm_q = _norm_clang_name(qualified)

        # Pass 1–3: normalised name match
        layout = qual_to_data.get(norm_q)

        # Pass 4: outer template match (same struct layout across instantiations)
        if layout is None:
            outer_q = _outer(qualified)
            layout = outer_to_data.get(outer_q)

        if layout is not None:
            sz, fields = layout
            if verbose:
                print(f'  [clangd-tmpl] {orig_name}: {sz} bytes, {len(fields)} fields')
            results[orig_name] = (sz, fields)
        else:
            if verbose:
                print(f'  [clangd-tmpl] UNRESOLVED: {orig_name}')
            results[orig_name] = (0, [])

    # Mark any not yet resolved (shouldn't happen after above loop)
    for name in names:
        if name not in results:
            results[name] = (0, [])


