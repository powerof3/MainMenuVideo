"""
Libclang-based template instantiation layout extractor.

Given a list of C++ template type names (stored without the RE:: namespace
prefix, as they come from the PDB/struct pipeline), generates a synthetic
C++ translation unit, parses it with libclang, and extracts the byte layout
(size + field list) for each instantiation.

This is an alternative to the hand-written rules in template_structural_rules.py
and is selected via the --clang-templates flag in parse_commonlib_types.py.

Usage:
    from clang_template_layouts import extract_layouts
    layouts = extract_layouts(
        template_names,   # list[str] — e.g. ['BSTArray<Actor *>', ...]
        parse_args,       # list[str] — same as PARSE_ARGS_BASE
        skyrim_h,         # str — path to RE/Skyrim.h
        map_type_fn,      # callable(CXType) -> str — e.g. parse_commonlib_types._map_type
        batch_size=200,   # templates per TU (larger = faster, but more errors)
        verbose=False,
    )
    # Returns: dict[str, (int, list[dict])]
    #   key   = original name as passed in
    #   value = (size_bytes, [{'name', 'offset', 'size', 'type'}, ...])
    #           or (0, []) on parse failure
"""

from __future__ import annotations

import os
import re as _re
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

# libclang is an optional dependency. Only required for the libclang template
# layout mode; the rules/clangd paths and `_qualify_re` don't need it.
try:
    import clang.cindex as ci
except ImportError:
    ci = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Primitive / stdlib type sets (must NOT receive a RE:: prefix)
# ---------------------------------------------------------------------------

_PRIM_BARE: frozenset[str] = frozenset({
    'void', 'bool', 'char', 'wchar_t', 'float', 'double', 'auto',
    'short', 'int', 'long',
    'signed', 'unsigned', '__int64', '__int32', '__int16', '__int8',
    'nullptr_t',
    # sized stdint (without std:: prefix)
    'uint8_t',  'uint16_t',  'uint32_t',  'uint64_t',
    'int8_t',   'int16_t',   'int32_t',   'int64_t',
    'size_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t',
})

# Multi-word primitive names (after stripping cv/ptr qualifiers)
_PRIM_MULTI: frozenset[str] = frozenset({
    'signed char', 'unsigned char',
    'signed short', 'unsigned short',
    'signed int',   'unsigned int',
    'signed long',  'unsigned long',
    'long long',    'signed long long', 'unsigned long long',
    'long double',
    'unsigned __int64', 'signed __int64',
})

_PRIM_ALL: frozenset[str] = _PRIM_BARE | _PRIM_MULTI


# ---------------------------------------------------------------------------
# Template name → qualified C++ name
# ---------------------------------------------------------------------------

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
    # Numeric literal (integer or float)
    if _re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]*)?[uUlLfF]*', name):
        return name
    return 'RE::' + name


def _qualify_re(name: str) -> str:
    """
    Recursively qualify a C++ type name string with RE:: namespace prefix.

    Input names come from the PDB/struct pipeline and have NO RE:: prefix
    on their outer type (e.g. 'BSTArray<Actor *>').  This function adds
    RE:: to every identifier that is not a primitive, stdlib, or already
    qualified type.

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

    # Strip leading cv-qualifiers
    leading = ''
    for q in ('const ', 'volatile '):
        while name.startswith(q):
            leading += q
            name = name[len(q):]

    # Strip trailing const/pointer/reference tokens
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

    # Check for template args
    lt = name.find('<')
    if lt >= 0 and name.endswith('>'):
        outer = name[:lt].strip()
        inner_str = name[lt + 1 : -1]
        qual_outer = _qualify_bare(outer)
        inner_args = _split_tmpl_args(inner_str)
        qual_args = ', '.join(_qualify_re(a) for a in inner_args)
        return f'{leading}{qual_outer}<{qual_args}>{trailing}'

    # Multi-word primitives: check full name (e.g. 'unsigned int')
    if name in _PRIM_ALL:
        return f'{leading}{name}{trailing}'

    # Split at '::' — qualify first component only if unqualified
    parts = name.split('::')
    first = parts[0].strip()
    if first in _PRIM_BARE or first in ('std', 'RE', 'REX', 'REL', 'WinAPI', 'SKSE', 'fmt'):
        return f'{leading}{name}{trailing}'

    # Add RE:: prefix to the whole scoped name
    return f'{leading}RE::{name}{trailing}'


# ---------------------------------------------------------------------------
# Synthetic TU generation
# ---------------------------------------------------------------------------

def _gen_tu_content(skyrim_h: str, names: List[str]) -> str:
    """
    Generate a synthetic C++ source file that forces instantiation of each
    template type and allows field layout inspection.
    """
    lines = [
        f'#include "{skyrim_h}"\n',
        'namespace _tmpl_probe {\n',
    ]
    for i, name in enumerate(names):
        cpp_name = _qualify_re(name)
        # using alias forces instantiation
        lines.append(f'using _T{i} = {cpp_name};\n')
    lines.append('}\n')
    return ''.join(lines)


# ---------------------------------------------------------------------------
# Field extraction from a libclang type
# ---------------------------------------------------------------------------

def _extract_fields(typ: 'Any', map_type_fn: Callable) -> Tuple[int, List[dict]]:
    """
    Extract (size_bytes, fields) from a libclang record Type.

    NOTE: Due to a limitation in libclang's Python bindings, only DIRECT
    (non-inherited) fields of the record are returned.  Template types that
    store all their fields in base classes (e.g. BSTArray, which inherits
    from BSTArrayHeapAllocator) will have 0 fields even though size is
    correct.  Use the clangd approach (clangd_template_layouts) for complete
    layout information including inherited fields.
    """
    sz = typ.get_size()
    if sz < 0:
        canonical = typ.get_canonical()
        sz = canonical.get_size()
    if sz < 0:
        return 0, []

    fields = []
    rec_type = typ.get_canonical() if typ.kind != ci.TypeKind.RECORD else typ

    for field_cur in rec_type.get_fields():
        fname = field_cur.spelling
        if not fname:
            continue
        try:
            offset_bits = rec_type.get_offset(fname)
        except Exception:
            continue
        if offset_bits < 0:
            continue
        offset = offset_bits // 8
        ftype_str = map_type_fn(field_cur.type)
        fsize = field_cur.type.get_size()
        if fsize < 0:
            fsize = 0
        fields.append({
            'name': fname,
            'type': ftype_str,
            'offset': offset,
            'size': fsize,
        })

    return sz, fields


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_layouts(
    template_names: List[str],
    parse_args: List[str],
    skyrim_h: str,
    map_type_fn: Optional[Callable] = None,
    batch_size: int = 200,
    verbose: bool = False,
) -> Dict[str, Tuple[int, List[dict]]]:
    """
    Parse template instantiations via libclang and return their layouts.

    Parameters
    ----------
    template_names:
        List of type name strings as they appear in the struct pipeline
        (WITHOUT RE:: prefix), e.g. ['BSTArray<Actor *>', 'NiPointer<NiAVObject>'].
    parse_args:
        Compiler flags to pass to libclang (includes, defines, -std, etc.).
        Pass the same PARSE_ARGS_BASE used in parse_commonlib_types.py.
    skyrim_h:
        Absolute path to RE/Skyrim.h.
    map_type_fn:
        A callable(CXType) -> str mapping a libclang type to a pipeline
        type string ('ptr', 'struct:RE::Foo', 'i32', etc.).
        When None, a simple built-in mapper is used.
    batch_size:
        Number of types to instantiate per libclang TU.  Smaller batches
        produce cleaner diagnostics; larger batches are faster.
    verbose:
        Print per-type status messages.

    Returns
    -------
    dict mapping each input name → (size_bytes, fields_list)
    where fields_list is [] and size_bytes is 0 on failure.
    """

    if map_type_fn is None:
        map_type_fn = _builtin_map_type

    results: Dict[str, Tuple[int, List[dict]]] = {}

    # Deduplicate while preserving order
    unique_names = list(dict.fromkeys(template_names))

    # Process in batches to limit TU size
    for batch_start in range(0, len(unique_names), batch_size):
        batch = unique_names[batch_start : batch_start + batch_size]
        _process_batch(batch, parse_args, skyrim_h, map_type_fn, results, verbose)

    # Ensure every requested name has an entry
    for name in template_names:
        if name not in results:
            results[name] = (0, [])

    return results


def _process_batch(
    names: List[str],
    parse_args: List[str],
    skyrim_h: str,
    map_type_fn: Callable,
    results: Dict,
    verbose: bool,
) -> None:
    """Parse one batch of template names and populate results."""
    src = _gen_tu_content(skyrim_h, names)
    vpath = os.path.join(tempfile.gettempdir(), '_clang_tmpl_probe.cpp')

    idx = ci.Index.create()
    tu = idx.parse(
        vpath,
        args=parse_args,
        unsaved_files=[(vpath, src)],
        options=(
            ci.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES |
            ci.TranslationUnit.PARSE_INCOMPLETE
        ),
    )

    # Build name-index → alias cursor map from _tmpl_probe namespace
    alias_map: Dict[int, Any] = {}
    for cursor in tu.cursor.get_children():
        if (cursor.kind == ci.CursorKind.NAMESPACE
                and cursor.spelling == '_tmpl_probe'):
            for child in cursor.get_children():
                if child.kind == ci.CursorKind.TYPE_ALIAS_DECL:
                    sp = child.spelling  # '_T0', '_T1', …
                    if sp.startswith('_T') and sp[2:].isdigit():
                        alias_map[int(sp[2:])] = child
            break

    for i, name in enumerate(names):
        alias_cur = alias_map.get(i)
        if alias_cur is None:
            if verbose:
                print(f'  [clang-tmpl] no alias cursor for: {name}')
            results[name] = (0, [])
            continue

        underlying = alias_cur.underlying_typedef_type
        sz, fields = _extract_fields(underlying, map_type_fn)
        if sz <= 0:
            if verbose:
                print(f'  [clang-tmpl] size=0 for: {name}')
            results[name] = (0, [])
        else:
            if verbose:
                print(f'  [clang-tmpl] {name}: {sz} bytes, {len(fields)} fields')
            results[name] = (sz, fields)


# ---------------------------------------------------------------------------
# Fallback type mapper (used when map_type_fn is not supplied)
# ---------------------------------------------------------------------------

_BUILTIN_PRIM_MAP = {
    ci.TypeKind.VOID: 'void',
    ci.TypeKind.BOOL: 'bool',
    ci.TypeKind.CHAR_S: 'i8',   ci.TypeKind.SCHAR: 'i8',
    ci.TypeKind.UCHAR: 'u8',
    ci.TypeKind.SHORT: 'i16',   ci.TypeKind.USHORT: 'u16',
    ci.TypeKind.INT: 'i32',     ci.TypeKind.UINT: 'u32',
    ci.TypeKind.LONG: 'i32',    ci.TypeKind.ULONG: 'u32',
    ci.TypeKind.LONGLONG: 'i64',ci.TypeKind.ULONGLONG: 'u64',
    ci.TypeKind.FLOAT: 'f32',   ci.TypeKind.DOUBLE: 'f64',
} if ci is not None else {}

def _builtin_map_type(typ: 'Any', depth: int = 0) -> str:
    """Minimal type mapper used when parse_commonlib_types._map_type is not available."""
    if depth > 8:
        return 'ptr'
    kind = typ.kind
    if kind in _BUILTIN_PRIM_MAP:
        return _BUILTIN_PRIM_MAP[kind]
    if kind in (ci.TypeKind.POINTER, ci.TypeKind.LVALUEREFERENCE,
                ci.TypeKind.RVALUEREFERENCE):
        pointee = typ.get_pointee()
        inner = _builtin_map_type(pointee, depth + 1)
        if inner.startswith('struct:') or inner.startswith('enum:'):
            return 'ptr:' + inner
        return 'ptr'
    if kind == ci.TypeKind.ELABORATED:
        return _builtin_map_type(typ.get_named_type(), depth + 1)
    if kind == ci.TypeKind.TYPEDEF:
        return _builtin_map_type(typ.get_canonical(), depth + 1)
    if kind == ci.TypeKind.RECORD:
        sp = typ.spelling or ''
        if sp:
            return 'struct:' + sp
        sz = typ.get_size()
        if sz > 0:
            return f'bytes:{sz}'
        return 'ptr'
    if kind == ci.TypeKind.ENUM:
        sz = typ.get_size()
        if sz == 1: return 'u8'
        if sz == 2: return 'u16'
        if sz == 4: return 'u32'
        return 'i32'
    if kind == ci.TypeKind.CONSTANTARRAY:
        elem = _builtin_map_type(typ.element_type, depth + 1)
        count = typ.element_count
        if count > 0:
            return f'arr:{elem}:{count}'
        return 'ptr'
    sz = typ.get_size()
    if sz == 1: return 'i8'
    if sz == 2: return 'i16'
    if sz == 4: return 'i32'
    if sz == 8: return 'i64'
    if sz > 0:  return f'bytes:{sz}'
    return 'ptr'
