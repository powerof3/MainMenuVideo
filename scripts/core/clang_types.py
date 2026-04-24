#!/usr/bin/env python3
"""
Clang subprocess-based C++ type extraction for Ghidra import.

Two-pass approach using clang.exe:
  Pass 1: -ast-dump (text)                       → enums, base classes, virtual methods
  Pass 2: -fdump-record-layouts-complete/canonical → struct fields, byte offsets, sizes

After both passes, results are merged, template instantiations are discovered
via template_types.py, and layouts are propagated to empty template entries.

Project-agnostic: root namespace and category prefix are configurable.

Public API:
  collect_types()         - run both passes and return (enums, structs, template_source)
  find_clang_binary()     - locate clang.exe on Windows (registry, common paths, PATH)
  _setup_include_paths()  - build clang include args from CommonLib + stub dirs
"""

import os
import sys
import re
import shutil
import subprocess


# ---------------------------------------------------------------------------
# clang.exe discovery
# ---------------------------------------------------------------------------

def find_clang_binary():
    try:
        import winreg
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
    except ImportError:
        pass
    for path in [
        r'C:\Program Files\LLVM\bin\clang.exe',
        r'C:\Program Files (x86)\LLVM\bin\clang.exe',
    ]:
        if os.path.isfile(path):
            return path
    return shutil.which('clang')


# ---------------------------------------------------------------------------
# Type-string mapping (clang type names → pipeline type descriptors)
# ---------------------------------------------------------------------------

_CLANG_TYPE_MAP = {
    'bool': 'bool',
    'char': 'i8', 'signed char': 'i8', 'unsigned char': 'u8',
    'short': 'i16', 'signed short': 'i16', 'unsigned short': 'u16',
    'int': 'i32', 'signed int': 'i32', 'unsigned int': 'u32',
    'long': 'i32', 'signed long': 'i32', 'unsigned long': 'u32',
    'long long': 'i64', 'signed long long': 'i64', 'unsigned long long': 'u64',
    '__int64': 'i64', 'unsigned __int64': 'u64',
    'float': 'f32', 'double': 'f64',
    'void': 'void',
    'std::uint8_t': 'u8', 'uint8_t': 'u8',
    'std::uint16_t': 'u16', 'uint16_t': 'u16',
    'std::uint32_t': 'u32', 'uint32_t': 'u32',
    'std::uint64_t': 'u64', 'uint64_t': 'u64',
    'std::int8_t': 'i8', 'int8_t': 'i8',
    'std::int16_t': 'i16', 'int16_t': 'i16',
    'std::int32_t': 'i32', 'int32_t': 'i32',
    'std::int64_t': 'i64', 'int64_t': 'i64',
    'std::size_t': 'u64', 'size_t': 'u64',
    'std::ptrdiff_t': 'i64', 'ptrdiff_t': 'i64',
    'std::uintptr_t': 'u64', 'uintptr_t': 'u64',
    'std::intptr_t': 'i64', 'intptr_t': 'i64',
}

_KW_STRIP_RE = re.compile(r'\b(?:class|struct|union|enum)\s+')

_PRIM_BARE = frozenset({
    'void', 'bool', 'char', 'wchar_t', 'float', 'double', 'auto',
    'short', 'int', 'long',
    'signed', 'unsigned', '__int64', '__int32', '__int16', '__int8',
    'nullptr_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'size_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t',
})

_PRIM_MULTI = frozenset({
    'signed char', 'unsigned char',
    'signed short', 'unsigned short',
    'signed int', 'unsigned int',
    'signed long', 'unsigned long',
    'long long', 'signed long long', 'unsigned long long',
    'long double',
    'unsigned __int64', 'signed __int64',
})

_PRIM_ALL = _PRIM_BARE | _PRIM_MULTI


def _split_tmpl_args(inner):
    args = []
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


def _ensure_qualified(name, root_ns='RE'):
    """Prepend root_ns:: to bare identifiers. Already-qualified names are unchanged."""
    name = name.strip()
    if not name:
        return name
    if '::' in name:
        return name
    if name in _PRIM_ALL:
        return name
    if re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]*)?[uUlLfF]*', name):
        return name
    return root_ns + '::' + name


def _qualify_type(name, root_ns='RE'):
    """Recursively ensure a C++ type name is fully qualified.

    Strips cv-qualifiers and pointer/reference suffixes, qualifies the core
    name (and template arguments), then re-attaches them.
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
                name = name[:-len(t)].rstrip()
                _changed = True
                break
    name = name.strip()
    lt = name.find('<')
    if lt >= 0 and name.endswith('>'):
        outer = name[:lt].strip()
        inner_str = name[lt + 1:-1]
        qual_outer = _ensure_qualified(outer, root_ns)
        inner_args = _split_tmpl_args(inner_str)
        qual_args = ', '.join(_qualify_type(a, root_ns) for a in inner_args)
        return '{}{}<{}>{}'.format(leading, qual_outer, qual_args, trailing)
    if name in _PRIM_ALL:
        return '{}{}{}'.format(leading, name, trailing)
    if '::' in name:
        parts = _split_ns(name)
        qualified_parts = []
        for p in parts:
            plt = p.find('<')
            if plt >= 0 and p.endswith('>'):
                p_outer = p[:plt].strip()
                p_inner = p[plt + 1:-1]
                p_args = _split_tmpl_args(p_inner)
                q_args = ', '.join(_qualify_type(a, root_ns) for a in p_args)
                qualified_parts.append('{}<{}>'.format(p_outer, q_args))
            else:
                qualified_parts.append(p)
        return '{}{}{}'.format(leading, '::'.join(qualified_parts), trailing)
    if name in _PRIM_BARE:
        return '{}{}{}'.format(leading, name, trailing)
    return '{}{}{}{}'.format(leading, root_ns + '::', name, trailing)


def _record_type_to_pipeline(raw, root_ns='RE'):
    """Convert a raw clang type string to a pipeline type descriptor."""
    raw = _KW_STRIP_RE.sub('', raw.strip()).strip()
    if raw.endswith('*') or raw.endswith('&'):
        pointee = raw[:-1].strip()
        inner = _record_type_to_pipeline(pointee, root_ns)
        if inner.startswith('struct:') or inner.startswith('enum:'):
            return 'ptr:' + inner
        return 'ptr'
    if raw in _CLANG_TYPE_MAP:
        return _CLANG_TYPE_MAP[raw]
    m_arr = re.match(r'^(.+)\[(\d+)\]$', raw)
    if m_arr:
        elem_type = _record_type_to_pipeline(m_arr.group(1).strip(), root_ns)
        count = int(m_arr.group(2))
        return 'arr:{}:{}'.format(elem_type, count)
    if raw:
        return 'struct:' + _qualify_type(raw, root_ns)
    return 'ptr'


# ---------------------------------------------------------------------------
# Include path and stub generation
# ---------------------------------------------------------------------------

def _setup_include_paths(commonlib_include, clang_stub_dir):

    _vcpkg_include = None
    _vcpkg_root = os.environ.get('VCPKG_ROOT', '')
    if _vcpkg_root:
        for _triplet in ('x64-windows-static', 'x64-windows'):
            _candidate = os.path.join(_vcpkg_root, 'installed', _triplet, 'include')
            if (os.path.isfile(os.path.join(_candidate, 'binary_io', 'file_stream.hpp'))
                    and os.path.isfile(os.path.join(_candidate, 'spdlog', 'spdlog.h'))):
                _vcpkg_include = _candidate
                break

    if _vcpkg_include:
        third_party = _vcpkg_include
    else:
        os.makedirs(os.path.join(clang_stub_dir, 'binary_io'), exist_ok=True)
        os.makedirs(os.path.join(clang_stub_dir, 'spdlog'), exist_ok=True)

        bio_stub = os.path.join(clang_stub_dir, 'binary_io', 'file_stream.hpp')
        if not os.path.isfile(bio_stub):
            with open(bio_stub, 'w') as f:
                f.write('#pragma once\nnamespace binary_io { class file_istream {}; class file_ostream {}; }\n')

        spdlog_stub = os.path.join(clang_stub_dir, 'spdlog', 'spdlog.h')
        if not os.path.isfile(spdlog_stub):
            with open(spdlog_stub, 'w') as f:
                f.write('#pragma once\nnamespace spdlog { class logger {}; }\n')

        third_party = clang_stub_dir

    # Shadow spdlog/details/windows_include.h to undef REX::W32 macro conflicts
    win_stub_dir = clang_stub_dir
    os.makedirs(os.path.join(win_stub_dir, 'spdlog', 'details'), exist_ok=True)
    os.makedirs(os.path.join(win_stub_dir, 'spdlog', 'sinks'), exist_ok=True)

    with open(os.path.join(win_stub_dir, 'spdlog', 'sinks', 'wincolor_sink-inl.h'), 'w') as f:
        f.write('#pragma once\n')

    rex_w32_names = []
    rex_dir = os.path.join(commonlib_include, 'REX', 'W32')
    if os.path.isdir(rex_dir):
        for root, _dirs, files in os.walk(rex_dir):
            for fname in files:
                if fname.endswith('.h'):
                    try:
                        with open(os.path.join(root, fname), encoding='utf-8', errors='replace') as fh:
                            for line in fh:
                                m = re.match(r'\s*inline\s+(?:constexpr\s+|const\s+)?auto\s+(\w+)', line)
                                if m:
                                    rex_w32_names.append(m.group(1))
                    except OSError:
                        pass

    extra_undefs = ['IMAGE_FIRST_SECTION', 'IMAGE_SNAP_BY_ORDINAL64']
    undef_block = '\n'.join('#undef ' + n for n in rex_w32_names + extra_undefs)
    win_inc_stub = os.path.join(win_stub_dir, 'spdlog', 'details', 'windows_include.h')
    with open(win_inc_stub, 'w') as f:
        f.write(
            '#pragma once\n'
            '#ifndef NOMINMAX\n#define NOMINMAX\n#endif\n'
            '#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif\n'
            '#include <windows.h>\n'
            + undef_block + '\n'
        )

    parse_args = [
        '-x', 'c++',
        '-std=c++23',
        '-fms-compatibility',
        '-fms-extensions',
        '-DWIN32', '-D_WIN64',
        '-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH',
        '-D_CRT_USE_BUILTIN_OFFSETOF',
        '-DSPDLOG_COMPILED_LIB',
        '-I' + win_stub_dir,
        '-isystem', third_party,
        '-I' + commonlib_include,
    ]

    return parse_args


# ---------------------------------------------------------------------------
# AST text dump parser — enums, base classes, virtual methods
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(r'^([| ]*[|`]-)\s*(.*)')


def _parse_line(line):
    """Extract (depth, content) from an AST dump line.

    Returns (depth, content) or (0, None) if the line is not a tree node.
    """
    m = _LINE_RE.match(line)
    if m:
        return len(m.group(1)) // 2, m.group(2)
    if line and not line[0].isspace() and not line.startswith('|'):
        return 0, line.rstrip()
    return 0, None


def _parse_ast_dump(text, re_include_path, root_ns='RE', category_prefix='/CommonLibSSE'):
    """Parse clang -ast-dump text output for enums and virtual methods.

    Streams through the text tracking namespace/class nesting via indentation.
    Only records types defined under the given include path.

    Returns:
        enums: dict full_name -> {name, full_name, size, category, values}
        ast_classes: dict full_name -> {name, full_name, bases, has_vtable, vmethods, category}
    """
    enums = {}
    ast_classes = {}

    re_path_fwd = re_include_path.replace('\\', '/')

    # Nesting stack: [(depth, kind, name, in_re)]
    stack = []
    cur_enum = None
    cur_enum_depth = 0
    pending_const_name = None

    _ENUM_SIZE = {
        'unsigned char': 1, 'signed char': 1, 'char': 1,
        'unsigned short': 2, 'short': 2,
        'unsigned int': 4, 'int': 4,
        'unsigned long': 4, 'long': 4,
        'unsigned long long': 8, 'long long': 8,
    }

    def _qual_prefix():
        return '::'.join(s[2] for s in stack if s[2])

    def _is_re():
        return any(s[3] for s in stack)

    def _category():
        ns_parts = [s[2] for s in stack if s[1] == 'namespace' and s[2]]
        return category_prefix + '/' + '/'.join(ns_parts) if ns_parts else category_prefix

    def _src_is_re(content):
        m = re.search(r'<([^>]+)>', content)
        if m:
            return re_path_fwd in m.group(1).replace('\\', '/')
        return False

    for line in text.splitlines():
        depth, content = _parse_line(line)
        if content is None:
            continue

        # Pop stack entries at or deeper than current depth
        while stack and stack[-1][0] >= depth:
            popped = stack.pop()
            if popped[1] == 'enum' and cur_enum and cur_enum_depth >= depth:
                if cur_enum.get('values') is not None:
                    enums[cur_enum['full_name']] = cur_enum
                cur_enum = None
                cur_enum_depth = 0

        # NamespaceDecl — name is the last word
        if content.startswith('NamespaceDecl '):
            ns_name = content.rstrip().rsplit(None, 1)[-1]
            if ns_name.startswith('0x') or ns_name in ('C', 'C++'):
                continue
            in_re = _is_re() or ns_name == 'RE'
            stack.append((depth, 'namespace', ns_name, in_re))
            continue

        # EnumDecl
        if content.startswith('EnumDecl '):
            m = re.search(r"(?:class\s+)?([a-zA-Z_]\w*)\s+'([^']*)'", content)
            if m:
                enum_name = m.group(1)
                underlying = m.group(2)
                # Strip desugared type: 'std::uint32_t':'unsigned int' -> 'unsigned int'
                if ':' in underlying and "'" in underlying:
                    underlying = underlying.split("'")[-1] if "':'" in underlying else underlying
                m2 = re.search(r"'[^']*':'([^']*)'", content)
                if m2:
                    underlying = m2.group(1)
                in_re = _is_re() or _src_is_re(content)
                prefix = _qual_prefix()
                full_name = prefix + '::' + enum_name if prefix else enum_name
                stack.append((depth, 'enum', enum_name, in_re))
                if in_re and enum_name and full_name not in enums:
                    sz = _ENUM_SIZE.get(underlying, 4)
                    cur_enum = {
                        'name': enum_name,
                        'full_name': full_name,
                        'size': sz,
                        'category': _category(),
                        'values': [],
                    }
                    cur_enum_depth = depth
            continue

        # EnumConstantDecl
        if content.startswith('EnumConstantDecl ') and cur_enum:
            m = re.search(r"(\w+)\s+'", content)
            if m:
                pending_const_name = m.group(1)
            continue

        # value: Int N
        if pending_const_name and content.startswith('value: Int'):
            m = re.match(r'value:\s+Int\s+(-?\d+)', content)
            if m and cur_enum:
                cur_enum['values'].append((pending_const_name, int(m.group(1))))
            pending_const_name = None
            continue

        # CXXRecordDecl (class/struct definition)
        if content.startswith('CXXRecordDecl ') and content.endswith('definition'):
            m = re.search(r'(?:class|struct)\s+(\w+)\s+definition', content)
            if m:
                class_name = m.group(1)
                in_re = _is_re() or _src_is_re(content)
                prefix = _qual_prefix()
                full_name = prefix + '::' + class_name if prefix else class_name
                stack.append((depth, 'class', class_name, in_re))
                if in_re and class_name and full_name not in ast_classes:
                    ast_classes[full_name] = {
                        'name': class_name,
                        'full_name': full_name,
                        'bases': [],
                        'has_vtable': False,
                        'vmethods': {},
                        'methods': {},
                        'category': _category(),
                    }
            continue

        # Base class specifier
        if content.startswith(('public ', 'private ', 'protected ')) and "'" in content:
            m = re.match(r"(?:public|private|protected)\s+'([^']+)'(?::'([^']*)')?", content)
            if m:
                for s in reversed(stack):
                    if s[1] == 'class':
                        qn = _qual_prefix() + '::' + s[2] if _qual_prefix().endswith(s[2]) else '::'.join(ss[2] for ss in stack if ss[2])
                        # Reconstruct full name from stack
                        parts = [ss[2] for ss in stack if ss[1] in ('namespace', 'class') and ss[2]]
                        fn = '::'.join(parts)
                        if fn in ast_classes:
                            base_name = m.group(2) or m.group(1)
                            ast_classes[fn]['bases'].append(base_name)
                        break
            continue

        # Method declarations (virtual and non-virtual)
        if content.startswith('CXXMethodDecl '):
            is_virtual = ' virtual' in content
            m = re.search(r"(operator\(\)|operator\w*|\w+)\s+'([^']+)'", content)
            if m:
                method_name = m.group(1)
                method_sig = m.group(2)
                parts = [s[2] for s in stack if s[1] in ('namespace', 'class') and s[2]]
                fn = '::'.join(parts)
                if fn in ast_classes:
                    cls = ast_classes[fn]
                    if method_name and '<' not in method_name:
                        ret, params = _parse_method_sig(method_sig, root_ns)
                        if is_virtual:
                            cls['has_vtable'] = True
                            if method_name not in cls['vmethods']:
                                cls['vmethods'][method_name] = (ret, params)
                        if method_name not in cls['methods']:
                            is_static = ' static' in content
                            cls['methods'][method_name] = (ret, params, is_static)
            continue

        # Constructor declarations
        if content.startswith('CXXConstructorDecl ') and ' implicit ' not in content:
            m = re.search(r"(\w+)\s+'([^']+)'", content)
            if m:
                ctor_name = m.group(1)
                ctor_sig = m.group(2)
                parts = [s[2] for s in stack if s[1] in ('namespace', 'class') and s[2]]
                fn = '::'.join(parts)
                if fn in ast_classes:
                    cls = ast_classes[fn]
                    if ctor_name == cls['name'] and ctor_name not in cls['methods']:
                        _ret, params = _parse_method_sig(ctor_sig, root_ns)
                        cls['methods'][ctor_name] = ('void', params, False)
            continue

        # Free function declarations in namespaces (stored as pseudo-class methods)
        if content.startswith('FunctionDecl ') and ' implicit ' not in content and _is_re():
            m = re.search(r"(operator\(\)|operator\w*|\w+)\s+'([^']+)'", content)
            if m:
                func_name = m.group(1)
                func_sig = m.group(2)
                ns_parts = [s[2] for s in stack if s[1] == 'namespace' and s[2]]
                fn = '::'.join(ns_parts)
                if fn and fn not in ast_classes:
                    short_name = ns_parts[-1] if ns_parts else fn
                    ast_classes[fn] = {
                        'name': short_name,
                        'full_name': fn,
                        'bases': [],
                        'has_vtable': False,
                        'vmethods': {},
                        'methods': {},
                        'category': _category(),
                    }
                if fn and fn in ast_classes and func_name and '<' not in func_name:
                    cls = ast_classes[fn]
                    if func_name not in cls['methods']:
                        ret, params = _parse_method_sig(func_sig, root_ns)
                        is_static = ' static' in content
                        cls['methods'][func_name] = (ret, params, is_static)
            continue

        # Virtual destructor
        if content.startswith('CXXDestructorDecl ') and ' virtual' in content:
            parts = [s[2] for s in stack if s[1] in ('namespace', 'class') and s[2]]
            fn = '::'.join(parts)
            if fn in ast_classes:
                cls = ast_classes[fn]
                cls['has_vtable'] = True
                dtor_name = '~' + cls['name']
                if dtor_name not in cls['vmethods']:
                    cls['vmethods'][dtor_name] = ('void', [])
            continue

    if cur_enum and cur_enum.get('values') is not None:
        enums[cur_enum['full_name']] = cur_enum

    return enums, ast_classes


def _parse_method_sig(sig, root_ns='RE'):
    """Parse 'ReturnType (ParamTypes) const' into (ret_str, [(name, type_str)])."""
    sig = sig.strip()
    sig = re.sub(r'\)\s*(?:const|noexcept|override|\s)+$', ')', sig)
    m = re.match(r'^(.+?)\s*\(([^)]*)\)\s*$', sig)
    if not m:
        return 'void', []
    ret_raw = m.group(1).strip()
    params_raw = m.group(2).strip()
    ret = _record_type_to_pipeline(ret_raw, root_ns)
    params = []
    if params_raw and params_raw != 'void':
        for i, p in enumerate(params_raw.split(',')):
            p = p.strip()
            ptype = _record_type_to_pipeline(p, root_ns)
            params.append(('p{}'.format(i), ptype))
    return ret, params


# ---------------------------------------------------------------------------
# Record layout parser
# ---------------------------------------------------------------------------

def _parse_layouts_with_bases(text, root_ns='RE'):
    """Parse -fdump-record-layouts-complete output.

    Returns:
        layouts: dict type_name -> {size, fields, bases, has_vtable}
    """
    results = {}

    for block in re.split(r'\*\*\* Dumping AST Record Layout', text)[1:]:
        m_sz = re.search(r'\[sizeof=(\d+)', block)
        if not m_sz:
            continue
        sizeof_bytes = int(m_sz.group(1))

        type_name = ''
        fields = []
        bases = []
        has_vtable = False
        first_seen = False
        value_field_indents = []

        for line in block.splitlines():
            line_r = line.rstrip()
            if not line_r or line_r.lstrip().startswith('['):
                continue
            bar = line_r.find('|')
            if bar < 0:
                continue
            rest = line_r[bar + 1:]
            indent = len(rest) - len(rest.lstrip())
            content = rest.strip()
            if not content:
                continue

            # Pop value-field frames
            while value_field_indents and indent <= value_field_indents[-1]:
                value_field_indents.pop()

            if value_field_indents:
                continue

            # Record header
            if not first_seen and indent == 1:
                m_rec = re.match(r'(?:class|struct|union)\s+(.+?)\s*$', content)
                if m_rec:
                    first_seen = True
                    raw_name = _KW_STRIP_RE.sub('', m_rec.group(1)).strip()
                    raw_name = re.sub(r'\s*\(empty\)\s*$', '', raw_name)
                    type_name = _qualify_type(raw_name, root_ns)
                continue

            # Base class
            if '(base)' in content or '(primary base)' in content:
                m_off = re.match(r'^\s*(\d+)\s+\|', line_r)
                if m_off:
                    base_off = int(m_off.group(1))
                    m_base = re.match(r'^(?:class|struct)\s+(.+?)\s+\((?:primary )?base\)', content)
                    if m_base:
                        bname = _qualify_type(
                            _KW_STRIP_RE.sub('', m_base.group(1)).strip(), root_ns)
                        bases.append((bname, base_off))
                continue

            if '(empty)' in content:
                continue

            # Vtable pointer
            if 'vftable pointer' in content or 'vbtable pointer' in content:
                has_vtable = True
                continue

            # Field — plain offset (e.g. "  0 |") or bitfield ("0:0-7 |")
            m_off = re.match(r'^\s*(\d+)\s+\|', line_r)
            m_bf = None
            if not m_off:
                m_bf = re.match(r'^\s*(\d+):(\d+)-(\d+)\s+\|', line_r)
                if not m_bf:
                    continue

            if m_bf:
                bf_byte = int(m_bf.group(1))
                m_tn = re.match(
                    r'^(?:(?:class|struct|union|enum)\s+)?(.+?)\s+(\w+)\s*$', content)
                if not m_tn:
                    continue
                fname = m_tn.group(2)
                if not fields or '_bf_byte' not in fields[-1]:
                    fields.append({
                        'name': fname,
                        'offset': bf_byte,
                        'size': 0,
                        'type': '',
                        '_bf_byte': bf_byte,
                        '_bf_total': 0,
                    })
                continue

            is_record_field = bool(re.match(r'^(?:class|struct|union)\s+', content))

            m_tn = re.match(
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
                'type': _record_type_to_pipeline(ftype_raw, root_ns),
            })

            if is_record_field:
                value_field_indents.append(indent)

        if type_name:
            _bf_indices = set()
            for i, f in enumerate(fields):
                if '_bf_byte' in f:
                    if '_bf_total' in f:
                        del f['_bf_total']
                    del f['_bf_byte']
                    f['type'] = ''
                    _bf_indices.add(i)
            _backfill_sizes(fields, sizeof_bytes)
            _SIZE_TO_TYPE = {1: 'u8', 2: 'u16', 4: 'u32', 8: 'u64'}
            for i in _bf_indices:
                f = fields[i]
                f['type'] = _SIZE_TO_TYPE.get(f['size'], 'u32')
            results[type_name] = {
                'size': sizeof_bytes,
                'fields': fields,
                'bases': bases,
                'has_vtable': has_vtable,
            }

    return results



def _backfill_sizes(fields, total_size):
    _NATURAL = {
        'bool': 1, 'i8': 1, 'u8': 1,
        'i16': 2, 'u16': 2,
        'i32': 4, 'u32': 4, 'f32': 4,
        'i64': 8, 'u64': 8, 'f64': 8,
        'ptr': 8,
    }
    for i, f in enumerate(fields):
        next_off = fields[i + 1]['offset'] if i + 1 < len(fields) else total_size
        computed = max(next_off - f['offset'], 0)
        natural = _NATURAL.get(f.get('type', ''), 0)
        if natural and natural < computed:
            f['size'] = natural
        else:
            f['size'] = computed


def _split_ns(qualified):
    """Split a qualified C++ name on :: boundaries, respecting template <> nesting."""
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(qualified):
        c = qualified[i]
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        elif c == ':' and depth == 0 and i + 1 < len(qualified) and qualified[i + 1] == ':':
            parts.append(qualified[start:i])
            i += 2
            start = i
            continue
        i += 1
    parts.append(qualified[start:])
    return parts


def _short_name(qualified):
    """Get the unqualified (short) name from a qualified C++ name."""
    return _split_ns(qualified)[-1]


def _ns_parts(qualified):
    """Get the namespace parts (everything except the final name)."""
    parts = _split_ns(qualified)
    return parts[:-1] if len(parts) > 1 else []


# ---------------------------------------------------------------------------
# Merge AST + layout data into unified struct descriptors
# ---------------------------------------------------------------------------

def _merge_ast_and_layouts(ast_classes, layouts, re_include_path,
                           root_ns='RE', category_prefix='/CommonLibSSE'):
    """Merge AST class metadata with record layout data.

    Returns structs dict: full_name -> {name, full_name, size, category,
                                        fields, bases, has_vtable, vmethods}
    """
    structs = {}
    re_path_fwd = re_include_path.replace('\\', '/')

    # Index layouts by short name for matching
    layouts_by_short = {}
    for lname, ldata in layouts.items():
        short = _short_name(lname) if '::' in lname else lname
        lt = short.find('<')
        base_short = short[:lt] if lt >= 0 else short
        layouts_by_short.setdefault(base_short, []).append((lname, ldata))

    # Process AST classes — merge with layout data
    ns_prefix = root_ns + '::'
    for full_name, ast in ast_classes.items():
        layout = layouts.get(full_name)
        if not layout:
            layout = layouts.get(ns_prefix + full_name)
        if not layout:
            for lname, ldata in layouts_by_short.get(ast['name'], []):
                layout = ldata
                break

        key = full_name

        if layout:
            bases = []
            for bname, boff in layout['bases']:
                bases.append(bname)

            structs[key] = {
                'name': ast['name'],
                'full_name': key,
                'size': layout['size'],
                'category': ast['category'],
                'fields': layout['fields'],
                'bases': bases,
                'pdb_bases': layout['bases'],
                'has_vtable': layout['has_vtable'] or ast['has_vtable'],
                'vmethods': ast.get('vmethods', {}),
                'methods': ast.get('methods', {}),
            }
        else:
            structs[key] = {
                'name': ast['name'],
                'full_name': key,
                'size': 0,
                'category': ast['category'],
                'fields': [],
                'bases': ast['bases'],
                'has_vtable': ast['has_vtable'],
                'vmethods': ast.get('vmethods', {}),
                'methods': ast.get('methods', {}),
            }

    # Add layout-only types (templates, types not in AST class list)
    for lname, ldata in layouts.items():
        if lname in structs:
            continue

        short = _short_name(lname)

        bases = [bname for bname, _ in ldata['bases']]

        ns_parts = _ns_parts(lname)
        category = category_prefix + '/' + '/'.join(ns_parts) if ns_parts else category_prefix

        structs[lname] = {
            'name': short,
            'full_name': lname,
            'size': ldata['size'],
            'category': category,
            'fields': ldata['fields'],
            'bases': bases,
            'pdb_bases': ldata['bases'],
            'has_vtable': ldata['has_vtable'],
            'vmethods': {},
        }

    return structs


# ---------------------------------------------------------------------------
# Vtable slot computation
# ---------------------------------------------------------------------------

def _compute_vfuncs(structs, root_ns='RE'):
    slot_cache = {}
    vmname_cache = {}
    ns_prefix = root_ns + '::'

    def resolve(name):
        st = structs.get(name)
        if st:
            return st
        if name.startswith(ns_prefix):
            st = structs.get(name[len(ns_prefix):])
            if st:
                return st
        if '<' not in name:
            return structs.get(name.split('::')[-1])
        return None

    def all_vmethod_names(full_name, depth=0):
        if depth > 30:
            return frozenset()
        if full_name in vmname_cache:
            return vmname_cache[full_name]
        vmname_cache[full_name] = frozenset()
        st = structs.get(full_name)
        if not st:
            return frozenset()
        result = set(st.get('vmethods', {}).keys())
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                result |= all_vmethod_names(bs['full_name'], depth + 1)
            break
        frozen = frozenset(result)
        vmname_cache[full_name] = frozen
        return frozen

    def total_slots(full_name, depth=0):
        if depth > 30:
            return 0
        if full_name in slot_cache:
            return slot_cache[full_name]
        slot_cache[full_name] = 0
        st = structs.get(full_name)
        if not st:
            return 0
        base_count = 0
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                base_count = total_slots(bs['full_name'], depth + 1)
            break
        primary_base_names = frozenset()
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                primary_base_names = all_vmethod_names(bs['full_name'])
            break
        own_intro = sum(1 for n in st.get('vmethods', {}) if n not in primary_base_names)
        result = base_count + own_intro
        slot_cache[full_name] = result
        return result

    count = 0
    for st in structs.values():
        if not st.get('has_vtable'):
            continue
        primary_base_names = frozenset()
        base_start = 0
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                primary_base_names = all_vmethod_names(bs['full_name'])
                base_start = total_slots(bs['full_name'])
            break
        intro = [n for n in st.get('vmethods', {}) if n not in primary_base_names]
        if not intro:
            continue
        st['vfuncs'] = [(mname, (base_start + i) * 8) for i, mname in enumerate(intro)]
        count += 1

    print('Computed vtable slots for {} structs from AST'.format(count))


def _tmpl_base(name):
    """Extract template base name: 'RE::NiPointer<RE::Actor>' -> 'RE::NiPointer'."""
    lt = name.find('<')
    return name[:lt] if lt >= 0 else None


def _generalize_field(f):
    """Copy a field dict, replacing type-specific pointer types with generic ptr."""
    f = dict(f)
    t = f['type']
    if t.startswith('ptr:struct:') or t.startswith('ptr:enum:'):
        f['type'] = 'ptr'
    elif t.startswith('struct:') and f['size'] == 8:
        pass
    return f


def _propagate_template_layouts(structs):
    """Fill empty template placeholders from known instantiations of the same template.

    For each empty template instantiation (size 0, no fields), find another
    instantiation of the same template base that has layout data. If ALL known
    instantiations share the same size, propagate the field layout.
    """
    by_base = {}
    for key, st in structs.items():
        base = _tmpl_base(key)
        if base is None:
            continue
        by_base.setdefault(base, []).append((key, st))

    propagated = 0
    for base, entries in by_base.items():
        has_layout = [(k, s) for k, s in entries if s['size'] > 0 and s['fields']]
        empty = [(k, s) for k, s in entries if s['size'] == 0 and not s['fields']]
        if not has_layout or not empty:
            continue
        sizes = set(s['size'] for _, s in has_layout)
        if len(sizes) != 1:
            continue
        donor_size = sizes.pop()
        donor = has_layout[0][1]
        for key, st in empty:
            st['size'] = donor_size
            st['fields'] = [_generalize_field(f) for f in donor['fields']]
            st['bases'] = list(donor['bases'])
            st['has_vtable'] = donor['has_vtable']
            propagated += 1
    return propagated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_types(header_path, include_path, parse_args,
                  verbose=False, clang_binary=None,
                  root_namespace='RE', category_prefix='/CommonLibSSE'):
    """Parse C++ headers via clang.exe and collect type definitions.

    Two-pass approach:
      Pass 1: clang -ast-dump (text)                       → enums, bases, virtual methods
      Pass 2: clang -fdump-record-layouts-complete/canonical → field offsets, sizes, bases

    After merging, discovers template instantiation names and propagates
    layouts from known instantiations to empty ones of the same template base.

    Parameters
    ----------
    header_path:
        Path to the main header file to parse (e.g. Skyrim.h).
    include_path:
        Path to the include directory containing the source headers.
        Only types from files under this path are collected.
    parse_args:
        Clang command-line arguments (include paths, defines).
    verbose:
        Print progress information.
    clang_binary:
        Path to clang.exe. Auto-detected via find_clang_binary() if None.
    root_namespace:
        The root C++ namespace to qualify types with (default 'RE').
    category_prefix:
        Ghidra Data Type Manager category prefix (default '/CommonLibSSE').

    Returns
    -------
    (enums, structs, template_source) where template_source is embeddable
    Python source for the TEMPLATE_TYPE_MAP dict.
    """
    if not clang_binary:
        clang_binary = find_clang_binary()
    if not clang_binary:
        print('ERROR: clang.exe not found. Install LLVM or set PATH.')
        sys.exit(1)

    if verbose:
        print('Using clang: {}'.format(clang_binary))

    header_fwd = header_path.replace('\\', '/')

    # --- Pass 1: AST dump for enums and virtual methods ---
    if verbose:
        print('Pass 1: AST dump (enums, virtual methods)...')
    cmd_ast = [clang_binary] + parse_args + [
        '-fsyntax-only', '-ferror-limit=0',
        '-Xclang', '-ast-dump',
        header_fwd,
    ]
    result_ast = subprocess.run(cmd_ast, capture_output=True, text=True, encoding='utf-8', errors='replace')
    ast_text = result_ast.stdout
    if verbose:
        print('  AST dump: {} lines'.format(ast_text.count('\n')))

    enums, ast_classes = _parse_ast_dump(ast_text, include_path,
                                         root_ns=root_namespace,
                                         category_prefix=category_prefix)
    if verbose:
        print('  Parsed {} enums, {} classes from AST'.format(len(enums), len(ast_classes)))

    # --- Pass 2: Record layouts for field offsets and sizes ---
    if verbose:
        print('Pass 2: Record layouts (field offsets, sizes)...')
    cmd_layout = [clang_binary] + parse_args + [
        '-fsyntax-only', '-ferror-limit=0',
        '-Xclang', '-fdump-record-layouts-complete',
        '-Xclang', '-fdump-record-layouts-canonical',
        header_fwd,
    ]
    result_layout = subprocess.run(cmd_layout, capture_output=True, text=True, encoding='utf-8', errors='replace')
    layout_text = result_layout.stdout
    if verbose:
        print('  Layout dump: {} lines'.format(layout_text.count('\n')))

    layouts = _parse_layouts_with_bases(layout_text, root_ns=root_namespace)
    if verbose:
        ns_prefix = root_namespace + '::'
        ns_layouts = {k: v for k, v in layouts.items() if k.startswith(ns_prefix)}
        print('  Parsed {} record layouts ({} {}::)'.format(
            len(layouts), len(ns_layouts), root_namespace))

    # --- Merge AST + layouts ---
    structs = _merge_ast_and_layouts(ast_classes, layouts, include_path,
                                     root_ns=root_namespace,
                                     category_prefix=category_prefix)
    if verbose:
        print('  Merged: {} structs'.format(len(structs)))

    _compute_vfuncs(structs, root_ns=root_namespace)

    # --- Template instantiation types ---
    tmpl_category = category_prefix + '/' + root_namespace
    template_source = ''
    try:
        from template_types import process_template_types as _process_templates
        tmpl = _process_templates(structs)
        template_source = tmpl.map_source

        _created = 0
        for _orig, _display in tmpl.template_map.items():
            if _display not in structs and _display not in enums:
                structs[_display] = {
                    'name': _display, 'full_name': _display, 'size': 0,
                    'category': tmpl_category, 'fields': [], 'bases': [],
                    'has_vtable': False,
                }
                _created += 1
        if tmpl.template_map:
            print('Discovered {} template instantiation aliases ({} new placeholders)'.format(
                len(tmpl.template_map), _created))

        _propagated = _propagate_template_layouts(structs)
        if _propagated:
            print('Propagated layout to {} empty template instantiations'.format(_propagated))
    except ImportError:
        pass

    return enums, structs, template_source
