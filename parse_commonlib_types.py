#!/usr/bin/env python3
"""
Parse CommonLibSSE headers and generate Ghidra import scripts that create
struct/class/enum type definitions with function symbols and relocations.

Run with: python parse_commonlib_types.py --ccls-re PATH

Pipeline:
  Types:        ccle_client.py via ccls-re $ccls/dumpTypes
  Relocations:  reloc_parser.py (regex-based, single-pass SE+AE)
  PDB symbols:  pdbparse (extras/SkyrimSE.pdb public function names, fallback)
"""

import os
import sys
import re
import struct
import ctypes

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMMONLIB_INCLUDE = os.path.join(SCRIPT_DIR, 'extern', 'CommonLibSSE', 'include')
SKYRIM_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Skyrim.h')
RE_INCLUDE = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'ghidrascripts')


# ---------------------------------------------------------------------------
# Address library / PDB / rename-DB utilities (inlined from extract_signatures)
# ---------------------------------------------------------------------------

class AddressLibrary:
    """Loads address-library binary databases mapping RELOCATION_IDs to RVAs."""

    def __init__(self):
        self.se_db = {}
        self.ae_db = {}

    def load_bin(self, file_path):
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            f.read(4)   # fmt
            f.read(16)  # version
            name_len = struct.unpack('<I', f.read(4))[0]
            f.read(name_len)
            ptr_size   = struct.unpack('<I', f.read(4))[0]
            addr_count = struct.unpack('<I', f.read(4))[0]
            pvid = 0; poffset = 0
            for _ in range(addr_count):
                type_byte = struct.unpack('<B', f.read(1))[0]
                low = type_byte & 0xF; high = type_byte >> 4
                if   low == 0: id_val = struct.unpack('<Q', f.read(8))[0]
                elif low == 1: id_val = pvid + 1
                elif low == 2: id_val = pvid + struct.unpack('<B', f.read(1))[0]
                elif low == 3: id_val = pvid - struct.unpack('<B', f.read(1))[0]
                elif low == 4: id_val = pvid + struct.unpack('<H', f.read(2))[0]
                elif low == 5: id_val = pvid - struct.unpack('<H', f.read(2))[0]
                elif low == 6: id_val = struct.unpack('<H', f.read(2))[0]
                elif low == 7: id_val = struct.unpack('<I', f.read(4))[0]
                tpoffset = (poffset // ptr_size) if (high & 8) != 0 else poffset
                h_type = high & 7
                if   h_type == 0: off_val = struct.unpack('<Q', f.read(8))[0]
                elif h_type == 1: off_val = tpoffset + 1
                elif h_type == 2: off_val = tpoffset + struct.unpack('<B', f.read(1))[0]
                elif h_type == 3: off_val = tpoffset - struct.unpack('<B', f.read(1))[0]
                elif h_type == 4: off_val = tpoffset + struct.unpack('<H', f.read(2))[0]
                elif h_type == 5: off_val = tpoffset - struct.unpack('<H', f.read(2))[0]
                elif h_type == 6: off_val = struct.unpack('<H', f.read(2))[0]
                elif h_type == 7: off_val = struct.unpack('<I', f.read(4))[0]
                if (high & 8) != 0: off_val *= ptr_size
                db[id_val] = off_val; pvid = id_val; poffset = off_val
        return db

    def load_all(self, base_path):
        self.se_db = self.load_bin(os.path.join(base_path, 'version-1-5-97-0.bin'))
        self.ae_db = self.load_bin(os.path.join(base_path, 'versionlib-1-6-1170-0.bin'))


def _undecorate(name):
    """Demangle an MSVC-mangled symbol name using dbghelp.UnDecorateSymbolName."""
    try:
        buf = ctypes.create_string_buffer(512)
        if ctypes.windll.dbghelp.UnDecorateSymbolName(name.encode(), buf, 512, 0x1000):
            return buf.value.decode('ascii', errors='replace')
    except Exception:
        pass
    return name


def load_se_pdb_names(file_path):
    """Parse a PDB file and return dict of rva -> name for all public function symbols."""
    if not os.path.exists(file_path):
        return {}

    import pdbparse

    pdb = pdbparse.parse(file_path)
    dbi = pdb.STREAM_DBI
    gsym = pdb.streams[dbi.DBIHeader.symrecStream]

    sec_data = pdb.streams[dbi.DBIDbgHeader.snSectionHdr].data
    sections = [struct.unpack_from('<I', sec_data, i * 40 + 12)[0]
                for i in range(len(sec_data) // 40)]

    result = {}
    for name, rec in gsym.funcs.items():
        if not (rec.symtype & 0x2) or not (1 <= rec.segment <= len(sections)):
            continue
        if name.startswith('?'):
            name = _undecorate(name)
        if re.match(r'^FUN_[0-9A-Fa-f]+$', name):
            continue
        name = re.sub(r'_14[0-9A-Fa-f]{6,8}$', '', name)
        name = re.sub(r':{3,}', '::', name.replace('__', '::'))
        result[sections[rec.segment - 1] + rec.offset] = name

    return result


def load_ae_rename_db(file_path, ae_db):
    """Load skyrimae.rename: lines of '<ae_id> <name>', skip version line."""
    result = {}  # ae_offset -> name
    if not os.path.exists(file_path):
        return result
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for line in lines[1:]:  # skip version line
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) != 2:
            continue
        name = parts[1].rstrip('*').rstrip('_')
        try:
            ae_id = int(parts[0])
        except ValueError:
            continue
        off = ae_db.get(ae_id)
        if off:
            result[off] = name
    return result


VERSIONS = {
    'se': {
        'defines':     [],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_SE.py'),
    },
    'ae': {
        'defines':     ['-DSKYRIM_AE', '-DSKYRIM_SUPPORT_AE'],
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_AE.py'),
    },
}


# Third-party includes from vcpkg (binary_io, spdlog).
# ccls-re needs these to parse CommonLibSSE headers.
_VCPKG_INCLUDE = None
_vcpkg_root = os.environ.get('VCPKG_ROOT', '')
if _vcpkg_root:
    for _triplet in ('x64-windows-static', 'x64-windows'):
        _candidate = os.path.join(_vcpkg_root, 'installed', _triplet, 'include')
        if (os.path.isfile(os.path.join(_candidate, 'binary_io', 'file_stream.hpp'))
                and os.path.isfile(os.path.join(_candidate, 'spdlog', 'spdlog.h'))):
            _VCPKG_INCLUDE = _candidate
            break
if not _VCPKG_INCLUDE:
    print('ERROR: VCPKG_ROOT not set or spdlog/binary_io not installed.')
    print('  Install: vcpkg install spdlog binary-io --triplet=x64-windows')
    sys.exit(1)

PARSE_ARGS_BASE = [
    '-x', 'c++',
    '-std=c++23',
    '-fms-compatibility',
    '-fms-extensions',
    '-DWIN32', '-D_WIN64',
    '-D_CRT_USE_BUILTIN_OFFSETOF',
    '-DSPDLOG_COMPILED_LIB',
    '-isystem', _VCPKG_INCLUDE,
    '-I' + COMMONLIB_INCLUDE,
]

def _type_str_size(type_str):
    """Estimate byte size from our type string."""
    sizes = {
        'bool': 1, 'i8': 1, 'u8': 1,
        'i16': 2, 'u16': 2,
        'i32': 4, 'u32': 4, 'f32': 4,
        'i64': 8, 'u64': 8, 'f64': 8,
        'ptr': 8, 'void': 0,
    }
    if type_str in sizes:
        return sizes[type_str]
    if type_str.startswith('bytes:'):
        return int(type_str[6:])
    if type_str.startswith('arr:'):
        # arr:ELEM:COUNT — count is always the last colon-terminated integer
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem_size = _type_str_size(rest[:last])
            return elem_size * count
        return 0
    if type_str.startswith('enum:'):
        return 4  # default enum size
    if type_str.startswith('struct:'):
        return 8  # unknown, assume pointer-sized
    return 0


# ---------------------------------------------------------------------------
# Ghidra script generation
# ---------------------------------------------------------------------------

GHIDRA_MERGED_HEADER = '''\
# Ghidra import script: CommonLibSSE types + symbols
# Generated by parse_commonlib_types.py
# Run in Ghidra via Script Manager
#
# @category CommonLib
# @description Import CommonLibSSE type definitions and symbol names

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import (
    StructureDataType, EnumDataType, ArrayDataType, PointerDataType,
    CategoryPath, DataTypeConflictHandler,
    ByteDataType, WordDataType, DWordDataType, QWordDataType,
    CharDataType, BooleanDataType, VoidDataType,
    FloatDataType, DoubleDataType,
    ShortDataType, IntegerDataType, LongLongDataType,
    UnsignedShortDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
    FunctionDefinitionDataType, ParameterDefinitionImpl,
)
import re

dtm = currentProgram.getDataTypeManager()
CONFLICT = DataTypeConflictHandler.REPLACE_HANDLER

created = {}  # full_name -> DataType

_VOID  = VoidDataType()
_BYTE  = ByteDataType()
_PTR   = PointerDataType()
_BOOL  = BooleanDataType()
_I16   = ShortDataType()
_U16   = UnsignedShortDataType()
_I32   = IntegerDataType()
_U32   = UnsignedIntegerDataType()
_I64   = LongLongDataType()
_U64   = UnsignedLongLongDataType()
_F32   = FloatDataType()
_F64   = DoubleDataType()

def get_builtin(type_str):
    if type_str == 'void': return _VOID
    if type_str == 'bool': return _BOOL
    if type_str == 'i8':   return _BYTE
    if type_str == 'u8':   return _BYTE
    if type_str == 'i16':  return _I16
    if type_str == 'u16':  return _U16
    if type_str == 'i32':  return _I32
    if type_str == 'u32':  return _U32
    if type_str == 'i64':  return _I64
    if type_str == 'u64':  return _U64
    if type_str == 'f32':  return _F32
    if type_str == 'f64':  return _F64
    if type_str == 'ptr':  return _PTR
    return None

def _resolve_struct_name(name):
    """Look up a struct/class name in 'created', handling template instantiations."""
    if '<' in name:
        # Template instantiation: look up the sanitized alias in TEMPLATE_TYPE_MAP
        alias = TEMPLATE_TYPE_MAP.get(name)
        if alias:
            return created.get(alias)
        return None
    return created.get(name) or created.get(name.split('::')[-1])

def resolve_type(type_str):
    b = get_builtin(type_str)
    if b: return b
    if type_str.startswith('ptr:struct:'):
        name = type_str[11:]
        inner = _resolve_struct_name(name)
        return dtm.getPointer(inner, 8) if inner else _PTR
    if type_str.startswith('ptr:enum:'):
        name = type_str[9:]
        inner = created.get(name) or created.get(name.split('::')[-1])
        return dtm.getPointer(inner, 8) if inner else _PTR
    if type_str.startswith('ptr:'):
        inner = get_builtin(type_str[4:]) or resolve_type(type_str[4:])
        if inner: return dtm.getPointer(inner, 8)
    if type_str.startswith('ptr'): return _PTR
    if type_str.startswith('bytes:'):
        n = int(type_str[6:])
        if n == 1: return _BYTE
        if n == 2: return _I16
        if n == 4: return _I32
        if n == 8: return _I64
        return ArrayDataType(_BYTE, n, 1) if n > 1 else _BYTE
    if type_str.startswith('arr:'):
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem = resolve_type(rest[:last])
            if elem and count > 0:
                return ArrayDataType(elem, count, elem.getLength())
        return None
    if type_str.startswith('enum:'):
        name = type_str[5:]
        return created.get(name) or created.get(name.split('::')[-1])
    if type_str.startswith('struct:'):
        name = type_str[7:]
        return _resolve_struct_name(name)
    if type_str.startswith('vtblptr:'):
        name = type_str[8:]
        vtbl_dt = created.get('vtbl:' + name)
        if vtbl_dt:
            return dtm.getPointer(vtbl_dt, 8)
        return _PTR
    return None

def make_padding(size):
    if size == 1: return _BYTE
    return ArrayDataType(_BYTE, size, 1)


def convert_sig_to_ghidra(sig, func_name):
    """Convert a CommonLib C++ signature to a Ghidra-compatible C prototype."""
    if not sig or sig == 'func_t':
        return None

    if 'RELOCATION_ID' in sig or 'func_t>' in sig or 'decltype' in sig:
        return None
    if ')(' in sig:
        return None
    if ':(' in sig:
        return None

    is_static = bool(re.search(r'\\bstatic\\b', sig))

    sig = ' '.join(sig.split())

    # Strip any leading `typedef ...;` declarations. CommonLibSSE occasionally
    # embeds nested typedefs in extracted function-body signatures, which would
    # otherwise end up concatenated into the return-type token we emit to
    # Ghidra's C parser.
    while True:
        _m_td = re.match(r'\\s*typedef\\s+[^;]+;\\s*', sig)
        if not _m_td: break
        sig = sig[_m_td.end():]

    sig = re.sub(r'^//\\s*[0-9A-Fa-f]+\\s*', '', sig)
    sig = re.sub(r'^//\\s*', '', sig)
    sig = re.sub(r'\\s*//[^\\n]*', '', sig)
    sig = re.sub(r'#\\w+\\b[^\\n]*', '', sig)
    sig = re.sub(r'\\b(?:public|private|protected)\\s*:\\s*', '', sig)
    sig = re.sub(r'\\boverride\\s+\\w+\\s*\\([^)]*\\)\\s*', '', sig)
    sig = re.sub(r'\\bRUNTIME_DATA_CONTENT\\b', '', sig)
    sig = re.sub(r'!\\w+\\([^)]*\\)\\s+', '', sig)

    sig = sig.replace('[[nodiscard]]', '')
    sig = re.sub(r'\\bstatic\\b', '', sig)
    sig = re.sub(r'\\bvirtual\\b', '', sig)
    sig = sig.strip()

    sig = _patch_templates(sig)

    candidates = []
    depth = 0
    for i, c in enumerate(sig):
        if c == '<': depth += 1
        elif c == '>': depth -= 1
        elif c == '(' and depth == 0:
            candidates.append(i)

    if not candidates:
        return None

    paren_idx = None
    for idx in reversed(candidates):
        before = sig[:idx].rstrip()
        if before and re.search(r'[\\w*&]\\s*$', before):
            stripped_ret = before.strip()
            if stripped_ret and not re.match(
                r'^(if|for|while|switch|return|override|namespace|class|struct)\\b',
                stripped_ret.split()[-1] if stripped_ret.split() else ''
            ):
                paren_idx = idx
                break

    if paren_idx is None or paren_idx == 0:
        return None

    ret_type_raw = sig[:paren_idx].strip()
    params = sig[paren_idx:]

    ret_type = ret_type_raw
    for pat in [r'.*\\b(?:public|private|protected)\\s*:\\s*',
                r'.*\\b(?:override)\\s+\\w+\\s*\\([^)]*\\)\\s*',
                r'.*//[^/]*\\s+',
                r'.*#\\w+[^(]*\\s+',
                r'.*!\\w+\\([^)]*\\)\\s+',
                r'.*\\bnamespace\\s+\\w+\\s*\\{\\s*',
                r'.*\\bmembers\\b\\s*']:
        m = re.match(pat, ret_type, re.DOTALL)
        if m: ret_type = ret_type[m.end():]

    ret_type = ret_type.strip()
    if not ret_type:
        return None

    def simplify_type(t, is_return=False):
        t = re.sub(r'\\s*=\\s*[^,)]*$', '', t)
        t = t.replace('std::uint64_t', 'ulonglong')
        t = t.replace('std::int64_t', 'longlong')
        t = t.replace('std::uint32_t', 'uint')
        t = t.replace('std::int32_t', 'int')
        t = t.replace('std::uint16_t', 'ushort')
        t = t.replace('std::int16_t', 'short')
        t = t.replace('std::uint8_t', 'uchar')
        t = t.replace('std::int8_t', 'char')
        t = t.replace('std::size_t', 'ulonglong')
        t = t.replace('std::ptrdiff_t', 'longlong')
        # Plain C99/POSIX fixed-width types
        t = re.sub(r'\\buint64_t\\b', 'ulonglong', t)
        t = re.sub(r'\\bint64_t\\b', 'longlong', t)
        t = re.sub(r'\\buint32_t\\b', 'uint', t)
        t = re.sub(r'\\bint32_t\\b', 'int', t)
        t = re.sub(r'\\buint16_t\\b', 'ushort', t)
        t = re.sub(r'\\bint16_t\\b', 'short', t)
        t = re.sub(r'\\buint8_t\\b', 'uchar', t)
        t = re.sub(r'\\bint8_t\\b', 'char', t)
        t = re.sub(r'\\bsize_t\\b', 'ulonglong', t)
        # stdlib/C++ types that survive namespace stripping
        t = re.sub(r'\\bresult\\b', 'int', t)
        t = re.sub(r'\\bhours\\b', 'longlong', t)
        t = re.sub(r'\\bminutes\\b', 'longlong', t)
        t = re.sub(r'\\bseconds\\b', 'longlong', t)
        t = re.sub(r'\\bErrorCode\\b', 'uint', t)
        t = re.sub(r'\\bmbstate_t\\b', 'void', t)
        t = re.sub(r'\\bva_list\\b', 'void *', t)
        t = re.sub(r'\\bchar16_t\\b', 'ushort', t)
        t = re.sub(r'\\bchar32_t\\b', 'uint', t)
        t = re.sub(r'\\bwchar_t\\b', 'ushort', t)
        t = re.sub(r'\\bconst\\b\\s*', '', t)
        t = re.sub(r'(\\w[\\w:<>]*)\\s*&', r'\\1 *', t)
        for _ in range(5):
            prev = t
            t = re.sub(r'\\w[\\w:]*<[^<>]*>\\s*\\*', 'void *', t)
            t = re.sub(r'\\w[\\w:]*<[^<>]*>', 'void', t)
            if t == prev: break
        t = re.sub(r'Args\\s*\\.\\.\\..*', '', t)
        if not is_return:
            t = re.sub(r'\\[.*?\\]', '', t)
        t = re.sub(r'\\w+::', '', t)
        return t.strip()

    ret_type = simplify_type(ret_type, is_return=True)
    if not ret_type:
        return None
    parts = ret_type.split()
    if len(parts) > 1 and parts[-1] not in ('*',) and not parts[-1].endswith('*'):
        ret_type = ' '.join(parts[:-1])

    params_inner = params[1:-1].strip() if params.endswith(')') else params[1:].rstrip(')').strip()

    if params_inner == '' or params_inner == 'void':
        ghidra_params = 'void'
    else:
        param_list = []
        current = ''; depth = 0
        for c in params_inner:
            if c == '<': depth += 1
            elif c == '>': depth -= 1
            elif c == ',' and depth == 0:
                param_list.append(current.strip()); current = ''; continue
            current += c
        if current.strip(): param_list.append(current.strip())

        ghidra_params_list = []
        for p in param_list:
            p = simplify_type(p)
            if not p: continue
            tokens = p.split()
            if len(tokens) == 2 and tokens[0] == 'void' and '*' not in tokens[1]:
                p = 'void * ' + tokens[1]
            if tokens:
                last = tokens[-1].rstrip('*')
                if last in ('int','uint','float','double','bool','void','char',
                            'short','long','uchar','ushort','ulonglong','longlong') or last.endswith('*'):
                    p = p + ' param' + str(len(ghidra_params_list))
            ghidra_params_list.append(p)

        ghidra_params = ', '.join(ghidra_params_list) if ghidra_params_list else 'void'

    simple_name = func_name.split('::')[-1] if '::' in func_name else func_name

    if '::' in func_name and not is_static:
        class_name = func_name.rsplit('::', 1)[0]
        class_name_simple = class_name.split('::')[-1] if '::' in class_name else class_name
        if class_name_simple and created.get(class_name_simple):
            this_type = class_name_simple
        else:
            this_type = 'void'
        this_param = this_type + ' * this'
        if ghidra_params == 'void':
            ghidra_params = this_param
        else:
            ghidra_params = this_param + ', ' + ghidra_params

    return ret_type + ' ' + simple_name + '(' + ghidra_params + ')'


_SAFE_TYPES = {
    'void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double',
    'uchar', 'ushort', 'uint', 'ulong', 'longlong', 'ulonglong',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'byte', 'word', 'dword', 'qword', 'pointer', 'unsigned', 'signed',
}

def sanitize_unknown_types(proto):
    """Replace unknown types with void* for Ghidra parse fallback."""
    m = re.match(r'(.*?)\\s+(\\w+)\\s*\\((.*)\\)$', proto)
    if not m: return proto
    ret, name, params = m.group(1), m.group(2), m.group(3)

    def sanitize_token(t):
        t = t.strip()
        if not t or t == 'void': return t
        parts = t.split()
        base = parts[0].rstrip('*')
        if base.lower() in _SAFE_TYPES: return t
        is_ptr = '*' in t
        if is_ptr:
            star_count = t.count('*')
            stars = ' ' + '*' * star_count
            param_name = ''
            if len(parts) > 1 and '*' not in parts[-1]:
                param_name = ' ' + parts[-1]
            return 'void' + stars + param_name
        else:
            if len(parts) > 1 and parts[-1].isidentifier():
                return 'void * ' + parts[-1]
            return 'void *'

    ret_base = ret.rstrip('*').rstrip().split()[-1] if ret.split() else ret
    if ret_base.lower() not in _SAFE_TYPES:
        if '*' in ret: ret = 'void ' + '*' * ret.count('*')
        else: ret = 'void *'

    if params.strip() == 'void':
        safe_params = 'void'
    else:
        safe_params = ', '.join(sanitize_token(p.strip()) for p in params.split(','))

    return ret + ' ' + name + '(' + safe_params + ')'

'''

GHIDRA_MERGED_FOOTER = '''\

def run():
    # Pass 1: import type definitions (enums, vtable structs, struct fields)
    # Use a DTM transaction to defer GUI updates until the end.
    tx_types = dtm.startTransaction('Import CommonLib types')
    try:
        _import_types()
    finally:
        dtm.endTransaction(tx_types, True)

    # Pass 2+3+4: apply symbol names, walk vtable addresses, then apply fallback symbols.
    # Fallback runs last so vtable-named functions are never overwritten by lower-priority sources.
    tx_syms = currentProgram.startTransaction('CommonLib symbol import')
    try:
        _import_symbols()
        _import_vtable_names()
        _import_fallback_symbols()
    finally:
        currentProgram.endTransaction(tx_syms, True)

    print('All passes complete.')


def _import_types():
    # Pass 1a: create all enums
    monitor.setMessage('Creating enums...')
    for en in ENUMS:
        name, size, category, values = en
        e = EnumDataType(CategoryPath(category), name, size)
        for vname, vval in values:
            try:
                e.add(vname, vval)
            except Exception:
                e.add(vname + '_', vval)
        dt = dtm.addDataType(e, CONFLICT)
        created[name] = dt
        created[category + '/' + name] = dt
        ns = category[len('/CommonLibSSE/'):].replace('/', '::')
        if ns:
            created[ns + '::' + name] = dt
    print('Created {} enums'.format(len(ENUMS)))

    # Pass 1b: create vtable structs (function pointer tables)
    monitor.setMessage('Creating vtable structs...')
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots = vt
        s = StructureDataType(CategoryPath(category), vname, vtbl_size)
        for slot_off, slot_name, slot_ret, slot_params in slots:
            field_name = slot_name.replace('~', '_dtor_') if slot_name.startswith('~') else slot_name
            if slot_off + 8 <= vtbl_size:
                try:
                    if slot_ret is not None and slot_params is not None:
                        fdef = FunctionDefinitionDataType(CategoryPath(category), field_name + '_t', dtm)
                        ret_dt = resolve_type(slot_ret)
                        if ret_dt:
                            fdef.setReturnType(ret_dt)
                        if slot_params:
                            param_defs = []
                            for pname, ptype in slot_params:
                                pdt = resolve_type(ptype) or _PTR
                                param_defs.append(ParameterDefinitionImpl(pname, pdt, ''))
                            fdef.setArguments(param_defs)
                        fptr = dtm.getPointer(dtm.addDataType(fdef, CONFLICT), 8)
                        s.replaceAtOffset(slot_off, fptr, 8, field_name, '')
                    else:
                        s.replaceAtOffset(slot_off, _PTR, 8, field_name, '')
                except Exception:
                    pass
        dt = dtm.addDataType(s, CONFLICT)
        created['vtbl:' + vname] = dt
    print('Created {} vtable structs'.format(len(VTABLES)))

    # Pass 1c: create all structs (empty shells)
    monitor.setMessage('Creating struct shells...')
    for st in STRUCTS:
        name, size, category, fields, bases, has_vtable = st
        s = StructureDataType(CategoryPath(category), name, size)
        dt = dtm.addDataType(s, CONFLICT)
        created[name] = dt
        created[category + '/' + name] = dt
        ns = category[len('/CommonLibSSE/'):].replace('/', '::')
        if ns:
            created[ns + '::' + name] = dt
    # Also register C-safe alias names for template structs (for CParserUtils resolution)
    _display_to_c = {}
    for _orig, _display in TEMPLATE_TYPE_MAP.items():
        _c_alias = TEMPLATE_C_ALIAS_MAP.get(_orig, '')
        if _c_alias and _display != _c_alias:
            _display_to_c[_display] = _c_alias
    for _display, _c_alias in _display_to_c.items():
        dt = created.get(_display)
        if dt and _c_alias not in created:
            created[_c_alias] = dt
    print('Created {} struct shells'.format(len(STRUCTS)))

    # Pass 1d: fill in struct fields
    monitor.setMessage('Filling struct fields...')
    filled = 0
    for st in STRUCTS:
        name, size, category, fields, bases, has_vtable = st
        s = dtm.getDataType(CategoryPath(category), name)
        if not s:
            continue
        for field in fields:
            fname, ftype_str, foffset, fsize = field
            if fsize <= 0 or foffset + fsize > size:
                continue
            dt_field = resolve_type(ftype_str)
            if dt_field and dt_field.getLength() == fsize:
                use_dt = dt_field
                use_name = fname
            else:
                use_dt = make_padding(fsize)
                use_name = fname + '_raw'
            try:
                s.replaceAtOffset(foffset, use_dt, fsize, use_name, '')
            except Exception:
                pass
        filled += 1
    print('Filled {} structs'.format(filled))


def _import_symbols():
    version_key = 's' if VERSION == 'se' else 'a'
    symbol_table = currentProgram.getSymbolTable()
    base_addr = currentProgram.getImageBase()
    fm = currentProgram.getFunctionManager()

    print('Target version: ' + VERSION.upper())
    print('Applying ' + str(len(SYMBOLS)) + ' symbols...')

    count_sym = 0; count_func = 0; count_sig = 0; count_sig_fail = 0
    used_names_at_addr = {}
    name_occurrence_count = {}

    for i, s in enumerate(SYMBOLS):
        off = s.get(version_key)
        if not off: continue
        off = int(off)

        addr = base_addr.add(off)
        sname = s['n']

        if addr not in used_names_at_addr:
            used_names_at_addr[addr] = set()
        if sname in used_names_at_addr[addr]:
            continue

        if sname in name_occurrence_count:
            name_occurrence_count[sname] += 1
            final_name = sname + '_' + str(name_occurrence_count[sname])
        else:
            name_occurrence_count[sname] = 0
            final_name = sname

        try:
            symbol_table.createLabel(addr, final_name, SourceType.USER_DEFINED)
            used_names_at_addr[addr].add(sname)
            count_sym += 1
            if s['t'] == 'label':
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu:
                    if final_name.startswith('RTTI_'):
                        cu.setComment(0, 'Source: CommonLibSSE (Offsets_RTTI.h)')
                    elif final_name.startswith('VTABLE_'):
                        cu.setComment(0, 'Source: CommonLibSSE (Offsets_VTABLE.h)')
                    elif s.get('src'):
                        cu.setComment(0, 'Source: ' + s['src'])
        except: pass

        if s['t'] == 'func':
            try:
                f = fm.getFunctionAt(addr)
                if not f:
                    cmd = DisassembleCommand(addr, None, True)
                    cmd.applyTo(currentProgram)
                    f = createFunction(addr, final_name)

                if f:
                    curr_name = f.getName()
                    if curr_name.startswith('FUN_') or curr_name.startswith('sub_'):
                        f.setName(final_name, SourceType.USER_DEFINED)

                    comment_parts = []
                    se_id = s.get('si')
                    ae_id = s.get('ai')
                    if se_id and ae_id:
                        comment_parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
                    elif se_id:
                        comment_parts.append('REL::ID(' + str(se_id) + ')')
                    elif ae_id:
                        comment_parts.append('REL::ID(' + str(ae_id) + ')')
                    src = s.get('src', '')
                    if src == 'CommonLibSSE':
                        comment_parts.append('Source: CommonLibSSE headers')
                    elif src == 'skyrimae.rename':
                        comment_parts.append('Source: AE rename database (fallback)')
                    elif src == 'SkyrimSE.pdb':
                        comment_parts.append('Source: SkyrimSE.pdb public symbols (fallback)')
                    if comment_parts:
                        cu = currentProgram.getListing().getCodeUnitAt(addr)
                        if cu:
                            cu.setComment(0, '\\n'.join(comment_parts))

                    if 'sig' in s and s['sig']:
                        proto = convert_sig_to_ghidra(s['sig'], final_name)
                        if proto:
                            applied = False
                            try:
                                func_def = CParserUtils.parseSignature(None, currentProgram, proto, True)
                                if func_def:
                                    cmd = ApplyFunctionSignatureCmd(addr, func_def, SourceType.USER_DEFINED, True, False)
                                    cmd.applyTo(currentProgram)
                                    applied = True
                            except: pass
                            if not applied:
                                proto_safe = sanitize_unknown_types(proto)
                                if proto_safe != proto:
                                    try:
                                        func_def = CParserUtils.parseSignature(None, currentProgram, proto_safe, True)
                                        if func_def:
                                            cmd = ApplyFunctionSignatureCmd(addr, func_def, SourceType.USER_DEFINED, True, False)
                                            cmd.applyTo(currentProgram)
                                            applied = True
                                    except: pass
                            if applied:
                                count_sig += 1
                            else:
                                count_sig_fail += 1
                                if count_sig_fail <= 20:
                                    print('SIG FAIL: ' + proto[:120])
                    count_func += 1
            except: pass

        if i % 5000 == 0 and i > 0:
            print('Progress: ' + str(i) + ' symbols processed...')

    print('Labels: ' + str(count_sym) + ', Functions: ' + str(count_func))
    print('Signatures applied: ' + str(count_sig) + ', failed: ' + str(count_sig_fail))


def _type_to_c(type_str):
    """Convert internal type descriptor to a C type name for CParserUtils."""
    if type_str == 'void':  return 'void'
    if type_str == 'bool':  return 'bool'
    if type_str == 'i8':    return 'char'
    if type_str == 'u8':    return 'uchar'
    if type_str == 'i16':   return 'short'
    if type_str == 'u16':   return 'ushort'
    if type_str == 'i32':   return 'int'
    if type_str == 'u32':   return 'uint'
    if type_str == 'i64':   return 'longlong'
    if type_str == 'u64':   return 'ulonglong'
    if type_str == 'f32':   return 'float'
    if type_str == 'f64':   return 'double'
    if type_str == 'ptr':   return 'void *'
    if type_str.startswith('ptr:struct:'):
        name = type_str[11:]
        if '<' in name:
            return 'void *'
        return name.split('::')[-1] + ' *'
    if type_str.startswith('ptr:enum:'):
        return type_str[9:].split('::')[-1] + ' *'
    if type_str.startswith('struct:'):
        name = type_str[7:]
        if '<' in name:
            return 'void *'
        return name.split('::')[-1]
    if type_str.startswith('enum:'):
        return type_str[5:].split('::')[-1]
    return 'void *'


def _import_vtable_names():
    # Walk each class vtable: VTABLE_ClassName label -> read function pointers -> rename functions.
    # VTABLE_ labels were just created by _import_symbols(), so they exist now.
    monitor.setMessage('Naming virtual functions from vtable addresses...')
    fm = currentProgram.getFunctionManager()
    sym_table = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    ptr_size = currentProgram.getDefaultPointerSize()
    named_vfuncs = 0
    vtbl_not_found = 0
    vtbl_found = 0
    read_fail = 0
    no_func = 0
    already_named = 0
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots = vt
        class_short = class_full_name.split('::')[-1]
        vtbl_label = 'VTABLE_' + class_short
        vtbl_syms = list(sym_table.getSymbols(vtbl_label))
        if not vtbl_syms:
            vtbl_not_found += 1
            continue
        vtbl_found += 1
        vtbl_addr = vtbl_syms[0].getAddress()
        for slot_off, slot_name, slot_ret, slot_params in slots:
            if slot_name.startswith('fn_'):
                continue
            try:
                ptr_addr = vtbl_addr.add(slot_off)
                if ptr_size == 8:
                    raw = memory.getLong(ptr_addr)
                    if raw < 0:
                        raw = raw + (1 << 64)
                else:
                    raw = memory.getInt(ptr_addr) & 0xFFFFFFFF
                func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(raw)
                func = fm.getFunctionAt(func_addr)
                if not func:
                    DisassembleCommand(func_addr, None, True).applyTo(currentProgram)
                    func = fm.getFunctionAt(func_addr)
                if not func:
                    no_func += 1
                    continue
                curr = func.getName()
                if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                    already_named += 1
                    continue
                func.setName(class_short + '::' + slot_name, SourceType.USER_DEFINED)
                cu = currentProgram.getListing().getCodeUnitAt(func_addr)
                if cu:
                    cu.setComment(0, (
                        'VTABLE ' + class_full_name + '::' + slot_name + '\\n' +
                        'Slot offset: +0x{:X}\\n'.format(slot_off) +
                        'Source: CommonLibSSE vtable walk'
                    ))
                if slot_ret is not None and slot_params is not None:
                    try:
                        param_parts = [class_short + ' * this']
                        for pname, ptype in slot_params:
                            param_parts.append(_type_to_c(ptype) + ' ' + pname)
                        proto = (_type_to_c(slot_ret) + ' ' + slot_name +
                                 '(' + ', '.join(param_parts) + ')')
                        proto = _patch_templates(proto)
                        for _vt_proto in (proto, sanitize_unknown_types(proto)):
                            try:
                                func_def = CParserUtils.parseSignature(None, currentProgram, _vt_proto, True)
                                if func_def:
                                    ApplyFunctionSignatureCmd(func_addr, func_def,
                                        SourceType.USER_DEFINED, True, False).applyTo(currentProgram)
                                    break
                            except Exception:
                                pass
                    except Exception:
                        pass
                named_vfuncs += 1
            except Exception:
                read_fail += 1
    print('Named {} virtual functions from vtable addresses'.format(named_vfuncs))
    print('  vtbl_found={} vtbl_not_found={} read_fail={} no_func={} already_named={}'.format(
        vtbl_found, vtbl_not_found, read_fail, no_func, already_named))

    # --- Second pass: walk VTABLE_ labels that have no struct definition ---
    # These are VTABLE_ symbols created by _import_symbols() but not in VTABLES.
    # Read sequential function pointers and name them ClassName::Func1, Func2, etc.
    handled_labels = set()
    for vt in VTABLES:
        class_short = vt[1].split('::')[-1]
        handled_labels.add('VTABLE_' + class_short)
    text_block = memory.getBlock('.text')
    unnamed_named = 0
    unnamed_walked = 0
    if text_block:
        text_start = text_block.getStart().getOffset()
        text_end = text_start + text_block.getSize()
        for sym in sym_table.getAllSymbols(False):
            sname = sym.getName()
            if not sname.startswith('VTABLE_') or sname in handled_labels:
                continue
            class_short = sname[7:]  # strip 'VTABLE_'
            vtbl_addr = sym.getAddress()
            unnamed_walked += 1
            slot_idx = 0
            while True:
                slot_idx += 1
                try:
                    ptr_addr = vtbl_addr.add((slot_idx - 1) * ptr_size)
                    if ptr_size == 8:
                        raw = memory.getLong(ptr_addr)
                        if raw < 0:
                            raw = raw + (1 << 64)
                    else:
                        raw = memory.getInt(ptr_addr) & 0xFFFFFFFF
                    # Stop if pointer is outside .text section
                    if raw < text_start or raw >= text_end:
                        break
                    func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(raw)
                    func = fm.getFunctionAt(func_addr)
                    if not func:
                        DisassembleCommand(func_addr, None, True).applyTo(currentProgram)
                        func = fm.getFunctionAt(func_addr)
                    if not func:
                        break
                    curr = func.getName()
                    if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                        continue
                    func_name = 'Func{}'.format(slot_idx)
                    func.setName(class_short + '::' + func_name, SourceType.USER_DEFINED)
                    cu = currentProgram.getListing().getCodeUnitAt(func_addr)
                    if cu:
                        cu.setComment(0, (
                            'VTABLE ' + class_short + '::' + func_name + '\\n' +
                            'Slot offset: +0x{:X}\\n'.format((slot_idx - 1) * ptr_size) +
                            'Source: CommonLibSSE vtable walk (unnamed)'
                        ))
                    unnamed_named += 1
                except Exception:
                    break
    print('Unnamed vtable walk: {} vtables walked, {} functions named'.format(
        unnamed_walked, unnamed_named))


def _import_fallback_symbols():
    """Apply AE rename / SE PDB fallback symbols only to addresses not yet named.

    Runs after _import_vtable_names() so any function already named by the
    vtable walk or the main symbol pass is left untouched.
    """
    version_key = 's' if VERSION == 'se' else 'a'
    base_addr = currentProgram.getImageBase()
    fm = currentProgram.getFunctionManager()
    symbol_table = currentProgram.getSymbolTable()

    print('Applying ' + str(len(FALLBACK_SYMBOLS)) + ' fallback symbols...')
    count_applied = count_skipped = 0

    for s in FALLBACK_SYMBOLS:
        off = s.get(version_key)
        if not off:
            continue
        addr = base_addr.add(int(off))
        sname = s['n']

        try:
            f = fm.getFunctionAt(addr)
            if not f:
                DisassembleCommand(addr, None, True).applyTo(currentProgram)
                f = fm.getFunctionAt(addr)

            if f:
                curr = f.getName()
                if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                    count_skipped += 1
                    continue
                f.setName(sname, SourceType.USER_DEFINED)
            else:
                # No function at address — fall back to a plain label
                symbol_table.createLabel(addr, sname, SourceType.USER_DEFINED)

            src = s.get('src', '')
            if src == 'skyrimae.rename':
                comment = 'Source: AE rename database (fallback)'
            elif src == 'SkyrimSE.pdb':
                comment = 'Source: SkyrimSE.pdb public symbols (fallback)'
            else:
                comment = ''
            if comment:
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu:
                    cu.setComment(0, comment)
            count_applied += 1
        except:
            pass

    print('Fallback: applied ' + str(count_applied) + ', skipped (already named): ' + str(count_skipped))


run()
'''


def generate_script(enums, structs, vtable_structs, output_path, version, symbols_json, fallback_symbols_json='[]', template_source=''):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    lines = [GHIDRA_MERGED_HEADER]

    # VERSION constant — hard-coded per file
    lines.append('VERSION = {}'.format(repr(version)))
    lines.append('')

    # Emit VTABLES
    lines.append('VTABLES = [')
    for vt in sorted(vtable_structs.values(), key=lambda v: v['name']):
        lines.append('    ({}, {}, {}, {}, {}),'.format(
            repr(vt['name']), repr(vt['class_full_name']), repr(vt['size']),
            repr(vt['category']), repr(vt['slots'])))
    lines.append(']')
    lines.append('')

    # Emit ENUMS.  Ghidra's EnumDataType.add(name, long value) takes a Java
    # `long` (signed 64-bit); values >= 2^63 from unsigned C++ enums overflow.
    # Convert to the equivalent signed representation so the bit pattern is
    # preserved.
    def _wrap_signed(values):
        out = []
        for n, v in values:
            if v >= (1 << 63):
                v -= (1 << 64)
            out.append((n, v))
        return out

    lines.append('ENUMS = [')
    for en in sorted(enums.values(), key=lambda e: e['full_name']):
        name = en['name']
        size = en['size']
        category = en['category']
        values = _wrap_signed(en['values'])
        val_str = repr(values)
        lines.append('    ({}, {}, {}, {}),'.format(
            repr(name), repr(size), repr(category), val_str))
    lines.append(']')
    lines.append('')

    # Emit STRUCTS
    lines.append('STRUCTS = [')
    for st in sorted(structs.values(), key=lambda s: s['full_name']):
        name = st['name']
        size = st['size']
        category = st['category']
        has_vtable = st['has_vtable']
        bases = st['bases']

        fields = sorted(st['fields'], key=lambda f: f['offset'])
        seen_names = {}
        deduped_fields = []
        for f in fields:
            n = f['name']
            if n in seen_names:
                seen_names[n] += 1
                n = '{}_{}'.format(n, seen_names[n])
            else:
                seen_names[n] = 0
            deduped_fields.append((n, f['type'], f['offset'], f['size']))

        lines.append('    ({}, {}, {}, {}, {}, {}),'.format(
            repr(name), repr(size), repr(category),
            repr(deduped_fields), repr(bases), repr(has_vtable)))
    lines.append(']')
    lines.append('')

    # Build class::method → signature lookup from ccls-re method data
    import json as _json_mod
    _method_sig_lookup = {}  # 'ClassName::Method' -> 'ret_type(param_type pname, ...)'
    for st in structs.values():
        class_short = st['name']
        for mname, (ret, params) in st.get('method_sigs', {}).items():
            if ret and params is not None:
                param_str = ', '.join('{} {}'.format(pt, pn) if pn else pt for pn, pt in params)
                _method_sig_lookup[class_short + '::' + mname] = '{}({})'.format(ret, param_str)

    # Inject signatures from ccls-re into symbol entries
    _syms = _json_mod.loads(symbols_json)
    _sig_count = 0
    for s in _syms:
        if s['t'] == 'func' and not s.get('sig') and '::' in s.get('n', ''):
            sig = _method_sig_lookup.get(s['n'])
            if sig:
                s['sig'] = sig
                _sig_count += 1
    if _sig_count:
        symbols_json = _json_mod.dumps(_syms, separators=(',', ':'))

    # Emit SYMBOLS (version-agnostic — version_key selected at runtime by VERSION)
    lines.append('SYMBOLS = ' + symbols_json)
    lines.append('')

    # Upgrade fallback symbols that match vtable slots: change source to CommonLibSSE
    # and add signature so they display correctly even if vtable walk fails at runtime.
    _vtable_sigs = {}  # 'ClassName::MethodName' -> (ret, params)
    for vt in vtable_structs.values():
        class_short = vt['class_full_name'].split('::')[-1]
        for _off, slot_name, slot_ret, slot_params in vt['slots']:
            if not slot_name.startswith('fn_') and not slot_name.startswith('__'):
                _vtable_sigs[class_short + '::' + slot_name] = (slot_ret, slot_params)
    if fallback_symbols_json != '[]' and _vtable_sigs:
        import json as _json_mod
        _fb = _json_mod.loads(fallback_symbols_json)
        _upgraded = 0
        for s in _fb:
            sig_info = _vtable_sigs.get(s.get('n'))
            if sig_info:
                s['src'] = 'CommonLibSSE'
                _upgraded += 1
        if _upgraded:
            print('  Upgraded {} vtable-known fallback symbols to CommonLibSSE source'.format(_upgraded))
            fallback_symbols_json = _json_mod.dumps(_fb, separators=(',', ':'))

    # Fallback symbols (AE rename / SE PDB new entries) applied after vtable walk
    lines.append('FALLBACK_SYMBOLS = ' + fallback_symbols_json)
    lines.append('')

    # Embed template type map and patch function (populated by template_types.py)
    if template_source:
        lines.append(template_source)
    else:
        lines.append('TEMPLATE_TYPE_MAP = {}')
        lines.append('TEMPLATE_C_ALIAS_MAP = {}')
        lines.append('')
        lines.append('def _patch_templates(proto):')
        lines.append('    for _tmpl, _alias in sorted(TEMPLATE_C_ALIAS_MAP.items(), key=lambda x: -len(x[0])):')
        lines.append('        proto = proto.replace(_tmpl, _alias)')
        lines.append('    return proto')
    lines.append('')

    lines.append(GHIDRA_MERGED_FOOTER)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return len(enums), len(structs)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------





def _build_vtable_structs(structs):
    """
    Build vtable type descriptors for each virtual class by collecting intro
    virtual methods (LF_ONEMETHOD mprop 4/5) from the class and its primary
    base chain.  Returns a dict: full_name → vtable descriptor.
    """
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    memo = {}     # full_name → {vbaseoff: method_name}
    sig_memo = {} # full_name → {method_name: (ret_type_str, [(pname, ptype_str)])}

    def _primary_base_st(st):
        """Return the struct dict for the primary base (offset-0 base), or None."""
        for base_ref in st.get('bases', []):
            return by_name.get(base_ref) or by_name.get(base_ref.split('::')[-1])
        return None

    def get_slots(full_name, depth=0):
        if depth > 20:
            return {}
        if full_name in memo:
            return memo[full_name]
        st = by_name.get(full_name)
        if not st:
            memo[full_name] = {}
            return {}
        memo[full_name] = {}  # cycle guard

        slots = {}

        # Inherit from primary base (first base placed at offset 0)
        bst = _primary_base_st(st)
        if bst:
            slots.update(get_slots(bst['full_name'], depth + 1))

        # Own intro virtual methods override inherited ones at same offset
        for mname, vbaseoff in st.get('vfuncs', []):
            if vbaseoff >= 0 and mname:
                slots[vbaseoff] = mname

        memo[full_name] = slots
        return slots

    def get_sigs(full_name, depth=0):
        """Collect inherited + own vmethods signatures: {name: (ret, params)}."""
        if depth > 20:
            return {}
        if full_name in sig_memo:
            return sig_memo[full_name]
        st = by_name.get(full_name)
        if not st:
            sig_memo[full_name] = {}
            return {}
        sig_memo[full_name] = {}  # cycle guard

        sigs = {}
        bst = _primary_base_st(st)
        if bst:
            sigs.update(get_sigs(bst['full_name'], depth + 1))
        sigs.update(st.get('vmethods', {}))

        sig_memo[full_name] = sigs
        return sigs

    vtable_structs = {}
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        named = get_slots(st['full_name'])
        if not named:
            continue
        max_off = max(named.keys())
        vtbl_size = max_off + 8
        # Fill every 8-byte slot — named slots keep their PDB names,
        # gaps get generic names so Ghidra won't use array indexing.
        # Cap at 0x4000 bytes (2048 slots) to guard against bogus vbaseoff values.
        all_slots = dict(named)
        if vtbl_size <= 0x4000:
            for off in range(0, vtbl_size, 8):
                if off not in all_slots:
                    all_slots[off] = 'fn_{:03X}'.format(off)
        # Build sorted slots as 4-tuples: (offset, name, ret_type, params)
        # ret_type and params come from ccls-re method data; None if unknown.
        sigs = get_sigs(st['full_name'])
        sorted_slots = []
        for off, name in sorted(all_slots.items()):
            sig = sigs.get(name)
            sorted_slots.append((off, name, sig[0] if sig else None, sig[1] if sig else None))
        vname = st['name'] + '_vtbl'
        vtable_structs[st['full_name']] = {
            'name': vname,
            'class_full_name': st['full_name'],
            'category': st['category'],
            'slots': sorted_slots,
            'size': vtbl_size,
        }

    print('Built {} vtable structs'.format(len(vtable_structs)))
    return vtable_structs


def _inject_vtable_fields(structs, vtable_structs):
    """
    For every virtual struct that has no field at offset 0, prepend a __vftable
    pointer field with type 'vtblptr:Name_vtbl' (or plain 'ptr' if no vtable data).
    Must run BEFORE _flatten_structs so vtable pointers propagate through hierarchy.
    """
    count = 0
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        if st['size'] < 8:
            continue
        if any(f['offset'] == 0 for f in st['fields']):
            continue
        vt = vtable_structs.get(st['full_name'])
        vtbl_type = ('vtblptr:' + vt['name']) if vt else 'ptr'
        st['fields'].insert(0, {
            'name': '__vftable',
            'type': vtbl_type,
            'offset': 0,
            'size': 8,
        })
        count += 1
    print('Injected vtable pointer fields into {} structs'.format(count))


_KNOWN_TEMPLATE_LAYOUTS = {
    'NiPointer': (8, [{'name': '_ptr', 'type': 'ptr', 'offset': 0, 'size': 8}]),
    'BSTSmartPointer': (8, [{'name': '_ptr', 'type': 'ptr', 'offset': 0, 'size': 8}]),
    'hkRefPtr': (8, [{'name': '_ptr', 'type': 'ptr', 'offset': 0, 'size': 8}]),
    'GPtr': (8, [{'name': '_ptr', 'type': 'ptr', 'offset': 0, 'size': 8}]),
    'BSTArray': (0x18, [
        {'name': '_data', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_capacity', 'type': 'u32', 'offset': 8, 'size': 4},
        {'name': '_size', 'type': 'u32', 'offset': 0x10, 'size': 4},
    ]),
    'BSScrapArray': (0x20, [
        {'name': '_allocator', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_data', 'type': 'ptr', 'offset': 8, 'size': 8},
        {'name': '_capacity', 'type': 'u32', 'offset': 0x10, 'size': 4},
        {'name': '_size', 'type': 'u32', 'offset': 0x18, 'size': 4},
    ]),
    'hkArray': (0x10, [
        {'name': '_data', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_size', 'type': 'i32', 'offset': 8, 'size': 4},
        {'name': '_capacityAndFlags', 'type': 'i32', 'offset': 0xC, 'size': 4},
    ]),
    'BSTHashMap': (0x30, [
        {'name': '_pad00', 'type': 'u64', 'offset': 0, 'size': 8},
        {'name': '_pad08', 'type': 'u32', 'offset': 8, 'size': 4},
        {'name': '_capacity', 'type': 'u32', 'offset': 0xC, 'size': 4},
        {'name': '_free', 'type': 'u32', 'offset': 0x10, 'size': 4},
        {'name': '_good', 'type': 'u32', 'offset': 0x14, 'size': 4},
        {'name': '_sentinel', 'type': 'ptr', 'offset': 0x18, 'size': 8},
        {'name': '_allocPad', 'type': 'u64', 'offset': 0x20, 'size': 8},
        {'name': '_entries', 'type': 'ptr', 'offset': 0x28, 'size': 8},
    ]),
    'BSTScrapHashMap': (0x30, [
        {'name': '_pad00', 'type': 'u64', 'offset': 0, 'size': 8},
        {'name': '_pad08', 'type': 'u32', 'offset': 8, 'size': 4},
        {'name': '_capacity', 'type': 'u32', 'offset': 0xC, 'size': 4},
        {'name': '_free', 'type': 'u32', 'offset': 0x10, 'size': 4},
        {'name': '_good', 'type': 'u32', 'offset': 0x14, 'size': 4},
        {'name': '_sentinel', 'type': 'ptr', 'offset': 0x18, 'size': 8},
        {'name': '_allocator', 'type': 'ptr', 'offset': 0x20, 'size': 8},
        {'name': '_entries', 'type': 'ptr', 'offset': 0x28, 'size': 8},
    ]),
    'BSTSet': (0x30, [
        {'name': '_pad00', 'type': 'u64', 'offset': 0, 'size': 8},
        {'name': '_pad08', 'type': 'u32', 'offset': 8, 'size': 4},
        {'name': '_capacity', 'type': 'u32', 'offset': 0xC, 'size': 4},
        {'name': '_free', 'type': 'u32', 'offset': 0x10, 'size': 4},
        {'name': '_good', 'type': 'u32', 'offset': 0x14, 'size': 4},
        {'name': '_sentinel', 'type': 'ptr', 'offset': 0x18, 'size': 8},
        {'name': '_allocPad', 'type': 'u64', 'offset': 0x20, 'size': 8},
        {'name': '_entries', 'type': 'ptr', 'offset': 0x28, 'size': 8},
    ]),
    'BSSimpleList': (0x10, [
        {'name': '_item', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_next', 'type': 'ptr', 'offset': 8, 'size': 8},
    ]),
    'BSTEventSource': (0x58, [
        {'name': '_sinks_data', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_sinks_capacity', 'type': 'u32', 'offset': 8, 'size': 4},
        {'name': '_sinks_size', 'type': 'u32', 'offset': 0x10, 'size': 4},
        {'name': '_pendReg_data', 'type': 'ptr', 'offset': 0x18, 'size': 8},
        {'name': '_pendReg_capacity', 'type': 'u32', 'offset': 0x20, 'size': 4},
        {'name': '_pendReg_size', 'type': 'u32', 'offset': 0x28, 'size': 4},
        {'name': '_pendUnreg_data', 'type': 'ptr', 'offset': 0x30, 'size': 8},
        {'name': '_pendUnreg_capacity', 'type': 'u32', 'offset': 0x38, 'size': 4},
        {'name': '_pendUnreg_size', 'type': 'u32', 'offset': 0x40, 'size': 4},
        {'name': '_lock', 'type': 'u64', 'offset': 0x48, 'size': 8},
        {'name': '_notifying', 'type': 'u8', 'offset': 0x50, 'size': 1},
    ]),
    'NiTMap': (0x28, [
        {'name': '__vftable', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_numBuckets', 'type': 'u32', 'offset': 8, 'size': 4},
        {'name': '_hashTable', 'type': 'ptr', 'offset': 0x10, 'size': 8},
        {'name': '_count', 'type': 'u32', 'offset': 0x18, 'size': 4},
    ]),
    'NiTPrimitiveArray': (0x18, [
        {'name': '__vftable', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_data', 'type': 'ptr', 'offset': 8, 'size': 8},
        {'name': '_capacity', 'type': 'u16', 'offset': 0x10, 'size': 2},
        {'name': '_freeIdx', 'type': 'u16', 'offset': 0x12, 'size': 2},
        {'name': '_size', 'type': 'u16', 'offset': 0x14, 'size': 2},
        {'name': '_growthSize', 'type': 'u16', 'offset': 0x16, 'size': 2},
    ]),
    'SimpleArray': (0x10, [
        {'name': '_data', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_size', 'type': 'u32', 'offset': 8, 'size': 4},
    ]),
    'GArray': (0x18, [
        {'name': '__vftable', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_data', 'type': 'ptr', 'offset': 8, 'size': 8},
        {'name': '_size', 'type': 'u32', 'offset': 0x10, 'size': 4},
    ]),
    'hkSmallArray': (0x10, [
        {'name': '_data', 'type': 'ptr', 'offset': 0, 'size': 8},
        {'name': '_size', 'type': 'u16', 'offset': 8, 'size': 2},
        {'name': '_capacityAndFlags', 'type': 'u16', 'offset': 0xA, 'size': 2},
    ]),
}


def _apply_known_template_layouts(structs, enums):
    """Patch template base types and instantiation aliases with known layouts.

    Template instantiation aliases have sanitized names like NiPointer_BSTriShape,
    BSTArray_TESForm_ptr, RE_BSTHashMap_RE_FormID_RE_TESForm_ptr, etc.
    We extract the base template name and apply the known fixed-size layout.
    """
    patched = 0
    for sname, st in structs.items():
        if st['size'] > 1 and st['fields']:
            continue
        key = sname
        for prefix in ('RE::', 'RE_', 'REX::', 'REX_'):
            if key.startswith(prefix):
                key = key[len(prefix):]
                break
        if '<' in key:
            base = key.split('<')[0]
        elif '_' in key:
            base = key.split('_')[0]
        else:
            base = key
        if base == 'EnumSet' or sname in ('REX::EnumSet', 'EnumSet'):
            st['size'] = 4
            st['fields'] = [{'name': '_impl', 'type': 'u32', 'offset': 0, 'size': 4}]
            patched += 1
            continue
        if base in _KNOWN_TEMPLATE_LAYOUTS:
            size, fields = _KNOWN_TEMPLATE_LAYOUTS[base]
            st['size'] = size
            st['fields'] = [dict(f) for f in fields]
            patched += 1

    if patched:
        print('Applied known template layouts to {} struct(s)'.format(patched))


def _flatten_structs(structs):
    """
    In-place: for every struct, expand base class fields into the derived struct
    so the final field list covers the entire layout at absolute byte offsets.

    Assumes first base starts at offset 0 (primary base chain).
    """
    # Build name → struct entry lookup
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    memo = {}   # full_name → flattened fields list (cached)

    def get_flat(full_name, depth=0):
        if depth > 20:
            return []
        if full_name in memo:
            return memo[full_name]

        st = by_name.get(full_name)
        if not st:
            memo[full_name] = []
            return []

        # Prevent cycles
        memo[full_name] = []

        combined = {}  # offset → field dict  (own fields take priority)

        # Assume first base at offset 0 (primary base chain)
        for base_ref in st.get('bases', []):
            base_st = by_name.get(base_ref) or by_name.get(base_ref.split('::')[-1])
            if not base_st or base_st['size'] <= 1:
                continue
            for f in get_flat(base_st['full_name'], depth + 1):
                if f['offset'] not in combined:
                    combined[f['offset']] = f
            break  # only first base without offset info

        # --- Own fields (override base at same offset) ---
        for f in st['fields']:
            combined[f['offset']] = f

        flat = sorted(combined.values(), key=lambda f: f['offset'])
        memo[full_name] = flat
        return flat

    for st in structs.values():
        st['fields'] = get_flat(st['full_name'])

    # Count how many structs gained fields from flattening
    gained = sum(1 for st in structs.values() if len(st['fields']) > 0)
    print('Flattening: {} structs have field data after inheritance expansion'.format(gained))


def run_version(version, symbols_json, fallback_symbols_json='[]', ccls_binary=None):
    cfg = VERSIONS[version]
    output_path = cfg['output']
    parse_args = PARSE_ARGS_BASE + cfg['defines']

    print('\n=== {} ==='.format(version.upper()))

    if not os.path.isfile(SKYRIM_H):
        print('ERROR: Could not find Skyrim.h at', SKYRIM_H)
        sys.exit(1)

    print('Collecting types via ccls-re ($ccls/dumpTypes)...')
    import ccle_client as _cac
    enums, structs = _cac.collect_types(SKYRIM_H, parse_args, RE_INCLUDE, verbose=True, ccls_binary=ccls_binary)
    print('Found {} enums, {} structs/classes'.format(len(enums), len(structs)))

    vtable_structs = _build_vtable_structs(structs)
    _inject_vtable_fields(structs, vtable_structs)
    _flatten_structs(structs)

    category = '/CommonLibSSE/RE'

    # Scan for C++ template instantiation types and emit sanitized aliases
    try:
        from template_types import process_template_types as _process_templates
        _tmpl = _process_templates(structs)
        template_source = _tmpl.combined_source()

        for _orig, _display in _tmpl.template_map.items():
            if _display not in structs and _display not in enums:
                structs[_display] = {'name': _display, 'full_name': _display, 'size': 0,
                                     'category': category, 'fields': [], 'bases': [],
                                     'has_vtable': False}
        if _tmpl.template_map:
            print('Discovered {} template instantiation aliases'.format(len(_tmpl.template_map)))

    except ImportError:
        template_source = ''

    _apply_known_template_layouts(structs, enums)

    if hasattr(_cac, 'resolve_deferred_typedef_aliases'):
        _n_extra = _cac.resolve_deferred_typedef_aliases(enums, structs, verbose=True)
        if _n_extra:
            print('Resolved {} deferred typedef alias(es) post-template'.format(_n_extra))

    print('Generating Ghidra script...')
    n_enums, n_structs = generate_script(enums, structs, vtable_structs, output_path, version, symbols_json, fallback_symbols_json, template_source)
    print('Output: {} ({} enums, {} structs)'.format(output_path, n_enums, n_structs))


def main():
    import json as _json
    import argparse

    ap = argparse.ArgumentParser(description='Parse CommonLibSSE and generate Ghidra import script')
    ap.add_argument('--ccls-re', metavar='PATH',
                    help='Path to ccls-re binary (default: search PATH)')
    args = ap.parse_args()

    # Load address databases (binary data, not source scanning)
    addr_lib = AddressLibrary()
    addr_lib.load_all(os.path.join(SCRIPT_DIR, 'addresslibrary'))
    print('SE entries: {}, AE entries: {}'.format(len(addr_lib.se_db), len(addr_lib.ae_db)))

    print('\n=== Collecting symbols via regex relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, offset_id_map, static_methods, se_offset_map, ae_offset_map = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    src_dir = os.path.join(SCRIPT_DIR, 'extern', 'CommonLibSSE', 'src')
    if os.path.isdir(src_dir):
        src_func_syms = _rp.collect_src_relocations(
            src_dir, addr_lib, offset_id_map,
            se_offset_map=se_offset_map, ae_offset_map=ae_offset_map,
            verbose=True)
    else:
        src_func_syms = []
        print('  src/ dir not found, skipping')

    label_by_name = {}
    for lbl in label_syms:
        label_by_name.setdefault(lbl['name'], {'name': lbl['name'], 'se_off': None, 'ae_off': None})
        entry = label_by_name[lbl['name']]
        if lbl.get('se_off'): entry['se_off'] = lbl['se_off']
        if lbl.get('ae_off'): entry['ae_off'] = lbl['ae_off']

    merged_funcs = list(func_syms)
    seen_se = set(fs['se_off'] for fs in merged_funcs if fs.get('se_off'))
    seen_ae = set(fs['ae_off'] for fs in merged_funcs if fs.get('ae_off'))

    for fs in src_func_syms:
        if not fs.get('is_static') and fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    for fs in src_func_syms:
        se_off = fs.get('se_off')
        ae_off = fs.get('ae_off')
        if se_off and se_off in seen_se:
            continue
        if ae_off and ae_off in seen_ae:
            continue
        if se_off: seen_se.add(se_off)
        if ae_off: seen_ae.add(ae_off)
        merged_funcs.append(fs)

    # Build SYMBOLS array
    symbols = []
    sym_seen_se = set()
    sym_seen_ae = set()

    # Function symbols
    for fs in merged_funcs:
        full_name = '{}::{}'.format(fs['class_'], fs['name']) if fs['class_'] else fs['name']
        sig = ''
        if fs.get('ret'):
            sig = '{}({})'.format(fs['ret'], fs.get('params', ''))
            if fs.get('is_static'):
                sig = 'static ' + sig
        sym = {'n': full_name, 't': 'func', 'sig': sig, 'src': 'CommonLibSSE'}
        if fs['se_off']: sym['s'] = fs['se_off']; sym_seen_se.add(fs['se_off'])
        if fs['ae_off']: sym['a'] = fs['ae_off']; sym_seen_ae.add(fs['ae_off'])
        symbols.append(sym)

    # RTTI/VTABLE labels
    for lbl in label_by_name.values():
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibSSE'}
        if lbl['se_off']: sym['s'] = lbl['se_off']; sym_seen_se.add(lbl['se_off'])
        if lbl['ae_off']: sym['a'] = lbl['ae_off']; sym_seen_ae.add(lbl['ae_off'])
        symbols.append(sym)

    # Index symbols by name for merge lookups.  Both fallback passes below use
    # this to merge a missing version offset into an existing entry (e.g. merge
    # a SE offset from the PDB into a symbol already present as AE-only from the
    # rename DB) rather than creating a duplicate entry with the same name.
    name_to_sym = {s['n']: s for s in symbols}

    # AE rename database fallback
    rename_db = os.path.join(SCRIPT_DIR, 'extern', 'AddressLibraryDatabase', 'skyrimae.rename')
    ae_rename = load_ae_rename_db(rename_db, addr_lib.ae_db)
    rename_added = rename_merged = 0
    for ae_off, name in ae_rename.items():
        if ae_off in sym_seen_ae:
            continue  # address already claimed by a higher-priority source
        if name in name_to_sym:
            # Symbol known from another source but missing its AE offset — merge it in.
            existing = name_to_sym[name]
            if not existing.get('a'):
                existing['a'] = ae_off
                sym_seen_ae.add(ae_off)
                rename_merged += 1
            continue
        sym_seen_ae.add(ae_off)
        sym = {'n': name, 't': 'func', 'sig': '', 'a': ae_off, 'src': 'skyrimae.rename'}
        symbols.append(sym)
        name_to_sym[name] = sym
        rename_added += 1
    print('Added {} new symbols from AE rename, merged AE offset into {} existing'.format(
        rename_added, rename_merged))

    # SE PDB public symbols fallback: true last resort — only adds symbols whose
    # name and address are not already represented by any higher-priority source.
    # When the name is already known (e.g. from the AE rename DB) but lacks an SE
    # address, the SE offset is merged in rather than creating a duplicate entry.
    se_pdb_path = os.path.join(SCRIPT_DIR, 'extras', 'SkyrimSE.pdb')
    se_pdb_names = load_se_pdb_names(se_pdb_path)
    pdb_added = pdb_merged = 0
    for se_off, name in se_pdb_names.items():
        if se_off in sym_seen_se:
            continue  # address already claimed by a higher-priority source
        if name in name_to_sym:
            # Symbol known from another source but missing its SE offset — merge it in.
            existing = name_to_sym[name]
            if not existing.get('s'):
                existing['s'] = se_off
                sym_seen_se.add(se_off)
                pdb_merged += 1
            continue
        sym_seen_se.add(se_off)
        sym = {'n': name, 't': 'func', 'sig': '', 's': se_off, 'src': 'SkyrimSE.pdb'}
        symbols.append(sym)
        name_to_sym[name] = sym
        pdb_added += 1
    print('Added {} new symbols from SE PDB, merged SE offset into {} existing'.format(
        pdb_added, pdb_merged))

    # Normalize __ → :: in all names
    for s in symbols:
        if '__' in s['n']:
            s['n'] = re.sub(r':{3,}', '::', s['n'].replace('__', '::'))

    funcs = [s for s in symbols if s['t'] == 'func']
    with_sig = len([s for s in funcs if s.get('sig')])
    labels_count = len([s for s in symbols if s['t'] == 'label'])
    print('\nGenerated {} symbols:'.format(len(symbols)))
    print('  Functions: {} ({} with signatures)'.format(len(funcs), with_sig))
    print('  Labels: {}'.format(labels_count))

    _FALLBACK_SRCS = {'skyrimae.rename', 'SkyrimSE.pdb'}
    primary_symbols  = [s for s in symbols if s.get('src') not in _FALLBACK_SRCS]
    fallback_symbols = [s for s in symbols if s.get('src') in _FALLBACK_SRCS]
    print('  Primary: {}, Fallback (AE rename / SE PDB new): {}'.format(
        len(primary_symbols), len(fallback_symbols)))

    symbols_json = _json.dumps(primary_symbols, separators=(',', ':'))

    # Build per-version fallback lists:
    # SE gets only SkyrimSE.pdb entries (skip skyrimae.rename-sourced symbols)
    # AE gets only skyrimae.rename entries (skip SkyrimSE.pdb-sourced symbols)
    se_fallback = [s for s in fallback_symbols if s.get('src') == 'SkyrimSE.pdb']
    ae_fallback = [s for s in fallback_symbols if s.get('src') == 'skyrimae.rename']
    print('  SE fallback: {} (PDB), AE fallback: {} (rename DB)'.format(
        len(se_fallback), len(ae_fallback)))

    se_fallback_json = _json.dumps(se_fallback, separators=(',', ':'))
    ae_fallback_json = _json.dumps(ae_fallback, separators=(',', ':'))

    for version in ('se', 'ae'):
        fb_json = se_fallback_json if version == 'se' else ae_fallback_json
        run_version(version, symbols_json, fb_json, ccls_binary=args.ccls_re)


if __name__ == '__main__':
    main()
