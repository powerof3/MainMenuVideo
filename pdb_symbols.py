"""PDB public symbol extraction and address library loading.

Provides:
  AddressLibrary  - loads Skyrim-style address library binary databases
  load_pdb_names  - extracts public function symbols from a PDB file via pdbparse
  undecorate      - demangles MSVC-mangled symbol names via dbghelp
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
from typing import Dict


# ---------------------------------------------------------------------------
# MSVC symbol demangling
# ---------------------------------------------------------------------------

def undecorate(name: str) -> str:
    """Demangle an MSVC-mangled symbol name using dbghelp.UnDecorateSymbolName."""
    try:
        buf = ctypes.create_string_buffer(512)
        if ctypes.windll.dbghelp.UnDecorateSymbolName(name.encode(), buf, 512, 0x1000):
            return buf.value.decode('ascii', errors='replace')
    except Exception:
        pass
    return name


# ---------------------------------------------------------------------------
# PDB public symbols
# ---------------------------------------------------------------------------

def load_pdb_names(file_path: str) -> Dict[int, str]:
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
            name = undecorate(name)
        if re.match(r'^FUN_[0-9A-Fa-f]+$', name):
            continue
        name = re.sub(r'_14[0-9A-Fa-f]{6,8}$', '', name)
        name = re.sub(r':{3,}', '::', name.replace('__', '::'))
        result[sections[rec.segment - 1] + rec.offset] = name

    return result


# ---------------------------------------------------------------------------
# Address library (Skyrim SE/AE binary database: relocation ID -> RVA)
# ---------------------------------------------------------------------------

class AddressLibrary:
    """Loads address-library binary databases mapping RELOCATION_IDs to RVAs."""

    def __init__(self):
        self.se_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
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

    def load_all(self, base_path: str) -> None:
        self.se_db = self.load_bin(os.path.join(base_path, 'version-1-5-97-0.bin'))
        self.ae_db = self.load_bin(os.path.join(base_path, 'versionlib-1-6-1170-0.bin'))
