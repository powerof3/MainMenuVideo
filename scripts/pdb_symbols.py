"""PDB public symbol extraction.

Provides:
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
