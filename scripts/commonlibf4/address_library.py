"""Fallout 4 address library loader (libxse/commonlibf4 format).

Binary format (from CommonLibF4 IDDatabase::load()):
  uint64  count
  count x (uint64 id, uint64 offset) pairs, sorted by id

AE (1.11.191) is the primary database used by all CommonLibF4 IDs.
NG (1.10.984) is loaded only to rebase Fallout4.pdb symbols onto AE:
  PDB rva -> NG id -> AE offset.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Optional


class F4AddressLibrary:
    """Loads AE (1.11.191) and NG (1.10.984) Fallout 4 address library .bin files."""

    def __init__(self):
        self.ae_db: Dict[int, int] = {}
        self.ng_db: Dict[int, int] = {}
        self._inv_ng: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            count = struct.unpack('<Q', f.read(8))[0]
            for _ in range(count):
                id_, offset = struct.unpack('<QQ', f.read(16))
                db[id_] = offset
        return db

    def load_all(self, base_path: str) -> None:
        self.ae_db  = self.load_bin(os.path.join(base_path, 'version-1-11-191-0.bin'))
        self.ng_db  = self.load_bin(os.path.join(base_path, 'version-1-10-984-0.bin'))
        self._inv_ng = {off: id_ for id_, off in self.ng_db.items()}

    def get_ae(self, id_: int) -> Optional[int]:
        return self.ae_db.get(id_) if id_ else None

    def rva_ng_to_ae(self, rva: int) -> Optional[int]:
        """Map a 1.10.984 (NG) RVA (e.g. from Fallout4.pdb) to its 1.11.191 (AE) RVA."""
        id_ = self._inv_ng.get(rva)
        if id_ is None:
            return None
        return self.ae_db.get(id_)
