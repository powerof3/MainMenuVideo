"""Fallout 4 address library loader (Dear-Modding-FO4 format).

Binary format (from CommonLibF4 IDDatabase::load()):
  uint64  count
  count × (uint64 id, uint64 offset) pairs, sorted by id

Holds both OG (1.10.163) and NG (1.11.191) databases.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Optional


class F4AddressLibrary:
    """Loads OG and NG Fallout 4 address library .bin files."""

    def __init__(self):
        self.og_db: Dict[int, int] = {}
        self.ng_db: Dict[int, int] = {}

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
        self.og_db = self.load_bin(os.path.join(base_path, 'version-1-10-163-0.bin'))
        self.ng_db = self.load_bin(os.path.join(base_path, 'version-1-11-191-0.bin'))

    def get_og(self, id_: int) -> Optional[int]:
        return self.og_db.get(id_) if id_ else None

    def get_ng(self, id_: int) -> Optional[int]:
        return self.ng_db.get(id_) if id_ else None
