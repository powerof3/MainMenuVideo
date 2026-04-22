#!/usr/bin/env python3
"""
Parse CommonLibSSE headers via clang.exe (-ast-dump=json + -fdump-record-layouts)
and generate a Ghidra import script (ghidrascripts/CommonLibTypes.py) that creates
struct/class/enum type definitions.

Run with: py -3.13 parse_commonlib_types.py
Requires: clang.exe reachable via PATH / registry / common install paths.

Pipeline (all via clang subprocess — no Python libclang bindings needed):
  Types:        clang_ast_collect.collect_types
  Relocations:  clang_ast_reloc.collect_relocations / collect_src_relocations
  Templates:    clangd_template_layouts via clang.exe -fdump-record-layouts
"""

import os
import sys
import re
import glob
import struct
import math
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
    """Parse a PDB (MSF7) file and return dict of rva -> name for all public function symbols."""
    if not os.path.exists(file_path):
        return {}

    with open(file_path, 'rb') as f:
        data = f.read()

    if not data.startswith(b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'):
        return {}

    # MSF superblock
    page_size = struct.unpack_from('<I', data, 32)[0]
    dir_size  = struct.unpack_from('<I', data, 44)[0]
    blk_map   = struct.unpack_from('<I', data, 52)[0]

    # Stream directory
    n_dir_pages = math.ceil(dir_size / page_size)
    dir_page_list = struct.unpack_from(f'<{n_dir_pages}I', data, blk_map * page_size)
    dir_data = b''.join(data[p * page_size:(p + 1) * page_size] for p in dir_page_list)[:dir_size]

    n_streams = struct.unpack_from('<I', dir_data, 0)[0]
    sizes = struct.unpack_from(f'<{n_streams}I', dir_data, 4)

    o = 4 + n_streams * 4
    stream_pages = []
    for sz in sizes:
        if sz == 0 or sz == 0xFFFFFFFF:
            stream_pages.append([])
        else:
            np = math.ceil(sz / page_size)
            stream_pages.append(list(struct.unpack_from(f'<{np}I', dir_data, o)))
            o += np * 4

    def read_stream(idx):
        if idx >= n_streams or sizes[idx] in (0, 0xFFFFFFFF):
            return b''
        return b''.join(data[p * page_size:(p + 1) * page_size] for p in stream_pages[idx])[:sizes[idx]]

    # DBI stream (stream 3)
    dbi = read_stream(3)
    if len(dbi) < 64:
        return {}

    (_, _, _,
     _, _,
     _, _,
     sym_rec_idx, _,
     mod_sz, sec_contrib_sz, sec_map_sz, src_sz, type_srv_sz, _,
     opt_dbg_sz, ec_sz,
     _, _, _) = struct.unpack_from('<iIIHHHHHHiiiiiIiiHHI', dbi)

    # Section headers stream index (offset 10 within optional debug header)
    opt_off = 64 + mod_sz + sec_contrib_sz + sec_map_sz + src_sz + type_srv_sz + ec_sz
    sec_hdr_idx = struct.unpack_from('<H', dbi, opt_off + 10)[0] if opt_dbg_sz >= 12 else 0xFFFF

    # Section virtual addresses (needed to convert seg:off -> RVA)
    sections = []
    if sec_hdr_idx != 0xFFFF:
        sec_data = read_stream(sec_hdr_idx)
        sections = [struct.unpack_from('<I', sec_data, i * 40 + 12)[0] for i in range(len(sec_data) // 40)]

    # Parse symbol records stream for S_PUB32 (public function) records
    sym_data = read_stream(sym_rec_idx)
    S_PUB32 = 0x110E
    result = {}
    o = 0
    while o + 4 <= len(sym_data):
        rec_len, rec_typ = struct.unpack_from('<HH', sym_data, o)
        rec_end = o + 2 + rec_len
        if rec_len < 2 or rec_end > len(sym_data):
            break
        if rec_typ == S_PUB32 and rec_end >= o + 14:
            pub_flags, off, seg = struct.unpack_from('<IIH', sym_data, o + 4)
            if pub_flags & 0x2 and 1 <= seg <= len(sections):
                nul = sym_data.find(b'\x00', o + 14, rec_end)
                if nul != -1:
                    name = sym_data[o + 14:nul].decode('ascii', errors='replace')
                    if name.startswith('?'):
                        name = _undecorate(name)
                    if re.match(r'^FUN_[0-9A-Fa-f]+$', name):
                        o = rec_end
                        continue
                    # Strip embedded full-address suffix (e.g. WriteToSaveGame_1404D62A0)
                    name = re.sub(r'_14[0-9A-Fa-f]{6,8}$', '', name)
                    # Replace __ namespace separator with ::
                    name = re.sub(r':{3,}', '::', name.replace('__', '::'))
                    result[sections[seg - 1] + off] = name
        o = rec_end

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


# ---------------------------------------------------------------------------
# Extra types supplementing clang's output
# ---------------------------------------------------------------------------
# - typedefs: clang now emits these as empty size-only shells (via TypedefDecl
#             walking in clang_ast_collect), but build_c_prelude() still needs
#             `typedef unsigned int FormID;` style lines for Ghidra's CParser —
#             empty struct shells don't teach CParser the underlying integer type.
# - enums:    stale fallbacks — clang finds these already; the `if name not in
#             enums` guard below skips almost all of them.
# - opaques:  genuine externals — forward-declared types whose real definitions
#             live in Havok/Gamebryo/Windows SDKs clang never sees. We do NOT
#             auto-emit shells from forward-decls (friend-decl inside class body
#             collides with the real type's qualified name).

_EXTRA_TYPEDEFS = {
    'FormID':          {'base': 'u32'},
    'ObjectRefHandle': {'base': 'u32'},
    'ActorHandle':     {'base': 'u32'},
    'RefHandle':       {'base': 'u32'},
    'VMHandle':        {'base': 'u64'},
    'UPInt':           {'base': 'u64'},
    'hkpShapeKey':     {'base': 'u32'},
    'va_list':         {'base': 'u64'},
    'char16_t':        {'base': 'u16'},
}

_EXTRA_ENUMS = {
    'EffectArchetype': {
        'size': 4,
        'values': {
            'kNone': -1, 'kValueModifier': 0, 'kScript': 1, 'kDispel': 2,
            'kCureDisease': 3, 'kAbsorb': 4, 'kDualValueModifier': 5,
            'kCalm': 6, 'kDemoralize': 7, 'kFrenzy': 8, 'kDisarm': 9,
            'kCommandSummoned': 10, 'kInvisibility': 11, 'kLight': 12,
            'kDarkness': 13, 'kNightEye': 14, 'kLock': 15, 'kOpen': 16,
            'kBoundWeapon': 17, 'kSummonCreature': 18, 'kDetectLife': 19,
            'kTelekinesis': 20, 'kParalysis': 21, 'kReanimate': 22,
            'kSoulTrap': 23, 'kTurnUndead': 24, 'kGuide': 25,
            'kWerewolfFeed': 26, 'kCureParalysis': 27, 'kCureAddiction': 28,
            'kCurePoison': 29, 'kConcussion': 30, 'kValueAndParts': 31,
            'kAccumulateMagnitude': 32, 'kStagger': 33, 'kPeakValueModifier': 34,
            'kCloak': 35, 'kWerewolf': 36, 'kSlowTime': 37, 'kRally': 38,
            'kEnhanceWeapon': 39, 'kSpawnHazard': 40, 'kEtherealize': 41,
            'kBanish': 42, 'kSpawnScriptedRef': 43, 'kDisguise': 44,
            'kGrabActor': 45, 'kVampireLord': 46,
        },
    },
    'InputContextID': {
        'size': 4,
        'values': {
            'kGameplay': 0, 'kMenuMode': 1, 'kConsole': 2, 'kItemMenu': 3,
            'kInventory': 4, 'kDebugText': 5, 'kFavorites': 6, 'kMap': 7,
            'kStats': 8, 'kCursor': 9, 'kBook': 10, 'kDebugOverlay': 11,
            'kJournal': 12, 'kTFCMode': 13, 'kMapDebug': 14, 'kLockpicking': 15,
            'kFavor': 16, 'kTotal': 17, 'kNone': 18,
        },
    },
    'ITEM_REMOVE_REASON': {
        'size': 4,
        'values': {
            'kRemove': 0, 'kSteal': 1, 'kSelling': 2,
            'kDropping': 3, 'kStoreInContainer': 4, 'kStoreInTeammate': 5,
        },
    },
    'REGION_DATA_ID':       {'size': 4, 'values': {}},
    'MATERIAL_ID':          {'size': 4, 'values': {}},
    'LoadConstants':        {'size': 4, 'values': {}},
    'SpellType':            {'size': 4, 'values': {}},
    'CastingSource':        {'size': 4, 'values': {}},
    'CannotCastReason':     {'size': 4, 'values': {}},
    'ActorValue':           {'size': 4, 'values': {}},
    'DEFAULT_OBJECT':       {'size': 4, 'values': {}},
    'SOUND_LEVEL':          {'size': 4, 'values': {}},
    'ErrorCode':            {'size': 4, 'values': {}},
    'ACTOR_LOS_LOCATION':   {'size': 4, 'values': {}},
    'ACTOR_VALUE_MODIFIER': {'size': 4, 'values': {}},
    'FormType':             {'size': 1, 'values': {}},
    'UI_MESSAGE_TYPE':      {'size': 4, 'values': {}},
}

_EXTRA_OPAQUES = [
    'BSFixedString', 'TintMask', 'IAIWorldLocation', 'AIWorldLocationContext',
    'IDebugText', 'NiVisibleArray', 'TrespassPackage',
    'CombatProjectileAimController', 'BSPathingStreamWrite', 'BSPathingStreamRead',
    'hkStatisticsCollector', 'hkaChunkCache', 'hkClass',
    'hkpShapeRayCastInput', 'hkpShapeRayCastOutput',
    'hkpShapeRayBundleCastInput', 'hkpShapeRayBundleCastOutput',
    'hkpShapeModifier', 'hkpCdBodyPairCollector', 'hkpCollisionInput',
    'hkpSimpleConstraintContactMgr', 'hkAabbUint32', 'hkbContext',
    'hkbClipGenerator', 'BSSynchronizedClipGenerator',
    'CollisionEntry', 'CheckTargetArgs', 'IUIMessageData',
    'GFxMovieDef', 'GFxValue', 'ObjectInterface',
    'RendererInitOSData', 'ApplicationWindowProperties', 'SourceActionMap',
    'IFunctionArguments', 'ISendEventFilter',
    'TrapData', 'TrapEntry', 'TargetEntry',
    'Location', 'ArgsType',
    'hkpCharacterRigidBody', 'hkpCharacterRigidBodyListener',
    'HWND', 'NiAVObject', 'NiPoint3', 'NiColorA',
    'BSRenderPass', 'BSShaderProperty', 'BSLight', 'BSGeometry', 'BSShader',
    'BSAnimNoteReceiver', 'BShkbAnimationGraph', 'IAnimationGraphManagerHolder',
    'BGSSoundDescriptorForm', 'BGSDecalNode', 'BSDynamicTriShape',
    'BGSImpactManager', 'BGSImpactDataSet', 'BGSNumericIDIndex',
    'BGSSaveLoadGame', 'BGSPrimitive',
    'TESHavokUtilities', 'TESRegionData', 'TESRegionDataGrass',
    'TESRegionDataObjects', 'TESRegionDataManager', 'TESIdleForm',
    'ExtraDataList', 'InventoryEntryData', 'MagicItem', 'MagicCaster',
    'MagicSystem', 'MagicUtilities', 'Effect', 'ActiveEffectFactory',
    'AIFormulas', 'HitData', 'MovementMessageActorCollision',
    'ActorMotionFeedbackOutput', 'ControlMap', 'BSGamepadDevice',
    'SkyrimVM', 'ConsoleLog', 'LooseFileStream',
    'AnimationFileManagerSingleton', 'SendHUDMessage', 'SendUIMessage',
    'PackageLocation', 'NiDefaultAVObjectPalette', 'BSScaleformExternalTexture',
    'hkpCollidable', 'hkVector4', 'hkVector4Comparison',
    'hkMoppBvTreeShapeBase', 'hkpBoxShape', 'hkpCapsuleShape',
    'hkpCompressedMeshShape', 'hkpConvexVerticesShape', 'hkpListShape',
    'hkpMoppBvTreeShape', 'hkpSphereShape', 'hkpRigidBody',
    'bhkRigidBody', 'bhkShape', 'CFilter', 'Result',
    'hkpCdBody', 'hkpRayHitCollector', 'hkpSphere', 'hkSphere',
    'hkp3AxisSweep', 'hkpBroadPhaseHandle', 'hkpCachingShapePhantom',
    'hkpWorld', 'hkpEntity', 'hkpPhantom', 'hkpSimulationIsland',
    'hkpWorldObject', 'ahkpCharacterProxy', 'ahkpWorld',
    'bhkCharacterStateClimbing', 'hkbBehaviorGraph', 'hkbStateMachine',
    'hkQsTransform', 'hkaAnimation', 'hkaAnimationControl',
    'hkaDefaultAnimationControl',
    'NiCamera', 'NiMatrix3', 'BSCullingProcess', 'BSParabolicCullingProcess',
    'NiBackToFrontAccumulator', 'BSString', 'BSStream',
    'ObjectBindPolicy', 'ProjectileHandle', 'LaunchData',
    'BSSoundHandle', 'TESFile', 'TESDescription',
    'TaskQueueInterface', 'SpellItem', 'BSPathingRequest',
]


_BASE_TO_C = {
    'u32': 'unsigned int', 'i32': 'int',
    'u64': 'unsigned long long', 'i64': 'long long',
    'u16': 'unsigned short', 'i16': 'short',
    'u8':  'unsigned char',  'i8':  'char',
}


def build_c_prelude():
    """Build a C declaration prelude from the extra-type tables for CParserUtils."""
    lines = []
    for name, info in sorted(_EXTRA_TYPEDEFS.items()):
        c_base = _BASE_TO_C.get(info['base'], 'unsigned int')
        lines.append('typedef {} {};'.format(c_base, name))
    for name, info in sorted(_EXTRA_ENUMS.items()):
        values = info.get('values', {})
        if values:
            body = ', '.join('{}={}'.format(k, v) for k, v in values.items())
            lines.append('enum {} {{ {} }};'.format(name, body))
        else:
            lines.append('typedef unsigned int {};'.format(name))
    for name in sorted(_EXTRA_OPAQUES):
        lines.append('struct {};'.format(name))
        lines.append('typedef struct {} {};'.format(name, name))
    return '\n'.join(lines)

VERSIONS = {
    'se': {
        'defines':     [],
        'pdb':         os.path.join(SCRIPT_DIR, 'pdbs', 'GhidraImport_SE_D.pdb'),
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_SE.py'),
    },
    'ae': {
        'defines':     ['-DSKYRIM_AE', '-DSKYRIM_SUPPORT_AE'],
        'pdb':         os.path.join(SCRIPT_DIR, 'pdbs', 'GhidraImport_AE_D.pdb'),
        'output':      os.path.join(OUTPUT_DIR, 'CommonLibImport_AE.py'),
    },
}

# ---------------------------------------------------------------------------
# PDB parser — DIA SDK via COM (primary), manual TPI stream (fallback)
# ---------------------------------------------------------------------------

# SymTag and LocType constants from dia2.h
_SymTagData      = 7
_SymTagFunction  = 5
_SymTagUDT       = 11
_SymTagBaseClass = 18
_LocIsThisRel    = 4

_TMPL_WS_RE = re.compile(r'\s+(?=[>,])|(?<=[<,])\s+')

def _norm_tmpl(s):
    """Normalise C++ template type name whitespace for consistent key matching.

    DIA produces 'Type >' (space before '>') while libclang canonical spellings
    use 'Type>, NextType' (space after ',').  Removing both variants gives a
    single canonical form for dict key lookups.
    """
    return _TMPL_WS_RE.sub('', s) if s else s


def _parse_tmpl(name):
    """Split 'Outer<A,B>' into ('Outer', ['A', 'B']).  Returns (name, []) for non-templates."""
    lt = name.find('<')
    if lt < 0 or not name.endswith('>'):
        return name, []
    outer = name[:lt]
    inner = name[lt + 1:-1]
    args, depth, start = [], 0, 0
    for i, c in enumerate(inner):
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        elif c == ',' and depth == 0:
            a = inner[start:i].strip()
            if a:
                args.append(a)
            start = i + 1
    a = inner[start:].strip()
    if a:
        args.append(a)
    return outer, args


def _tmpl_arg_fuzzy_eq(lc, pdb):
    """True if lc matches pdb, tolerating a missing leading 'RE::' on lc and/or
    trailing default template arguments present in pdb but absent in lc."""
    if lc == pdb:
        return True
    if 'RE::' + lc == pdb:
        return True
    lc_o, lc_a = _parse_tmpl(lc)
    pdb_o, pdb_a = _parse_tmpl(pdb)
    if lc_o != pdb_o and 'RE::' + lc_o != pdb_o:
        return False
    if len(lc_a) > len(pdb_a):
        return False
    return all(_tmpl_arg_fuzzy_eq(la, pa) for la, pa in zip(lc_a, pdb_a))


def _pdb_fuzzy_lookup(orig, pdb_types):
    """Find a PDB type entry for orig using fuzzy template argument matching.

    Accepts orig with missing 'RE::' on inner args and/or missing trailing
    default args that the PDB expands.  When multiple candidates match,
    picks the shortest PDB name (fewest extra defaults).

    Returns (pdb_key, pdb_info) or (None, None).
    """
    lc_o, lc_a = _parse_tmpl(orig)
    if not lc_a:
        return None, None
    prefix = lc_o + '<'
    candidates = []
    for k, v in pdb_types.items():
        if not k.startswith(prefix):
            continue
        pdb_o, pdb_a = _parse_tmpl(k)
        if len(lc_a) > len(pdb_a):
            continue
        if all(_tmpl_arg_fuzzy_eq(la, pa) for la, pa in zip(lc_a, pdb_a)):
            candidates.append((k, v))
    if not candidates:
        return None, None
    if len(candidates) == 1:
        return candidates[0]
    # Multiple candidates: only accept if all agree on size, otherwise ambiguous
    sizes = {v['size'] for _, v in candidates}
    if len(sizes) > 1:
        return None, None
    # Same size — pick the one with fewest extra args, then shortest name
    candidates.sort(key=lambda kv: (len(_parse_tmpl(kv[0])[1]) - len(lc_a), len(kv[0])))
    return candidates[0]


def _find_msdia_dll():
    """Locate msdia140.dll — checks VS, PIX, and the registry CLSID path."""
    # Check registry first: DIA registers its DLL path under its CLSID
    try:
        import winreg
        clsid = '{E6756135-1E65-4D17-8576-610761398C3C}'
        key_path = r'CLSID\{}\InprocServer32'.format(clsid)
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path) as k:
            path, _ = winreg.QueryValueEx(k, '')
            if path and os.path.isfile(path):
                return path
    except OSError:
        pass

    # Glob common install locations (VS DIA SDK, PIX, WinSDK)
    patterns = [
        r'C:\Program Files\Microsoft Visual Studio\*\*\DIA SDK\bin\amd64\msdia140.dll',
        r'C:\Program Files (x86)\Microsoft Visual Studio\*\*\DIA SDK\bin\amd64\msdia140.dll',
        r'C:\Program Files\Microsoft Visual Studio\*\*\DIA SDK\bin\msdia140.dll',
        r'C:\Program Files (x86)\Microsoft Visual Studio\*\*\DIA SDK\bin\msdia140.dll',
        r'C:\Program Files\Microsoft PIX\*\msdia140.dll',
        r'C:\Program Files (x86)\Microsoft PIX\*\msdia140.dll',
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            # Prefer amd64 / non-ARM builds
            amd = [m for m in matches if 'arm' not in m.lower() and 'x86' not in m.lower()]
            return (amd or matches)[0]
    return None


def _dia_iter(enum):
    """Yield IDiaSymbol objects from an IDiaEnumSymbols one at a time."""
    while True:
        try:
            result = enum.Next(1)
        except Exception:
            break
        # comtypes maps Next(celt) → (rgelt, pceltFetched)
        try:
            syms, count = result
        except (TypeError, ValueError):
            break
        if not count:
            break
        # rgelt is a single IDiaSymbol when celt=1
        yield syms[0] if isinstance(syms, (list, tuple)) else syms


def _load_pdb_types_dia(pdb_path):
    """Read RE:: struct layouts from a PDB using the DIA SDK COM interface."""
    import ctypes
    import logging
    import comtypes
    import comtypes.client

    msdia_path = _find_msdia_dll()
    if not msdia_path:
        raise RuntimeError('msdia140.dll not found in VS installation')

    # Suppress "Generating comtypes.gen.*" noise
    for log_name in ('comtypes.client._code_cache', 'comtypes.client._generate'):
        logging.getLogger(log_name).setLevel(logging.WARNING)

    dia = comtypes.client.GetModule(msdia_path)

    # Create IDiaDataSource — try registered COM first, then DllGetClassObject
    clsid = dia.DiaSource._reg_clsid_
    iface = dia.IDiaDataSource
    source = None

    try:
        source = comtypes.client.CreateObject(clsid, interface=iface)
    except Exception:
        pass

    if source is None:
        _dll = ctypes.WinDLL(msdia_path)
        _dll.DllGetClassObject.restype = ctypes.HRESULT
        IID_CF = comtypes.GUID('{00000001-0000-0000-C000-000000000046}')
        cf_ptr = ctypes.c_void_p()
        hr = _dll.DllGetClassObject(
            ctypes.byref(clsid), ctypes.byref(IID_CF), ctypes.byref(cf_ptr)
        )
        if hr:
            raise OSError('DllGetClassObject failed: {:#010x}'.format(hr & 0xFFFFFFFF))
        # IClassFactory — define inline since comtypes doesn't expose it publicly
        class IClassFactory(comtypes.IUnknown):
            _iid_ = comtypes.GUID('{00000001-0000-0000-C000-000000000046}')
            _methods_ = [
                comtypes.COMMETHOD([], ctypes.HRESULT, 'CreateInstance',
                    (['in'], ctypes.POINTER(comtypes.IUnknown), 'pUnkOuter'),
                    (['in'], ctypes.POINTER(comtypes.GUID), 'riid'),
                    (['out'], ctypes.POINTER(ctypes.c_void_p), 'ppvObject'),
                ),
                comtypes.COMMETHOD([], ctypes.HRESULT, 'LockServer',
                    (['in'], ctypes.c_bool, 'fLock'),
                ),
            ]
        # comtypes LP types proxy COM calls directly — no .contents needed
        unk = ctypes.cast(cf_ptr, ctypes.POINTER(comtypes.IUnknown))
        factory = unk.QueryInterface(IClassFactory)
        ppv = factory.CreateInstance(None, ctypes.byref(iface._iid_))
        source = ctypes.cast(ppv, ctypes.POINTER(iface))

    source.loadDataFromPdb(pdb_path)
    session = source.openSession()
    scope = session.globalScope

    result = {}

    for sym in _dia_iter(scope.findChildren(_SymTagUDT, None, 0)):
        try:
            name = _norm_tmpl(sym.name)
        except Exception:
            continue
        if not name or not name.startswith('RE::'):
            continue
        try:
            size = sym.length
        except Exception:
            continue
        if not size:
            continue

        fields = []
        try:
            for fsym in _dia_iter(sym.findChildren(_SymTagData, None, 0)):
                try:
                    if fsym.locationType == _LocIsThisRel:
                        try:
                            type_name = _norm_tmpl(fsym.type.name or '')
                        except Exception:
                            type_name = ''
                        fields.append((fsym.name, fsym.offset, type_name))
                except Exception:
                    pass
        except Exception:
            pass

        bases = []
        try:
            for bsym in _dia_iter(sym.findChildren(_SymTagBaseClass, None, 0)):
                try:
                    bases.append((_norm_tmpl(bsym.type.name), bsym.offset))
                except Exception:
                    pass
        except Exception:
            pass

        vfuncs = []
        _class_short = name.split('::')[-1]
        try:
            for fsym in _dia_iter(sym.findChildren(_SymTagFunction, None, 0)):
                try:
                    if fsym.intro and fsym.virtual:
                        voff = fsym.virtualBaseOffset
                        fname = fsym.name
                        if fname == '__vecDelDtor':
                            fname = '~' + _class_short
                        if fname and '<' not in fname and 0 <= voff < 0x4000:
                            vfuncs.append((fname, voff))
                except Exception:
                    pass
        except Exception:
            pass

        if name not in result:
            result[name] = {
                'size': size,
                'fields': fields,
                'bases': bases,
                'vfuncs': vfuncs,
            }

    return result


def load_pdb_types(pdb_path):
    """
    Extract RE:: struct layouts from a PDB file using DIA SDK via COM.
    Returns: { 'RE::StructName': { 'size', 'fields', 'bases', 'vfuncs' } }
    """
    if not os.path.isfile(pdb_path):
        return {}
    return _load_pdb_types_dia(pdb_path)

# Third-party include directory for headers required by CommonLibSSE PCH
# (binary_io, spdlog).  Without these, PCH.h triggers a fatal error that
# aborts parsing and prevents libclang from instantiating templates — causing
# ~1300 structs (TESForm and all descendants) to report size=1.
#
# Prefer real vcpkg-installed headers ($VCPKG_ROOT/installed/x64-windows/include);
# fall back to minimal stubs generated in _clang_stubs/ if vcpkg is unavailable.
_VCPKG_INCLUDE = None
_vcpkg_root = os.environ.get('VCPKG_ROOT', '')
if _vcpkg_root:
    for _triplet in ('x64-windows-static', 'x64-windows'):
        _candidate = os.path.join(_vcpkg_root, 'installed', _triplet, 'include')
        if (os.path.isfile(os.path.join(_candidate, 'binary_io', 'file_stream.hpp'))
                and os.path.isfile(os.path.join(_candidate, 'spdlog', 'spdlog.h'))):
            _VCPKG_INCLUDE = _candidate
            break

if _VCPKG_INCLUDE:
    _THIRD_PARTY_INCLUDE = _VCPKG_INCLUDE
else:
    # Generate minimal stubs so parsing doesn't fatal-error
    _STUB_DIR = os.path.join(SCRIPT_DIR, '_clang_stubs')
    os.makedirs(os.path.join(_STUB_DIR, 'binary_io'), exist_ok=True)
    os.makedirs(os.path.join(_STUB_DIR, 'spdlog'), exist_ok=True)

    _binary_io_stub = os.path.join(_STUB_DIR, 'binary_io', 'file_stream.hpp')
    if not os.path.isfile(_binary_io_stub):
        with open(_binary_io_stub, 'w') as _f:
            _f.write('#pragma once\nnamespace binary_io { class file_istream {}; class file_ostream {}; }\n')

    _spdlog_stub = os.path.join(_STUB_DIR, 'spdlog', 'spdlog.h')
    if not os.path.isfile(_spdlog_stub):
        with open(_spdlog_stub, 'w') as _f:
            _f.write('#pragma once\nnamespace spdlog { class logger {}; }\n')

    _THIRD_PARTY_INCLUDE = _STUB_DIR

# <windows.h> (pulled in by spdlog/details/windows_include.h) defines macros
# with identical names to REX::W32 constexpr variables (CP_UTF8, MAX_PATH,
# MEM_RELEASE, IMAGE_SCN_MEM_EXECUTE, …).  When libclang sees REX::W32::CP_UTF8
# it macro-expands CP_UTF8 → 65001, producing REX::W32::65001 which is an
# "expected unqualified-id" error.
#
# Fix: shadow spdlog/details/windows_include.h with a wrapper that includes the
# real <windows.h> and then #undefs every name that REX::W32 redeclares as a
# constexpr variable.  This gives spdlog its Windows types while keeping the
# REX::W32 namespace free of conflicting preprocessor macros.
import re as _re

_rex_w32_constexpr_names = []
for _root, _dirs, _files in os.walk(os.path.join(COMMONLIB_INCLUDE, 'REX', 'W32')):
    for _fname in _files:
        if _fname.endswith('.h'):
            try:
                with open(os.path.join(_root, _fname), encoding='utf-8', errors='replace') as _fh:
                    for _line in _fh:
                        _m = _re.match(r'\s*inline\s+(?:constexpr\s+|const\s+)?auto\s+(\w+)', _line)
                        if _m:
                            _rex_w32_constexpr_names.append(_m.group(1))
            except OSError:
                pass

_WIN_STUB_DIR = os.path.join(SCRIPT_DIR, '_clang_stubs')
os.makedirs(os.path.join(_WIN_STUB_DIR, 'spdlog', 'details'), exist_ok=True)
os.makedirs(os.path.join(_WIN_STUB_DIR, 'spdlog', 'sinks'), exist_ok=True)
_win_inc_stub = os.path.join(_WIN_STUB_DIR, 'spdlog', 'details', 'windows_include.h')
# spdlog/sinks/wincolor_sink-inl.h uses INVALID_HANDLE_VALUE directly as a macro.
# Stub it empty so we can safely undef INVALID_HANDLE_VALUE to prevent
# REX::W32::INVALID_HANDLE_VALUE from being macro-expanded in CommonLibSSE headers.
with open(os.path.join(_WIN_STUB_DIR, 'spdlog', 'sinks', 'wincolor_sink-inl.h'), 'w') as _f:
    _f.write('#pragma once\n')
# Also undefine Windows SDK function-like macros that shadow REX::W32 functions:
# IMAGE_FIRST_SECTION: complex pointer macro in winnt.h, redeclared inline in KERNEL32.h
# IMAGE_SNAP_BY_ORDINAL64: function-like macro in winnt.h, shadows REX::W32 inline function
_EXTRA_MACRO_UNDEFS = ['IMAGE_FIRST_SECTION', 'IMAGE_SNAP_BY_ORDINAL64']
_undef_block = '\n'.join('#undef ' + _n for _n in _rex_w32_constexpr_names + _EXTRA_MACRO_UNDEFS)
with open(_win_inc_stub, 'w') as _f:
    _f.write(
        '#pragma once\n'
        '// Wrapper: include real windows.h then undefine all REX::W32 macro name conflicts\n'
        '#ifndef NOMINMAX\n#define NOMINMAX\n#endif\n'
        '#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif\n'
        '#include <windows.h>\n'
        + _undef_block + '\n'
    )

PARSE_ARGS_BASE = [
    '-x', 'c++',
    '-std=c++23',
    '-fms-compatibility',
    '-fms-extensions',
    '-DWIN32', '-D_WIN64',
    '-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH',  # suppress STL1000 clang version check
    # MSVC's ucrt/stddef.h defines offsetof as a reinterpret_cast expression, which
    # is not constexpr, causing static_assert(offsetof(...)==N) to fail as
    # "not an integral constant expression".  _CRT_USE_BUILTIN_OFFSETOF makes
    # stddef.h use __builtin_offsetof instead, which is always constexpr in clang.
    '-D_CRT_USE_BUILTIN_OFFSETOF',
    # spdlog/common.h defines SPDLOG_HEADER_ONLY (and includes all -inl.h files) unless
    # SPDLOG_COMPILED_LIB is set.  wincolor_sink-inl.h uses INVALID_HANDLE_VALUE as a
    # raw macro, conflicting with our undef.  Pretend spdlog is a compiled library so
    # none of the inl files are pulled in.
    '-DSPDLOG_COMPILED_LIB',
    '-I' + _WIN_STUB_DIR,                          # shadow spdlog/details/windows_include.h
    '-isystem', _THIRD_PARTY_INCLUDE,              # binary_io/spdlog (vcpkg or stubs)
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
    for vt in VTABLES:
        vname, class_full_name, vtbl_size, category, slots = vt
        class_short = class_full_name.split('::')[-1]
        vtbl_label = 'VTABLE_' + class_short
        vtbl_syms = list(sym_table.getSymbols(vtbl_label))
        if not vtbl_syms:
            continue
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
                    continue
                curr = func.getName()
                if not (curr.startswith('FUN_') or curr.startswith('sub_')):
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
                pass
    print('Named {} virtual functions from vtable addresses'.format(named_vfuncs))

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


def generate_script(enums, structs, vtable_structs, output_path, version, symbols_json, fallback_symbols_json='[]', c_prelude='', template_source=''):
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

    # Embed C prelude for CParserUtils signature parsing
    lines.append('C_TYPE_PRELUDE = ' + repr(c_prelude))
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

def _compute_vfuncs(structs):
    """Derive vtable slot byte-offsets from the class hierarchy.

    An 'intro virtual' is a virtual method declared in this class whose name
    does not appear anywhere in the primary base's accumulated virtual method set.
    Slots are assigned in declaration order starting after the primary base's
    total slot count.

    Stores st['vfuncs'] = [(method_name, byte_offset)] on qualifying structs.
    The PDB merge step will override these with more precise compiled data when
    the PDB is available.
    """
    slot_cache    = {}  # full_name → total vtable slot count
    vmname_cache  = {}  # full_name → frozenset of all virtual method names (recursive)

    def resolve(name):
        return structs.get(name) or structs.get(name.split('::')[-1])

    def all_vmethod_names(full_name, depth=0):
        """All virtual method names visible in full_name's vtable (own + inherited)."""
        if depth > 30:
            return frozenset()
        if full_name in vmname_cache:
            return vmname_cache[full_name]
        vmname_cache[full_name] = frozenset()  # cycle guard
        st = structs.get(full_name)
        if not st:
            return frozenset()
        result = set(st.get('vmethods', {}).keys())
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                result |= all_vmethod_names(bs['full_name'], depth + 1)
            break  # primary base only (vtable chain is primary base chain)
        frozen = frozenset(result)
        vmname_cache[full_name] = frozen
        return frozen

    def total_slots(full_name, depth=0):
        """Total vtable slots in full_name including all inherited intro virtuals."""
        if depth > 30:
            return 0
        if full_name in slot_cache:
            return slot_cache[full_name]
        slot_cache[full_name] = 0  # cycle guard
        st = structs.get(full_name)
        if not st:
            return 0
        # Primary base contributes all its slots
        base_count = 0
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                base_count = total_slots(bs['full_name'], depth + 1)
            break
        # Own intro virtuals = vmethods whose names are NOT in primary base's full set
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
        # Get primary base's accumulated vmethods and slot count
        primary_base_names = frozenset()
        base_start = 0
        for base_name in st.get('bases', []):
            bs = resolve(base_name)
            if bs:
                primary_base_names = all_vmethod_names(bs['full_name'])
                base_start = total_slots(bs['full_name'])
            break
        # Intro virtuals in declaration order
        intro = [n for n in st.get('vmethods', {}) if n not in primary_base_names]
        if not intro:
            continue
        st['vfuncs'] = [(mname, (base_start + i) * 8) for i, mname in enumerate(intro)]
        count += 1

    print('Computed vtable slots for {} structs'.format(count))


def _merge_pdb_into_structs(structs, pdb_types):
    """
    Cross-reference libclang struct data with PDB TPI data.
    Also stores PDB base class offsets on each struct for later flattening.
    """
    matched = size_ok = size_mismatch = supplemented = 0

    # Build short-name → struct entry map for field type inference in PDB-supplemented structs
    structs_by_short = {}
    for st in structs.values():
        short = st['name']
        if short not in structs_by_short or structs_by_short[short]['size'] > 1:
            structs_by_short[short] = st

    for pdb_name, pdb_info in pdb_types.items():
        # Skip template types for struct cross-referencing — they're only used
        # for enriching field type names, not for matching clang structs.
        if '<' in pdb_name:
            continue
        short = pdb_name.split('::')[-1]
        clang_key = pdb_name if pdb_name in structs else short if short in structs else None
        if clang_key is None:
            continue

        matched += 1
        clang = structs[clang_key]
        pdb_sz = pdb_info['size']
        pdb_fields = pdb_info['fields']    # [(name, offset)] — own members only
        pdb_bases  = pdb_info['bases']     # [(base_name, base_offset)]

        # Always store PDB base offsets and vfuncs — used by flattening and vtable building
        clang['pdb_bases'] = pdb_bases
        clang['vfuncs'] = pdb_info.get('vfuncs', [])

        if clang['size'] == 1 and pdb_sz > 1:
            # libclang got an incomplete layout; use PDB size + own fields.
            # Pass structs_by_short so field types can be inferred from known struct sizes.
            clang['size'] = pdb_sz
            clang['fields'] = _pdb_fields_to_clang(pdb_fields, pdb_sz, structs_by_short)
            # Enrich PDB fields with clang type hints (clang knows types even
            # when it can't compute offsets for incomplete types)
            hints = clang.get('field_type_hints', {})
            if hints:
                for f in clang['fields']:
                    if f['type'].startswith('bytes:') or f['type'] == 'ptr':
                        hint = hints.get(f['name'])
                        if hint:
                            f['type'] = hint
            supplemented += 1

        elif clang['size'] == pdb_sz and pdb_sz > 1:
            size_ok += 1
            # Sizes match — fill PDB field names and template types where libclang is incomplete.
            clang_field_map = {f['offset']: f for f in clang['fields']}
            for entry in pdb_fields:
                pdb_fname, pdb_foff = entry[0], entry[1]
                pdb_type_name = entry[2] if len(entry) > 2 else ''
                if pdb_foff in clang_field_map:
                    f = clang_field_map[pdb_foff]
                    if not f['name']:
                        f['name'] = pdb_fname
                    # Enrich field type with PDB template info when clang has generic type
                    if pdb_type_name and '<' in pdb_type_name:
                        cur_type = f['type']
                        if cur_type.startswith('bytes:') or cur_type == 'ptr' or \
                           (cur_type.startswith('struct:') and '<' not in cur_type):
                            f['type'] = 'struct:' + pdb_type_name

        elif clang['size'] == 1 and pdb_sz == 1:
            # Both sides report size 1: forward declaration, empty tag struct, or enum.
            # No field data on either side; nothing to merge.
            pass

        else:
            # Genuine layout disagreement — both sides have a non-trivial size but disagree.
            size_mismatch += 1
            print('  SIZE MISMATCH: {} clang={} pdb={}'.format(pdb_name, clang['size'], pdb_sz))

    print('PDB cross-reference: {} matched, {} size-ok, {} supplemented, {} mismatched'.format(
        matched, size_ok, supplemented, size_mismatch))


def _pdb_fields_to_clang(pdb_fields, total_size, structs_by_short=None):
    """Convert [(name, offset, pdb_type_name)] from PDB into our field format.

    Uses pdb_type_name (from DIA fsym.type.name) to infer the struct type where possible,
    falling back to structs_by_short size-matching, then bytes:N.
    """
    if not pdb_fields:
        return []
    sorted_fields = sorted(pdb_fields, key=lambda x: x[1])
    result = []
    for i, entry in enumerate(sorted_fields):
        name, off = entry[0], entry[1]
        pdb_type_name = entry[2] if len(entry) > 2 else ''
        if i + 1 < len(sorted_fields):
            next_off = sorted_fields[i + 1][1]
        else:
            next_off = total_size
        fsize = next_off - off
        if fsize <= 0:
            continue

        ftype = 'bytes:{}'.format(fsize)

        # Priority 0: PDB type name is a template instantiation — use directly
        if pdb_type_name and '<' in pdb_type_name:
            ftype = 'struct:' + pdb_type_name

        # Priority 1: use PDB type name if it refers to a known struct/enum
        elif pdb_type_name and structs_by_short:
            short = pdb_type_name.split('::')[-1].strip()
            if short in structs_by_short:
                cand = structs_by_short[short]
                if cand['size'] == fsize:
                    ftype = 'struct:' + cand['full_name']

        # Priority 2: field name matches a known struct of the right size
        if ftype.startswith('bytes:') and structs_by_short and name in structs_by_short:
            cand = structs_by_short[name]
            if cand['size'] == fsize:
                ftype = 'struct:' + cand['full_name']

        result.append({
            'name': name,
            'type': ftype,
            'offset': off,
            'size': fsize,
        })
    return result


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
        pdb_bases = st.get('pdb_bases', [])
        if pdb_bases:
            primary_name, primary_off = pdb_bases[0]
            if primary_off == 0:
                return by_name.get(primary_name) or by_name.get(primary_name.split('::')[-1])
        else:
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
        # ret_type and params come from libclang signature data; None if unknown.
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


def _flatten_structs(structs):
    """
    In-place: for every struct, expand base class fields into the derived struct
    so the final field list covers the entire layout at absolute byte offsets.

    Uses pdb_bases ([(base_name, base_offset)]) when available for accurate
    base placement; falls back to assuming first base starts at offset 0.
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

        # --- Determine base class placements ---
        pdb_bases = st.get('pdb_bases', [])  # [(base_name, base_offset)] from PDB

        if pdb_bases:
            # PDB gave us exact offsets for each base
            for base_name, base_off in pdb_bases:
                base_st = by_name.get(base_name) or by_name.get(base_name.split('::')[-1])
                if not base_st:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    abs_off = base_off + f['offset']
                    if abs_off not in combined:
                        field_copy = dict(f, offset=abs_off)
                        # Secondary vtable pointers (base placed at non-zero offset):
                        # rename __vftable → __vftable_BaseName so they're identifiable
                        if f['name'] == '__vftable' and base_off > 0:
                            field_copy['name'] = '__vftable_' + base_st['name']
                        combined[abs_off] = field_copy
        else:
            # No PDB base info — assume single base at offset 0
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


def run_version(version, symbols_json, fallback_symbols_json='[]'):
    cfg = VERSIONS[version]
    pdb_path = cfg['pdb']
    output_path = cfg['output']
    parse_args = PARSE_ARGS_BASE + cfg['defines']

    print('\n=== {} ==='.format(version.upper()))

    if not os.path.isfile(SKYRIM_H):
        print('ERROR: Could not find Skyrim.h at', SKYRIM_H)
        sys.exit(1)

    print('Collecting types via clang.exe (-ast-dump=json)...')
    import clang_ast_collect as _cac
    enums, structs = _cac.collect_types(SKYRIM_H, parse_args, RE_INCLUDE, verbose=True)
    print('Found {} enums, {} structs/classes'.format(len(enums), len(structs)))

    _compute_vfuncs(structs)

    if os.path.isfile(pdb_path):
        print('Loading PDB type info from {}...'.format(os.path.basename(pdb_path)))
        pdb_types = load_pdb_types(pdb_path)
        print('Found {} RE:: types in PDB'.format(len(pdb_types)))
        _merge_pdb_into_structs(structs, pdb_types)
    else:
        print('PDB not found at {}, skipping cross-reference'.format(pdb_path))

    vtable_structs = _build_vtable_structs(structs)
    _inject_vtable_fields(structs, vtable_structs)
    _flatten_structs(structs)

    # Inject hand-authored extras (typedefs, stub enums, external opaques) not
    # derivable from CommonLibSSE headers.  Each only fires when clang didn't
    # already produce the type.
    category = '/CommonLibSSE/RE'
    _base_sz = {'u32': 4, 'i32': 4, 'u64': 8, 'i64': 8, 'u16': 2, 'i16': 2, 'u8': 1, 'i8': 1}
    for name, info in _EXTRA_TYPEDEFS.items():
        if name not in enums and name not in structs:
            structs[name] = {'name': name, 'full_name': name,
                             'size': _base_sz.get(info['base'], 4),
                             'category': category, 'fields': [], 'bases': [],
                             'has_vtable': False}
    for name, info in _EXTRA_ENUMS.items():
        if name not in enums:
            vals = list(info.get('values', {}).items())
            enums[name] = {'name': name, 'full_name': name,
                           'size': info.get('size', 4),
                           'category': category, 'values': vals}
    for name in _EXTRA_OPAQUES:
        if name not in structs and name not in enums:
            structs[name] = {'name': name, 'full_name': name, 'size': 0,
                             'category': category, 'fields': [], 'bases': [],
                             'has_vtable': False}

    c_prelude = build_c_prelude()

    # Optional: scan for C++ template instantiation types and extend the prelude
    try:
        from template_types import process_template_types as _process_templates
        _tmpl = _process_templates(structs)
        # NOTE: Do NOT append _tmpl.c_prelude_fragment to c_prelude — the template
        # alias structs are created as Ghidra DataTypes (struct shells) so
        # CParserUtils can resolve them via the DataTypeManager.  Putting 1200+
        # forward declarations in C_TYPE_PRELUDE makes it ~280KB which causes
        # Ghidra's C parser to fail on every prototype.
        template_source = _tmpl.combined_source()
        # Add template types to structs so they get created as Ghidra DataTypes.
        # template_map: original → display name (RE:: stripped)
        # Populate fields from PDB where available, flattening base class fields.
        _pdb = pdb_types if os.path.isfile(pdb_path) else {}
        _sbs = {st['name']: st for st in structs.values() if st['size'] > 1}

        def _flatten_pdb_fields(pdb_name, pdb_db, depth=0):
            """Recursively collect fields from a PDB type and its bases."""
            if depth > 10:
                return []
            entry = pdb_db.get(pdb_name)
            if not entry:
                return []
            collected = {}  # offset → (name, offset, type_name)
            # First, pull in base class fields at their base offsets
            for base_name, base_off in entry.get('bases', []):
                for bf in _flatten_pdb_fields(base_name, pdb_db, depth + 1):
                    abs_off = base_off + bf[1]
                    if abs_off not in collected:
                        collected[abs_off] = (bf[0], abs_off, bf[2] if len(bf) > 2 else '')
            # Own fields override bases at the same offset
            for f in entry.get('fields', []):
                fname, foff = f[0], f[1]
                ftype = f[2] if len(f) > 2 else ''
                collected[foff] = (fname, foff, ftype)
            return sorted(collected.values(), key=lambda x: x[1])

        # Pre-compute clangd layouts for all template instantiations.
        _tmpl_clangd_layouts: dict = {}
        try:
            from clangd_template_layouts import (
                extract_layouts as _clangd_extract,
                find_clang_binary as _find_clang,
            )
            _clang_bin = _find_clang()
            if _clang_bin:
                _all_orig_names = [_norm_tmpl(o) for o in _tmpl.template_map]
                print('  [clangd] Extracting layouts for {} template types '
                      'using {}...'.format(len(_all_orig_names),
                                           os.path.basename(_clang_bin)))
                _tmpl_clangd_layouts = _clangd_extract(
                    _all_orig_names, parse_args, SKYRIM_H,
                    clang_binary=_clang_bin)
                _ok = sum(1 for sz, _ in _tmpl_clangd_layouts.values() if sz > 0)
                print('  [clangd] Resolved {}/{} types'.format(
                    _ok, len(_all_orig_names)))
            else:
                print('  [clangd] ERROR: clang binary not found')
        except Exception as _e:
            print('  [clangd] ERROR:', _e)

        for _orig, _display in _tmpl.template_map.items():
            if _display not in structs and _display not in enums:
                _sz = 0
                _fields = []
                # Look up the original template name in PDB types for size + fields.
                # Normalise whitespace so DIA ("Type >") and clang ("Type>,") keys match.
                _orig_n = _norm_tmpl(_orig)
                _orig_re = 'RE::' + _orig_n
                pdb_entry = _pdb.get(_orig_n) or _pdb.get(_orig_re)
                _pdb_name = _orig_n if _orig_n in _pdb else (_orig_re if _orig_re in _pdb else None)
                if not pdb_entry:
                    # Exact lookup failed — try fuzzy match for missing RE:: / default args
                    _fuzz_key, pdb_entry = _pdb_fuzzy_lookup(_orig_n, _pdb)
                    if pdb_entry:
                        _pdb_name = _fuzz_key
                if pdb_entry:
                    _sz = pdb_entry.get('size', 0)
                    if _sz > 0 and _pdb_name:
                        flat = _flatten_pdb_fields(_pdb_name, _pdb)
                        if flat:
                            _fields = _pdb_fields_to_clang(flat, _sz, _sbs)

                _clangd_sz, _clangd_fields = _tmpl_clangd_layouts.get(_orig_n, (0, []))
                if _clangd_sz:
                    if not _sz:
                        _sz, _fields = _clangd_sz, _clangd_fields
                    elif _clangd_sz == _sz:
                        _fields = _clangd_fields
                structs[_display] = {'name': _display, 'full_name': _display, 'size': _sz,
                                     'category': category, 'fields': _fields, 'bases': [],
                                     'has_vtable': False}
        if _tmpl.template_map:
            print('Discovered {} template instantiation aliases'.format(len(_tmpl.template_map)))

    except ImportError:
        template_source = ''

    print('Generating Ghidra script...')
    n_enums, n_structs = generate_script(enums, structs, vtable_structs, output_path, version, symbols_json, fallback_symbols_json, c_prelude, template_source)
    print('Output: {} ({} enums, {} structs)'.format(output_path, n_enums, n_structs))


def main():
    import json as _json
    import argparse

    ap = argparse.ArgumentParser(description='Parse CommonLibSSE and generate Ghidra import script')
    ap.parse_args()

    # Load address databases (binary data, not source scanning)
    addr_lib = AddressLibrary()
    addr_lib.load_all(os.path.join(SCRIPT_DIR, 'addresslibrary'))
    print('SE entries: {}, AE entries: {}'.format(len(addr_lib.se_db), len(addr_lib.ae_db)))

    print('\n=== Collecting symbols via clang.exe (JSON AST) ===')
    se_func_syms = []
    se_label_syms = []
    ae_func_syms = []
    ae_label_syms = []
    se_offset_map = {}
    ae_offset_map = {}
    static_methods = set()

    import clang_ast_reloc as _car

    for version, is_ae in (('se', False), ('ae', True)):
        cfg = VERSIONS[version]
        parse_args = PARSE_ARGS_BASE + cfg['defines']
        print('\n--- {} relocation scan ---'.format(version.upper()))
        fs, ls, off_map, sm = _car.collect_relocations(
            SKYRIM_H, parse_args, addr_lib, is_ae, verbose=True)
        static_methods |= sm  # union of SE and AE static methods (same headers)
        if is_ae:
            ae_func_syms, ae_label_syms, ae_offset_map = fs, ls, off_map
        else:
            se_func_syms, se_label_syms, se_offset_map = fs, ls, off_map

    # Parse src/ cpp files (unity build) for functions not in Skyrim.h
    src_dir = os.path.join(SCRIPT_DIR, 'extern', 'CommonLibSSE', 'src')
    if os.path.isdir(src_dir):
        src_func_syms = _car.collect_src_relocations(
            src_dir,
            PARSE_ARGS_BASE + VERSIONS['se']['defines'],
            PARSE_ARGS_BASE + VERSIONS['ae']['defines'],
            addr_lib, se_offset_map, ae_offset_map, skyrim_h=SKYRIM_H,
            verbose=True,
        )
    else:
        src_func_syms = []
        print('  src/ dir not found, skipping')

    # Merge RTTI/VTABLE labels — combine SE and AE offsets by name
    label_by_name = {}
    for lbl in se_label_syms:
        label_by_name.setdefault(lbl['name'], {'name': lbl['name'], 'se_off': None, 'ae_off': None})
        label_by_name[lbl['name']]['se_off'] = lbl['se_off']
    for lbl in ae_label_syms:
        label_by_name.setdefault(lbl['name'], {'name': lbl['name'], 'se_off': None, 'ae_off': None})
        label_by_name[lbl['name']]['ae_off'] = lbl['ae_off']

    # AE parse gives both IDs for functions; SE parse also yields any SE-only functions
    # Merge: prefer AE entries (have both IDs); add SE-only if not covered
    seen_se = set(fs['se_off'] for fs in ae_func_syms if fs['se_off'])
    seen_ae = set(fs['ae_off'] for fs in ae_func_syms if fs['ae_off'])
    merged_funcs = list(ae_func_syms)
    for fs in se_func_syms:
        if fs['se_off'] and fs['se_off'] not in seen_se:
            seen_se.add(fs['se_off'])
            merged_funcs.append(fs)
    # Correct static detection for src/ symbols using the header-derived static_methods set.
    # A .cpp definition's StorageClass may be missing when the compiler cannot link it
    # back to its (static) header declaration — fall back to the header-derived set.
    for fs in src_func_syms:
        if not fs.get('is_static') and fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    # Add src/ symbols not already found via headers
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
        run_version(version, symbols_json, fb_json)


if __name__ == '__main__':
    main()
