#!/usr/bin/env python3
"""
Parse CommonLibSSE headers and generate Ghidra import scripts that create
struct/class/enum type definitions with function symbols and relocations.

Run with: python parse_commonlib_types.py --ccls-re PATH

Pipeline:
  Types:        ccle_client.py via ccls-re $ccls/dumpTypes
  Relocations:  reloc_parser.py (regex-based, single-pass SE+AE)
  PDB symbols:  pdbparse (extras/SkyrimSE.pdb public function names, fallback)
  Script gen:   ghidra_import_gen.py (generic Ghidra import script generator)
"""

import os
import sys
import re

from pdb_symbols import AddressLibrary, load_pdb_names as load_se_pdb_names
from ghidra_import_gen import (
    build_vtable_structs as _build_vtable_structs,
    inject_vtable_fields as _inject_vtable_fields,
    flatten_structs as _flatten_structs,
    generate_script,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMMONLIB_INCLUDE = os.path.join(SCRIPT_DIR, 'extern', 'CommonLibSSE', 'include')
SKYRIM_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Skyrim.h')
RE_INCLUDE = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'ghidrascripts')


# ---------------------------------------------------------------------------
# AE rename database
# ---------------------------------------------------------------------------

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
