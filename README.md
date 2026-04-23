# Ghidra Import Scripts

Toolchain that reverse-engineers Skyrim SE/AE by importing CommonLibSSE type definitions,
vtable layouts, and function signatures into Ghidra.

## Table of Contents

1. [Project Layout](#project-layout)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
4. [Running the Generator](#running-the-generator)
5. [Running the Ghidra Scripts](#running-the-ghidra-scripts)
6. [Pipeline Overview](#pipeline-overview)
7. [Pipeline Files Reference](#pipeline-files-reference)
8. [Known Limitations](#known-limitations)

---

## Project Layout

```
GhidraImportScripts/
├── extern/
│   ├── CommonLibSSE/           CommonLibSSE submodule (powerof3/dev branch)
│   └── AddressLibraryDatabase/ Includes AE rename database
├── addresslibrary/
│   ├── version-1-5-97-0.bin       SE address library
│   └── versionlib-1-6-1170-0.bin  AE address library
├── extras/
│   └── SkyrimSE.pdb            SE PDB for extra symbol names
├── ghidrascripts/
│   ├── CommonLibImport_SE.py   Generated: import SE types + vtables + symbols
│   └── CommonLibImport_AE.py   Generated: import AE types + vtables + symbols
├── parse_commonlib_types.py    CommonLibSSE-specific orchestrator
├── ghidra_import_gen.py        Generic Ghidra import script generator
├── ccle_client.py              LSP client for ccls-re type extraction
├── pdb_symbols.py              PDB parsing and address library loading
├── reloc_parser.py             Regex-based relocation/symbol scanner
├── template_types.py           C++ template instantiation handling
└── run_headless.py             Headless PyGhidra runner for verification
```

---

## Prerequisites

### Python (host machine)

- Python **3.10+**, 64-bit
- Install dependencies:

```bash
pip install pdbparse pyghidra
```

`pdbparse` reads SE PDB public symbols. `pyghidra` is optional, only needed
for headless verification via `run_headless.py`.

### ccls-re

[ccls-re](https://github.com/doodlum/ccls-re) is a fork of ccls with custom
`$ccls/dumpTypes` extensions for extracting C++ type layouts (records, enums,
vtable slots, method signatures). It is the sole type backend for the pipeline.

Build from source (requires LLVM+Clang dev libraries) or use a prebuilt binary.
Pass the path via `--ccls-re <path>`.

### CommonLibSSE submodule

The generator reads directly from `extern/CommonLibSSE/`. Ensure the submodule
is checked out:

```bash
git submodule update --init extern/CommonLibSSE
```

### Ghidra

- [Ghidra](https://ghidra-sre.org/) 12.x or later

---

## Setup

All paths are relative to the repository root. The generator finds all inputs
automatically — no environment variables are required.

---

## Running the Generator

Run from the repository root:

```bash
python parse_commonlib_types.py --ccls-re /path/to/ccls-re
```

Outputs:
- `ghidrascripts/CommonLibImport_SE.py` — SE types, enums, vtables, symbols
- `ghidrascripts/CommonLibImport_AE.py` — AE types, enums, vtables, symbols

Typical run time: ~30–60 seconds (two ccls-re indexing passes + relocation scan).

Console output:
```
=== Collecting symbols via regex relocation parser ===
  Parsed 196 SE + 204 AE offset IDs from Offsets.h
  Parsed 7327 labels from Offsets_RTTI.h
  Parsed 7224 labels from Offsets_VTABLE.h
  Header scan: 178 func symbols, 14551 labels
  src/ scan: 626 func symbols from 347 cpp files
Generated 53230 symbols

=== SE ===
Collecting types via ccls-re ($ccls/dumpTypes)...
Found 918 enums, 3677 structs/classes
Built 1314 vtable structs
Output: ghidrascripts/CommonLibImport_SE.py (918 enums, 4730 structs)
```

### Regeneration

Regenerate whenever:
- CommonLibSSE submodule is updated (`git submodule update`)
- `template_types.py` or the generator is modified

---

## Running the Ghidra Scripts

### Import the binary

1. Open Ghidra and create a project.
2. Import `SkyrimSE.exe` (SE) or the AE executable. Use the default PE import
   options.

### Run CommonLibImport_SE.py or CommonLibImport_AE.py

In the Ghidra Script Manager (`Window > Script Manager`):

1. Add `ghidrascripts/` to the script directories.
2. Run **`CommonLibImport_SE.py`** for SE binaries or **`CommonLibImport_AE.py`**
   for AE binaries.

The script:
- Creates all structs, classes, and enums under `/CommonLibSSE/RE/`.
- Populates vtable structs with typed function pointer fields.
- Names virtual functions by walking vtable addresses in the binary.
- Applies function signatures via `CParserUtils.parseSignature()`.
- Labels all known symbols at their computed addresses.

Both scripts are safe to re-run; they overwrite existing types and labels.

---

## Pipeline Overview

```
CommonLibSSE headers ─┬─ reloc_parser.py ──► symbols (SE+AE offsets)
CommonLibSSE src/   ──┤
Address libraries   ──┘

CommonLibSSE headers ─── ccls-re ──► types, enums, vtable slots, method signatures

parse_commonlib_types.py ─── merges both ──┐
ghidra_import_gen.py ─── generates script ─┴─► CommonLibImport_SE.py / AE.py
```

**Symbol sources** (in priority order):

1. CommonLibSSE headers — regex relocation scan (`RELOCATION_ID`, `REL::Relocation`)
2. CommonLibSSE `src/*.cpp` — regex scan (functions not in headers)
3. `skyrimae.rename` — AE address database fallback names
4. `SkyrimSE.pdb` — SE PDB public symbols (fallback, no signatures)

**Type sources:**

- ccls-re `$ccls/dumpTypes` — records (fields, bases, methods with signatures),
  enums (values, underlying type), typedefs

---

## Pipeline Files Reference

### `parse_commonlib_types.py`

CommonLibSSE-specific orchestrator. Coordinates ccls-re for types, reloc_parser
for symbols, loads address libraries / PDB / AE rename DB, and calls
`ghidra_import_gen` to emit the Ghidra import scripts.

| Input | Purpose |
|-------|---------|
| `extern/CommonLibSSE/include/RE/` | Type definitions + relocation IDs |
| `extern/CommonLibSSE/src/*.cpp` | Additional function relocations |
| `addresslibrary/` | SE and AE offset databases |
| `extern/AddressLibraryDatabase/skyrimae.rename` | AE fallback symbol names |
| `extras/SkyrimSE.pdb` | SE fallback symbol names |

### `ghidra_import_gen.py`

Generic Ghidra import script generator. Game-agnostic — takes processed type
data (enums, structs, vtable info) and symbol tables, then generates a
self-contained Jython script for Ghidra. Provides vtable hierarchy building,
struct inheritance flattening, and the full Ghidra
runtime code (type creation, symbol application, vtable walking).

### `ccle_client.py`

LSP client for ccls-re. Launches ccls-re as a subprocess, sends
`$ccls/dumpTypes` requests, and converts responses to pipeline dicts.
Parses method signatures from ccls `detailed_name` into return types and
parameter lists.

### `reloc_parser.py`

Regex-based scanner for CommonLibSSE relocation data. Extracts:
- `RELOCATION_ID(SE, AE)` — both IDs in a single pass
- `RTTI_*` / `VTABLE_*` labels from `Offsets_RTTI.h` / `Offsets_VTABLE.h`
- `RE::Offset::` namespace IDs from `Offsets.h`
- Function context (class, method name) from `.cpp` source files

### `template_types.py`

Scans for C++ template instantiation names and generates sanitized C identifier
aliases so Ghidra's `CParserUtils.parseSignature()` can resolve them.

### `run_headless.py`

Headless PyGhidra runner that imports `SkyrimSE.exe`, runs the generated script,
and prints a verification summary with sanity checks.

---

## Known Limitations

### Template instantiation layout

Template instantiation layouts come from ccls-re. Template instantiations that
ccls-re cannot resolve are emitted as opaque placeholder structs.

### Vtable slot computation

Slot indices come from ccls-re's `vtableIndex` data. Diamond inheritance with
shared virtual bases may produce incorrect slot numbers. Multi-vtable classes
(multiple inheritance) use only the primary vtable (index 0) for the vtable walk.

### CParserUtils type resolution

Ghidra's `CParserUtils.parseSignature()` resolves type names against the
Data Type Manager. Types not covered by the DTM are replaced with `void *`
by the `sanitize_unknown_types()` fallback.

---

## License

[MIT](LICENSE)
