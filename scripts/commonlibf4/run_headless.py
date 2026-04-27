"""
Headless PyGhidra runner: imports Fallout4.exe into a Ghidra project and
runs CommonLibImport_F4_OG.py or CommonLibImport_F4_NG.py.

Usage:
  python run_headless.py          # default: OG (1.10.163)
  python run_headless.py ng       # NG (1.11.191)
"""
import sys
import os
from pathlib import Path

GAME_VERSION = 'ng' if len(sys.argv) > 1 and sys.argv[1].lower() == 'ng' else 'og'

REPO_DIR     = Path(__file__).parent.parent.parent
GHIDRA_DIR   = REPO_DIR / "ghidra_12.0.4_PUBLIC"
BINARY       = REPO_DIR / "Fallout4.exe"
SCRIPT       = REPO_DIR / "ghidrascripts" / f"CommonLibImport_F4_{GAME_VERSION.upper()}.py"
PROJECT_DIR  = REPO_DIR / os.environ.get("HEADLESS_PROJECT_DIR", f"ghidra_project_f4_{GAME_VERSION}")
PROJECT_NAME = "Fallout4"

print(f"Game version: {GAME_VERSION.upper()}")

os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))

import pyghidra

pyghidra.start(install_dir=GHIDRA_DIR)

PROJECT_DIR.mkdir(exist_ok=True)

with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=True) as project:
    from ghidra.app.util.importer import MessageLog
    from ghidra.util.task import ConsoleTaskMonitor
    import ghidra
    import java.io
    import java.lang

    monitor = ConsoleTaskMonitor()
    root_folder = project.getProjectData().getRootFolder()

    domain_file = None
    for candidate in (BINARY.name, BINARY.stem, PROJECT_NAME):
        domain_file = root_folder.getFile(candidate)
        if domain_file is not None:
            break

    if domain_file is None:
        print(f"Importing {BINARY} ...")
        msg_log = MessageLog()
        jfile = java.io.File(str(BINARY))
        import_consumer = java.lang.Object()
        load_results = ghidra.app.util.importer.AutoImporter.importByUsingBestGuess(
            jfile, project, "/", import_consumer, msg_log, monitor
        )
        if not load_results:
            print("ERROR: import returned no results.")
            sys.exit(1)
        print(f"Import complete. Loaded {load_results.size()} program(s).")
        load_results.save(monitor)
        load_results.close()
        for candidate in (BINARY.name, BINARY.stem, PROJECT_NAME):
            domain_file = root_folder.getFile(candidate)
            if domain_file is not None:
                break
        if domain_file is None:
            files = [f.getName() for f in root_folder.getFiles()]
            if files:
                domain_file = root_folder.getFile(files[0])
            else:
                print("ERROR: no files found in project after import.")
                sys.exit(1)
    else:
        print(f"Program '{domain_file.getName()}' already in project, skipping import.")

    consumer = java.lang.Object()
    program = domain_file.getDomainObject(consumer, True, False, monitor)

    try:
        print(f"Running {SCRIPT.name} ...")
        stdout, stderr = pyghidra.ghidra_script(SCRIPT, project, program, echo_stdout=False, echo_stderr=False)
        if stdout:
            print(stdout)
        if stderr:
            print("STDERR:", stderr, file=sys.stderr)

        program.save(f"CommonLibF4 {GAME_VERSION.upper()} import", monitor)
        print("Saved.")

        # --- Verification ---
        print("\n=== Verification Summary ===")
        fm        = program.getFunctionManager()
        dtm       = program.getDataTypeManager()
        sym_table = program.getSymbolTable()

        total_funcs = fm.getFunctionCount()
        named_funcs = sum(
            1 for f in fm.getFunctions(True)
            if not f.getName().startswith("FUN_") and not f.getName().startswith("sub_")
        )
        scoped_funcs = sum(1 for f in fm.getFunctions(True) if "::" in f.getName())

        enum_count = struct_count = 0
        for dt in dtm.getAllDataTypes():
            s = dt.getClass().getSimpleName()
            if s == "EnumDB":       enum_count   += 1
            elif s == "StructureDB": struct_count += 1

        sym_count    = sum(1 for _ in sym_table.getAllSymbols(True))
        sigs_applied = sum(
            1 for f in fm.getFunctions(True)
            if f.getSignature().getReturnType().getClass().getSimpleName() != "DefaultDataType"
        )

        print(f"  Total functions       : {total_funcs:>8,}")
        print(f"  Named functions       : {named_funcs:>8,}")
        print(f"    Scoped (Class::Fn)  : {scoped_funcs:>8,}")
        print(f"  Signatures set        : {sigs_applied:>8,}")
        print(f"    Enums               : {enum_count:>8,}")
        print(f"    Structs/Classes     : {struct_count:>8,}")
        print(f"  Total symbols         : {sym_count:>8,}")

        print("\n--- Type spot-checks ---")
        from ghidra.program.model.data import CategoryPath
        spot_ok = True
        for type_name, cat_path, min_bytes, min_comps in [
            ("ActorMovementData",  "/CommonLibF4/RE", 70,  1),
            ("BGSEquipType",       "/CommonLibF4/RE", 10,  1),
            ("Actor_vtbl",         "/CommonLibF4/RE", 800, 100),
        ]:
            dt = dtm.getDataType(CategoryPath(cat_path), type_name)
            if dt is None:
                print(f"  MISSING: {type_name} in {cat_path}")
                spot_ok = False
            else:
                comps   = dt.getComponents() if hasattr(dt, "getComponents") else []
                n_comps = len(comps)
                named   = len([x for x in comps if x.getFieldName()])
                size    = dt.getLength()
                ok      = size >= min_bytes and n_comps >= min_comps
                mark    = "OK" if ok else "FAIL"
                print(f"  [{mark}] {type_name}: {size} bytes, {n_comps} components ({named} named)")
                if not ok:
                    spot_ok = False

        print("\n--- Label spot-checks ---")
        for lname in ["VTABLE_Actor", "VTABLE_ActiveEffect", "RTTI_Actor"]:
            syms = list(sym_table.getSymbols(lname))
            if syms:
                print(f"  [OK] {lname} @ {syms[0].getAddress()}")
            else:
                print(f"  [MISSING] {lname}")
                # RTTI labels are NG-only; don't fail OG for missing RTTI
                if GAME_VERSION == 'og' and lname.startswith('RTTI_'):
                    print(f"         (RTTI labels are NG-only -- expected for OG)")
                else:
                    spot_ok = False

        print("\n--- Sanity checks ---")
        errors = []
        min_named = 500 if GAME_VERSION == 'og' else 200
        if named_funcs < min_named:
            errors.append(f"Named functions too low: {named_funcs:,} (expected >={min_named})")
        if enum_count < 100:
            errors.append(f"Enum count too low: {enum_count} (expected >=100)")
        if struct_count < 500:
            errors.append(f"Struct count too low: {struct_count} (expected >=500)")
        if not spot_ok:
            errors.append("One or more spot-checks failed (see above)")

        if errors:
            print("\n!!! VERIFICATION FAILURES !!!")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("\nAll verification checks passed.")

    finally:
        program.release(consumer)

print("\nDone.")
