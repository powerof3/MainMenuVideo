"""
Headless PyGhidra runner: imports SkyrimSE.exe into a Ghidra project and
runs CommonLibImport_SE.py, then prints a verification summary.
"""
import sys
import os
from pathlib import Path

REPO_DIR = Path(__file__).parent
GHIDRA_DIR = REPO_DIR / "ghidra_12.0.4_PUBLIC"
BINARY = REPO_DIR / "SkyrimSE.exe"
SCRIPT = REPO_DIR / "ghidrascripts" / "CommonLibImport_SE.py"
PROJECT_DIR = REPO_DIR / os.environ.get("HEADLESS_PROJECT_DIR", "ghidra_project")
PROJECT_NAME = "SkyrimSE"

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

    # Ghidra stores the domain file with the full filename (SkyrimSE.exe)
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
            print(f"Files in project root: {files}")
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
        # echo_stdout=False: avoid double-printing (we print the returned string below)
        stdout, stderr = pyghidra.ghidra_script(SCRIPT, project, program, echo_stdout=False, echo_stderr=False)
        if stdout:
            print(stdout)
        if stderr:
            print("STDERR:", stderr, file=sys.stderr)

        program.save("CommonLib import", monitor)
        print("Saved.")

        # --- Verification ---
        print("\n=== Verification Summary ===")
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        sym_table = program.getSymbolTable()

        total_funcs = fm.getFunctionCount()

        # Named = any function not starting with Ghidra's auto-generated FUN_/sub_ prefix.
        # Vtable functions are stored as flat scoped names like "Actor::GetLevel".
        named_funcs = sum(
            1 for f in fm.getFunctions(True)
            if not f.getName().startswith("FUN_") and not f.getName().startswith("sub_")
        )
        # Subset: functions with "::" (vtable / CommonLib class methods)
        scoped_funcs = sum(
            1 for f in fm.getFunctions(True)
            if "::" in f.getName()
        )

        # Live types in DTM are backed by *DB classes.
        type_count = 0
        enum_count = 0
        struct_count = 0
        for dt in dtm.getAllDataTypes():
            type_count += 1
            simple = dt.getClass().getSimpleName()
            if simple == "EnumDB":
                enum_count += 1
            elif simple == "StructureDB":
                struct_count += 1

        sym_count = sum(1 for _ in sym_table.getAllSymbols(True))

        # Functions with an explicit non-default return type have a signature applied.
        sigs_applied = sum(
            1 for f in fm.getFunctions(True)
            if f.getSignature().getReturnType().getClass().getSimpleName() != "DefaultDataType"
        )

        print(f"  Total functions       : {total_funcs:>8,}")
        print(f"  Named functions       : {named_funcs:>8,}")
        print(f"    Scoped (Class::Fn)  : {scoped_funcs:>8,}")
        print(f"  Signatures set        : {sigs_applied:>8,}")
        print(f"  Total data types      : {type_count:>8,}")
        print(f"    Enums               : {enum_count:>8,}")
        print(f"    Structs/Classes     : {struct_count:>8,}")
        print(f"  Total symbols         : {sym_count:>8,}")

        # Spot-check specific known types.
        # Thresholds use total component count (includes unnamed padding bytes).
        # The clang.exe record layout backend produces compact, fully-typed
        # fields (embedded structs are single components), so thresholds reflect
        # named-field counts rather than byte-granular sub-field expansion.
        print("\n--- Type spot-checks ---")
        from ghidra.program.model.data import CategoryPath
        spot_ok = True
        for type_name, cat_path, min_bytes, min_comps in [
            ("Actor",           "/CommonLibSSE/RE", 680, 85),
            ("TESObjectREFR",   "/CommonLibSSE/RE", 140,  18),
            ("PlayerCharacter", "/CommonLibSSE/RE", 3000, 260),
            ("ActorValue",      "/CommonLibSSE/RE",    4,   0),
        ]:
            dt = dtm.getDataType(CategoryPath(cat_path), type_name)
            if dt is None:
                print(f"  MISSING: {type_name} in {cat_path}")
                spot_ok = False
            else:
                comps = dt.getComponents() if hasattr(dt, "getComponents") else []
                n_comps = len(comps)
                named = len([x for x in comps if x.getFieldName()])
                size = dt.getLength()
                ok = size >= min_bytes and n_comps >= min_comps
                mark = "OK" if ok else "FAIL"
                print(f"  [{mark}] {type_name}: {size} bytes, {n_comps} components ({named} named)")
                if not ok:
                    spot_ok = False

        # Spot-check vtable-named functions exist.
        # Only functions at already-disassembled vtable slots will be named (no auto-analysis run).
        print("\n--- Function spot-checks ---")
        for fname in ["AbsorbEffect::ModifyOnStart", "AbsorbEffect::AdjustForPerks"]:
            syms = list(sym_table.getSymbols(fname))
            if syms:
                f = fm.getFunctionAt(syms[0].getAddress())
                ret = f.getReturnType().getName() if f else "?"
                nparams = f.getParameterCount() if f else "?"
                print(f"  [OK] {fname} @ {syms[0].getAddress()} ret={ret} params={nparams}")
            else:
                print(f"  [MISSING] {fname}")
                spot_ok = False

        # Hard sanity checks (calibrated from actual first-run results)
        print("\n--- Sanity checks ---")
        errors = []
        if named_funcs < 12000:
            errors.append(f"Named functions too low: {named_funcs:,} (expected >=12,000)")
        if enum_count < 300:
            errors.append(f"Enum count too low: {enum_count} (expected >=300)")
        if struct_count < 4500:
            errors.append(f"Struct count too low: {struct_count} (expected >=4,500)")
        if sym_count < 250000:
            errors.append(f"Symbol count too low: {sym_count:,} (expected >=250,000)")
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
