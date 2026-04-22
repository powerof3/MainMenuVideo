"""LSP client for ccle-re (forked ccls) — drop-in replacement for clang_ast_collect.

Launches ccle-re as a subprocess over stdio (JSON-RPC 2.0), performs the standard
LSP handshake, then uses custom extension requests ($ccle/dumpTypes,
$ccle/vtableLayout) to collect types, enums, structs, and vtable layouts.

The high-level API matches clang_ast_collect.collect_types() so
parse_commonlib_types.py can swap ``import clang_ast_collect`` for
``import ccle_client`` with minimal changes.

Relocation scanning (REL::Relocation<>) remains in clang_ast_reloc.py — it is
game-specific logic that does not belong in the language server fork.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, List, Optional, Tuple

# Reuse the pipeline type-mapping utilities from the existing codebase.
from clangd_template_layouts import _record_type_to_pipeline, _qualify_re

# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

_CCLE_BINARY_NAME = "ccle-re.exe" if os.name == "nt" else "ccle-re"
_CCLE_FALLBACK_PATH = os.path.join(
    "D:\\GitHub\\ghidrascripts\\ccle-re\\build", _CCLE_BINARY_NAME
)


def find_ccle_binary() -> Optional[str]:
    """Locate the ccle-re binary.  Checks PATH first, then the fallback build dir."""
    on_path = shutil.which(_CCLE_BINARY_NAME)
    if on_path:
        return on_path
    if os.path.isfile(_CCLE_FALLBACK_PATH):
        return _CCLE_FALLBACK_PATH
    return None


# ---------------------------------------------------------------------------
# Primitive-size table (shared with clang_ast_collect)
# ---------------------------------------------------------------------------

_PRIM_SIZES: Dict[str, int] = {
    "bool": 1, "char": 1, "signed char": 1, "unsigned char": 1,
    "short": 2, "unsigned short": 2, "wchar_t": 2, "char16_t": 2,
    "int": 4, "unsigned int": 4, "long": 4, "unsigned long": 4,
    "char32_t": 4, "float": 4,
    "std::uint8_t": 1, "std::int8_t": 1, "uint8_t": 1, "int8_t": 1,
    "std::uint16_t": 2, "std::int16_t": 2, "uint16_t": 2, "int16_t": 2,
    "std::uint32_t": 4, "std::int32_t": 4, "uint32_t": 4, "int32_t": 4,
    "std::uint64_t": 8, "std::int64_t": 8, "uint64_t": 8, "int64_t": 8,
    "long long": 8, "unsigned long long": 8, "double": 8,
    "size_t": 8, "ptrdiff_t": 8, "intptr_t": 8, "uintptr_t": 8,
    "std::size_t": 8, "std::ptrdiff_t": 8,
    "std::intptr_t": 8, "std::uintptr_t": 8,
}

# Enum full names collected during type conversion (for struct:→enum: swaps).
_ENUM_NAMES: set = set()


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 / LSP low-level client
# ---------------------------------------------------------------------------

class LspClient:
    """Stdio-based JSON-RPC 2.0 client for an LSP server (ccle-re).

    Spawns the server as a subprocess with stdin/stdout pipes.  A background
    reader thread demultiplexes responses (matched by ``id``) from server-
    initiated notifications.
    """

    def __init__(self, binary: str, init_args: Optional[List[str]] = None,
                 timeout: float = 300.0):
        self._binary = binary
        self._timeout = timeout

        cmd = [binary] + (init_args or [])
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        self._id_counter = 0
        self._lock = threading.Lock()

        # Pending request futures: id -> (Event, result_holder_dict)
        self._pending: Dict[int, Tuple[threading.Event, dict]] = {}

        # Progress tracking for indexing
        self._index_done = threading.Event()

        # Start the reader thread
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    # ------------------------------------------------------------------
    # Wire protocol
    # ------------------------------------------------------------------

    def _send(self, obj: dict) -> None:
        """Send a JSON-RPC message with Content-Length framing."""
        body = json.dumps(obj, separators=(",", ":"))
        header = f"Content-Length: {len(body)}\r\n\r\n"
        data = (header + body).encode("utf-8")
        assert self._proc.stdin is not None
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def _reader_loop(self) -> None:
        """Background thread: read Content-Length framed messages from stdout."""
        assert self._proc.stdout is not None
        stream = self._proc.stdout
        while True:
            # Read headers until blank line
            headers: Dict[str, str] = {}
            while True:
                line = stream.readline()
                if not line:
                    return  # EOF — server exited
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    key, _, val = line_str.partition(":")
                    headers[key.strip().lower()] = val.strip()

            length = int(headers.get("content-length", "0"))
            if length <= 0:
                continue

            body = b""
            while len(body) < length:
                chunk = stream.read(length - len(body))
                if not chunk:
                    return  # EOF
                body += chunk

            try:
                msg = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                continue

            msg_id = msg.get("id")
            if msg_id is not None and not isinstance(msg.get("method"), str):
                # This is a response (has id, no method = not a request from server)
                with self._lock:
                    pending = self._pending.pop(msg_id, None)
                if pending:
                    event, holder = pending
                    holder["result"] = msg.get("result")
                    holder["error"] = msg.get("error")
                    event.set()
            else:
                # Notification or server-initiated request — handle gracefully
                self._handle_notification(msg)

    def _handle_notification(self, msg: dict) -> None:
        """Handle server-sent notifications."""
        method = msg.get("method", "")
        params = msg.get("params", {})

        if method == "$/progress":
            token = params.get("token", "")
            value = params.get("value", {})
            if token == "index" and value.get("kind") == "end":
                self._index_done.set()

        if method == "window/workDoneProgress/create":
            msg_id = msg.get("id")
            if msg_id is not None:
                self._send({"jsonrpc": "2.0", "id": msg_id, "result": None})

    def wait_for_indexing(self, timeout: float = 300.0) -> bool:
        """Block until the server signals indexing is complete."""
        return self._index_done.wait(timeout=timeout)

    # ------------------------------------------------------------------
    # Request / notify helpers
    # ------------------------------------------------------------------

    def request(self, method: str, params: Any = None) -> Any:
        """Send a JSON-RPC request and block until the response arrives.

        Raises RuntimeError on timeout or error response.
        """
        with self._lock:
            self._id_counter += 1
            req_id = self._id_counter
            event = threading.Event()
            holder: dict = {}
            self._pending[req_id] = (event, holder)

        msg: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

        if not event.wait(timeout=self._timeout):
            with self._lock:
                self._pending.pop(req_id, None)
            raise RuntimeError(
                f"LSP request '{method}' (id={req_id}) timed out "
                f"after {self._timeout}s"
            )

        if holder.get("error"):
            err = holder["error"]
            code = err.get("code", "?")
            emsg = err.get("message", "unknown error")
            raise RuntimeError(f"LSP error {code} on '{method}': {emsg}")

        return holder.get("result")

    def notify(self, method: str, params: Any = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    # ------------------------------------------------------------------
    # LSP lifecycle
    # ------------------------------------------------------------------

    def initialize(self, root_uri: str, index_threads: int = 1) -> dict:
        """Send initialize request with minimal capabilities."""
        params = {
            "processId": os.getpid(),
            "rootUri": root_uri,
            "capabilities": {
                "textDocument": {
                    "synchronization": {"didOpen": True},
                },
            },
            "initializationOptions": {
                "index": {"threads": index_threads},
                "cache": {"directory": ""},
            },
        }
        result = self.request("initialize", params)
        self.notify("initialized", {})
        return result

    def shutdown(self) -> None:
        """Send shutdown request followed by exit notification."""
        try:
            self.request("shutdown")
        except (RuntimeError, BrokenPipeError, OSError):
            pass
        try:
            self.notify("exit")
        except (BrokenPipeError, OSError):
            pass

    def did_open(self, uri: str, text: str, language_id: str = "cpp") -> None:
        """Send textDocument/didOpen notification."""
        self.notify("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": language_id,
                "version": 1,
                "text": text,
            },
        })

    def close(self) -> None:
        """Shut down the server and kill the subprocess."""
        self.shutdown()
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Custom ccle-re extensions
    # ------------------------------------------------------------------

    def ccle_dump_types(
        self,
        namespaces: List[str],
        include_prefix: str,
    ) -> dict:
        """$ccle/dumpTypes — fetch all types under the given namespaces.

        Returns the raw response dict with keys: records, enums, typedefs.
        """
        # TODO: Confirm parameter names with the actual ccle-re fork once
        # the extension is implemented.  The names below match the spec
        # in the task description.
        return self.request("$ccle/dumpTypes", {
            "namespaces": namespaces,
            "includePrefix": include_prefix,
        })

    def ccle_vtable_layout(self, qual_name: str) -> dict:
        """$ccle/vtableLayout — fetch vtable slot assignments for a class.

        Returns dict with keys: qualName, slots.
        """
        return self.request("$ccle/vtableLayout", {
            "qualName": qual_name,
        })



# ---------------------------------------------------------------------------
# Path / URI helpers
# ---------------------------------------------------------------------------

def _path_to_uri(path: str) -> str:
    """Convert a filesystem path to a file:// URI."""
    p = os.path.abspath(path).replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    return "file://" + p


# ---------------------------------------------------------------------------
# qualType → pipeline type descriptor conversion
# ---------------------------------------------------------------------------

def _qualtype_to_pipeline(qual: str) -> str:
    """Map a ccle-re qualType string to the pipeline descriptor format.

    Uses the same logic as clang_ast_collect._qualtype_to_pipeline but pulls
    from the module-level _ENUM_NAMES set populated during conversion.
    """
    stripped = re.sub(r"^(?:const|volatile)\s+", "", qual.strip())
    stripped = re.sub(r"\s+(?:const|volatile)$", "", stripped).strip()

    pipe = _record_type_to_pipeline(stripped)

    # Swap struct:→enum: for names that are actually enums.
    if pipe.startswith("struct:") and pipe[7:] in _ENUM_NAMES:
        return "enum:" + pipe[7:]
    if pipe.startswith("ptr:struct:") and pipe[11:] in _ENUM_NAMES:
        return "ptr:enum:" + pipe[11:]
    return pipe


# ---------------------------------------------------------------------------
# Response → pipeline dict converters
# ---------------------------------------------------------------------------

def _convert_enums(raw_enums: List[dict]) -> Dict[str, dict]:
    """Convert $ccle/dumpTypes .enums entries to the pipeline enum dict shape.

    Pipeline shape: {full_name: {name, full_name, size, category, values: [(name, value), ...]}}
    """
    out: Dict[str, dict] = {}
    for e in raw_enums:
        full_name = e["qualName"]
        short_name = e["shortName"]

        # Determine size from underlyingType or the explicit size field
        size = e.get("size", 4)
        if size <= 0:
            size = 4
        underlying = e.get("underlyingType", "")
        if underlying:
            prim_size = _PRIM_SIZES.get(underlying.strip())
            if prim_size:
                size = prim_size

        # Derive category from the namespace path
        # e.g. "RE::FormType" -> "/CommonLibSSE/RE"
        ns_parts = full_name.split("::")[:-1]
        category = "/CommonLibSSE/" + "/".join(ns_parts) if ns_parts else "/CommonLibSSE"

        values: List[Tuple[str, int]] = []
        for v in e.get("values", []):
            try:
                val_int = int(v["value"])
            except (TypeError, ValueError, KeyError):
                val_int = 0
            values.append((v["name"], val_int))

        _ENUM_NAMES.add(full_name)

        out[full_name] = {
            "name": short_name,
            "full_name": full_name,
            "size": size,
            "category": category,
            "values": values,
        }
    return out


def _convert_records(raw_records: List[dict]) -> Dict[str, dict]:
    """Convert $ccle/dumpTypes .records entries to the pipeline struct dict shape.

    Pipeline shape: {full_name: {name, full_name, size, category,
                     fields: [(name, offset, type_str), ...],
                     bases: [full_name, ...], has_vtable: bool}}

    Note: The raw fields from ccle-re include offset and qualType which we
    convert to pipeline descriptors.  This replaces the separate record-layout
    merge pass that the clang_ast_collect pipeline needs.
    """
    out: Dict[str, dict] = {}
    for r in raw_records:
        full_name = r["qualName"]
        short_name = r["shortName"]

        ns_parts = full_name.split("::")[:-1]
        category = "/CommonLibSSE/" + "/".join(ns_parts) if ns_parts else "/CommonLibSSE"

        bases: List[str] = []
        for b in r.get("bases", []):
            bname = b.get("qualName", "")
            if bname:
                bases.append(bname)

        fields: List[dict] = []
        field_type_hints: Dict[str, str] = {}
        for f in r.get("fields", []):
            fname = f.get("name", "")
            if not fname:
                continue
            ftype_raw = f.get("qualType", "")
            ftype = _qualtype_to_pipeline(ftype_raw)

            # TODO: ccle-re returns offset in bytes; verify this matches the
            # -fdump-record-layouts byte offsets used by the existing pipeline.
            offset = f.get("offset", 0)
            size = f.get("size", 0)

            if ftype and ftype not in ("ptr", "bytes:0"):
                field_type_hints[fname] = ftype

            fields.append({
                "name": fname,
                "type": ftype,
                "offset": offset,
                "size": size,
            })

        has_vtable = r.get("hasVTable", False)

        vmethods: Dict[str, Any] = {}
        vfuncs: List[Tuple[str, int]] = []
        for m in r.get("methods", []):
            mname = m.get("shortName", "")
            if not mname:
                continue
            if m.get("isVirtual") and mname not in vmethods:
                vmethods[mname] = (None, None)
                vi = m.get("vtableIndex", -1)
                if vi >= 0:
                    vfuncs.append((mname, vi * 8))

        vfuncs.sort(key=lambda x: x[1])

        rec_size = r.get("size", 0)
        if rec_size <= 0:
            rec_size = 1

        out[full_name] = {
            "name": short_name,
            "full_name": full_name,
            "size": rec_size,
            "category": category,
            "fields": fields,
            "field_type_hints": field_type_hints,
            "bases": bases,
            "has_vtable": has_vtable,
            "vmethods": vmethods,
            "vfuncs": vfuncs,
        }
    return out


def _convert_typedefs(
    raw_typedefs: List[dict],
    enums: Dict[str, dict],
    structs: Dict[str, dict],
) -> None:
    """Convert $ccle/dumpTypes .typedefs entries and merge into enums/structs.

    Typedef aliases are resolved against the already-populated enums and structs
    dicts, matching the deferred-resolution logic in clang_ast_collect.
    """
    for td in raw_typedefs:
        full_name = td["qualName"]
        short_name = td["shortName"]
        if full_name in enums or full_name in structs:
            continue

        target_usr = td.get("targetUsr", 0)
        target_qual = td.get("targetQualName", "")
        underlying = td.get("underlyingType", "")
        target_canonical = target_qual if target_qual else underlying

        ns_parts = full_name.split("::")[:-1]
        category = "/CommonLibSSE/" + "/".join(ns_parts) if ns_parts else "/CommonLibSSE"

        # Pointer types -> 8 bytes
        if target_canonical.endswith("*"):
            structs[full_name] = {
                "name": short_name, "full_name": full_name, "size": 8,
                "category": category, "fields": [], "bases": [],
                "has_vtable": False,
            }
            continue

        # Primitive types
        stripped = re.sub(r"^(?:const|volatile)\s+", "", target_canonical)
        stripped = re.sub(r"\s+(?:const|volatile)$", "", stripped).strip()
        prim_size = _PRIM_SIZES.get(stripped, 0)
        if prim_size > 0:
            structs[full_name] = {
                "name": short_name, "full_name": full_name, "size": prim_size,
                "category": category, "fields": [], "bases": [],
                "has_vtable": False,
            }
            continue

        # Try to resolve the target against known enums/structs.
        # TODO: The target USR from ccle-re should allow exact matching once
        # we build a USR index.  For now, use qualified-name lookup.
        resolved_enum = _lookup_by_qualname(target_canonical, enums)
        if resolved_enum:
            entry = enums[resolved_enum]
            enums[full_name] = {
                "name": short_name,
                "full_name": full_name,
                "size": entry["size"],
                "category": category,
                "values": list(entry["values"]),
            }
            continue

        resolved_struct = _lookup_by_qualname(target_canonical, structs)
        if resolved_struct:
            entry = structs[resolved_struct]
            structs[full_name] = {
                "name": short_name,
                "full_name": full_name,
                "size": entry.get("size", 0),
                "category": category,
                "fields": [],
                "bases": [],
                "has_vtable": False,
            }
            continue

        # TODO: If the target is a template instantiation not yet in structs,
        # defer and retry after the template engine runs — matching the
        # _TYPEDEF_ALIASES / resolve_deferred_typedef_aliases pattern in
        # clang_ast_collect.


def _lookup_by_qualname(target: str, dct: Dict[str, dict]) -> Optional[str]:
    """Look up a type by qualified name, stripping class/struct/enum keywords."""
    t = re.sub(r"\b(?:class|struct|union|enum)\s+", "", target).strip()
    if t in dct:
        return t
    # Short-name fallback (unique match only)
    short = t.split("::")[-1]
    hits = [k for k in dct if k.split("::")[-1] == short]
    if len(hits) == 1:
        return hits[0]
    return None


# ---------------------------------------------------------------------------
# High-level API — drop-in replacement for clang_ast_collect.collect_types
# ---------------------------------------------------------------------------

def _write_compile_commands(
    skyrim_h: str, parse_args: List[str], root_dir: str
) -> str:
    """Write a compile_commands.json for ccle-re at the project root."""
    import json as _json

    cmd_parts = ["clang++"] + parse_args + ["-c", skyrim_h.replace("\\", "/")]
    cc = [{
        "directory": root_dir.replace("\\", "/"),
        "command": " ".join(cmd_parts),
        "file": skyrim_h.replace("\\", "/"),
    }]
    cc_path = os.path.join(root_dir, "compile_commands.json")
    with open(cc_path, "w") as f:
        _json.dump(cc, f, indent=2)
    return cc_path


def collect_types(
    skyrim_h: str,
    parse_args: List[str],
    re_include: str,
    verbose: bool = False,
    index_wait: float = 60.0,
) -> Tuple[dict, dict]:
    """Drop-in replacement for clang_ast_collect.collect_types().

    Returns (enums, structs) dicts matching the pipeline shape:
        enums:   {full_name: {name, full_name, size, category, values: [(name, value), ...]}}
        structs: {full_name: {name, full_name, size, category,
                  fields: [{name, type, offset, size}, ...],
                  field_type_hints: {name: type_str},
                  bases: [full_name, ...], has_vtable: bool}}

    Uses ccle-re's $ccle/dumpTypes extension instead of spawning multiple
    clang.exe JSON AST + record layout passes.
    """
    import time as _time

    binary = find_ccle_binary()
    if not binary:
        raise RuntimeError(
            "ccle-re binary not found.  Place it on PATH or build at "
            f"{_CCLE_FALLBACK_PATH}"
        )

    _ENUM_NAMES.clear()

    root_dir = os.path.dirname(re_include)
    root_uri = _path_to_uri(root_dir)

    if verbose:
        print(f"  [ccle-re] launching {binary}")
        print(f"  [ccle-re] root: {root_dir}")

    cc_path = _write_compile_commands(skyrim_h, parse_args, root_dir)
    cc_cleanup = True

    try:
        client = LspClient(binary, timeout=300.0)
        try:
            client.initialize(root_uri, index_threads=4)

            if verbose:
                print(f"  [ccle-re] waiting for indexing (timeout={index_wait:.0f}s)...")
            if not client.wait_for_indexing(timeout=index_wait):
                if verbose:
                    print("  [ccle-re] indexing wait done (progress signal not received, "
                          "may have completed before tracking started)")

            if verbose:
                print("  [ccle-re] requesting $ccle/dumpTypes...")

            response = client.ccle_dump_types(
                namespaces=["RE", "REX", "REL"],
                include_prefix=re_include.replace("\\", "/"),
            )

            raw_enums = response.get("enums", [])
            raw_records = response.get("records", [])
            raw_typedefs = response.get("typedefs", [])

            enums = _convert_enums(raw_enums)
            structs = _convert_records(raw_records)
            _convert_typedefs(raw_typedefs, enums, structs)

            if verbose:
                print(f"  [ccle-re] collected {len(enums)} enums, {len(structs)} structs")

        finally:
            client.close()
    finally:
        if cc_cleanup:
            try:
                os.remove(cc_path)
            except OSError:
                pass

    return enums, structs


