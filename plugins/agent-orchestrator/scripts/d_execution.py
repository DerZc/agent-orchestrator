#!/usr/bin/env python3
"""D1 managed-execution facts, contracts, admission and attempt evidence.

This module is loaded by ``cli_agent_job.py`` through an absolute-path import,
matching the B1/B2/C pattern. It owns one narrow, versioned append-only
execution-fact journal inside the existing managed plan directory::

    <plan>/execution/events/NNNNNN.json
    <plan>/execution/blobs/<sha256>

The journal never duplicates B1 consensus truth. Every event references the
immutable B1 plan, step, cycle and candidate, and every composite eligibility
check or append uses B1's one existing plan lock. Content-addressed blobs are
published and fsynced before any event that references them, so a crash can
leave an unreferenced blob but never an event pointing at missing evidence.

D1 stops at ``IMPLEMENTATION_COMPLETE``. Review acceptance, formal repair
dispatch, independent validation execution, PR/CI/MERGED completion and
dependency opening are structurally closed; no function in this module can
mint them. Recovery is evidence-driven: recorded facts and hashes are
re-validated, never reinterpreted by wall-clock or exit-only inference.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

EXECUTION_VERSION = 1
JOURNAL_VERSION = 1
EVENT_FILE_RE = re.compile(r"^[0-9]{6}\.json$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_EVENT_BYTES = 65_536
MAX_BLOB_BYTES = 64 * 1024 * 1024
MAX_JOB_FILE_BYTES = 64 * 1024 * 1024
MAX_TASK_BYTES = 1_000_000
MAX_CONTRACT_BYTES = 65_536
MAX_TEXT_BYTES = 8_192
MAX_LIST_ITEMS = 64
MAX_PATH_LIST = 200
MAX_REPORT_PATHS = 4_000
MAX_PROTECTED_OBSERVATION_PATHS = 4_000
PROTECTION_VERSION = 1
MAX_PROTECTED_ROOTS = 256
MAX_ANCESTOR_ANCHORS = 1_024
MAX_EXTRA_MOUNT_ARGV_BYTES = 128 * 1024
MAX_MUTABLE_STAT_PATHS = 100_000
MAX_PROTECTION_REFINEMENT_DEPTH = 8
DEFAULT_INVOCATION_LIMIT = 3
FORMAL_REPAIR_LIMIT = 3
ZERO_DIGEST = "0" * 64

SLOT_ROUNDS = {1: "proposal", 2: "cross_examination", 3: "consensus"}
READONLY_OPERATIONS = {"proposal", "cross_examination", "consensus"}

CLOSED_GATES = {
    "review_acceptance": "CLOSED_UNTIL_D2",
    "formal_repair": "CLOSED_UNTIL_D2",
    "independent_validation": "CLOSED_UNTIL_D2",
    "pr_ci_merged": "CLOSED_UNTIL_E",
    "dependency_opening": "CLOSED_UNTIL_E",
}

TYPE_ASSIGNMENT = "discussion_assignment"
TYPE_EVIDENCE = "discussion_evidence"
TYPE_CONTRACT = "contract_frozen"
TYPE_INTENT = "implementation_intent"
TYPE_CLAIM = "implementation_claim"
TYPE_RESULT = "invocation_result"
TYPE_COMPLETE = "implementation_complete"
TYPE_BLOCKED = "implementation_blocked"
TYPE_CONTINUATION = "continuation_authorized"
TYPE_ABORTED = "implementation_aborted"

# D2 facts live in the same append-only journal under separate reducer
# namespaces. They never carry a top-level writer ``attempt_id``; their own
# IDs and reference fields are validated by the D2 event schema hook.
TYPE_VALIDATION_INTENT = "validation_intent"
TYPE_VALIDATION_CLAIM = "validation_claim"
TYPE_VALIDATION_RESULT = "validation_result"
TYPE_VALIDATION_PREFLIGHT = "validation_preflight"
TYPE_REVIEW_SESSION = "review_session"
TYPE_REVIEW = "independent_review"
TYPE_REPAIR_CONTRACT = "repair_contract"
TYPE_REPAIR_ALLOCATION = "repair_allocation"
TYPE_REPAIR_SETUP = "repair_setup_attempt"
TYPE_DESIGN_LINK = "design_link"

D2_EVENT_TYPES = {
    TYPE_VALIDATION_INTENT,
    TYPE_VALIDATION_CLAIM,
    TYPE_VALIDATION_RESULT,
    TYPE_VALIDATION_PREFLIGHT,
    TYPE_REVIEW_SESSION,
    TYPE_REVIEW,
    TYPE_REPAIR_CONTRACT,
    TYPE_REPAIR_ALLOCATION,
    TYPE_REPAIR_SETUP,
    TYPE_DESIGN_LINK,
}

EVENT_TYPES = {
    TYPE_ASSIGNMENT,
    TYPE_EVIDENCE,
    TYPE_CONTRACT,
    TYPE_INTENT,
    TYPE_CLAIM,
    TYPE_RESULT,
    TYPE_COMPLETE,
    TYPE_BLOCKED,
    TYPE_CONTINUATION,
    TYPE_ABORTED,
    *D2_EVENT_TYPES,
}

D2_JOURNAL_LISTS = {
    TYPE_VALIDATION_INTENT: "validation_intents",
    TYPE_VALIDATION_CLAIM: "validation_claims",
    TYPE_VALIDATION_RESULT: "validation_results",
    TYPE_VALIDATION_PREFLIGHT: "validation_preflights",
    TYPE_REVIEW_SESSION: "review_sessions",
    TYPE_REVIEW: "reviews",
    TYPE_REPAIR_CONTRACT: "repair_contracts",
    TYPE_REPAIR_ALLOCATION: "repair_allocations",
    TYPE_REPAIR_SETUP: "repair_setups",
    TYPE_DESIGN_LINK: "design_links",
}

_HOOKS: dict[str, Any] = {}


def configure(**hooks: Any) -> None:
    """Install runner-provided hooks. Safe to call repeatedly."""
    _HOOKS.update(hooks)


def _hook(name: str) -> Any:
    try:
        return _HOOKS[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise RuntimeError(f"d_execution is not configured: missing {name}") from exc


def _error(message: str) -> Exception:
    return _hook("runner_error")(message)


def _fail(message: str) -> None:
    raise _error(message)


def _b1() -> Any:
    return _hook("b1_module")()


def _b2() -> Any:
    return _hook("b2_module")()


def _c() -> Any:
    return _hook("c_module")()


def _now() -> str:
    return _hook("utc_now")()


def _plans_dir() -> Path:
    return Path(_hook("plans_dir")())


def _plan_dir(plan_id: str) -> Path:
    path = _hook("plan_dir")(plan_id, must_exist=False)
    return Path(path)


def _jobs_dir() -> Path:
    return Path(_hook("jobs_dir")())


def _read_json(path: Path) -> dict[str, Any]:
    value = _hook("read_json")(path)
    if not isinstance(value, dict):
        _fail(f"Expected a JSON object in {path}")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _require_directory(path: Path, label: str) -> None:
    """Require an existing real directory, never a symlink."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        _fail(f"{label} is unavailable at {path}: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(f"{label} is not a regular directory: {path}")


def _ensure_child_directory(parent: Path, name: str, label: str) -> Path:
    """Create one journal directory and durably publish its parent entry.

    The parent fsync is unconditional: a concurrent creator may have published
    the directory entry but crashed before syncing its parent, and the first
    fact/reference acknowledgement must not depend on that writer's timing.
    Creation remains idempotent; every failure propagates as a fail-closed
    runner error before provider authority is granted.
    """
    path = parent / name
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        _fail(f"Cannot create the {label} directory {path}: {exc}")
    _require_directory(path, label)
    try:
        _fsync_dir(parent)
    except OSError as exc:
        _fail(f"Cannot durably publish the {label} directory entry in {parent}: {exc}")
    return path


def _ensure_execution_dir(plan_id: str) -> Path:
    plan_dir = _plan_dir(plan_id)
    _require_directory(plan_dir, "managed plan directory")
    return _ensure_child_directory(
        plan_dir, "execution", "execution journal"
    )


def _ensure_events_dir(plan_id: str) -> Path:
    execution = _ensure_execution_dir(plan_id)
    return _ensure_child_directory(execution, "events", "execution events")


def _ensure_blobs_dir(plan_id: str) -> Path:
    execution = _ensure_execution_dir(plan_id)
    return _ensure_child_directory(execution, "blobs", "execution blobs")


def _execution_dir(plan_id: str) -> Path:
    return _plan_dir(plan_id) / "execution"


def _events_dir(plan_id: str) -> Path:
    return _execution_dir(plan_id) / "events"


def _blobs_dir(plan_id: str) -> Path:
    return _execution_dir(plan_id) / "blobs"


def _published_event_files(plan_id: str) -> list[Path]:
    directory = _events_dir(plan_id)
    if not directory.is_dir():
        return []
    files: list[Path] = []
    for item in sorted(directory.iterdir(), key=lambda candidate: candidate.name):
        if item.name.startswith("."):
            continue
        if (
            not EVENT_FILE_RE.fullmatch(item.name)
            or item.is_symlink()
            or not item.is_file()
        ):
            _fail(f"Unexpected execution journal entry: {item}")
        files.append(item)
    return files


def _write_event_file(plan_id: str, path: Path, event: dict[str, Any]) -> None:
    # Durably establish plan -> execution -> events before the first event
    # entry is acknowledged. The final directory fsync below covers the file.
    _ensure_events_dir(plan_id)
    if path.exists():
        _fail(f"Refusing to replace published execution event {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}-{os.urandom(4).hex()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(event, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        _fsync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _read_blob(plan_id: str, sha: Any, label: str) -> bytes:
    if not isinstance(sha, str) or not DIGEST_RE.fullmatch(sha):
        _fail(f"{label} has an invalid content-addressed blob digest")
    path = _blobs_dir(plan_id) / sha
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        _fail(f"{label} references a missing execution evidence blob: {sha}")
    except OSError as exc:
        _fail(f"{label} cannot inspect execution evidence blob {sha}: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail(f"{label} references a non-regular execution evidence blob: {sha}")
    if info.st_size > MAX_BLOB_BYTES:
        _fail(f"{label} references an oversized execution evidence blob: {sha}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        _fail(f"{label} cannot read execution evidence blob {sha}: {exc}")
    if _sha256_bytes(data) != sha:
        _fail(f"{label} references a corrupt execution evidence blob: {sha}")
    return data


def _publish_blob(plan_id: str, data: bytes, label: str) -> str:
    if len(data) > MAX_BLOB_BYTES:
        _fail(f"{label} exceeds the {MAX_BLOB_BYTES}-byte execution blob bound")
    sha = _sha256_bytes(data)
    # Durably establish plan -> execution -> blobs before any event may
    # reference this content-addressed evidence.
    directory = _ensure_blobs_dir(plan_id)
    path = directory / sha
    if path.exists():
        # Content-addressed evidence is never replaced. An existing blob with
        # different bytes is corruption and must fail closed. The directory is
        # synced even here because a previous publisher may have crashed
        # between publishing the entry and syncing its parent; this retry only
        # acknowledges a reference after that entry is durable.
        existing = _read_blob(plan_id, sha, label)
        if existing != data:
            _fail(f"{label} collides with existing execution evidence blob {sha}")
        try:
            _fsync_dir(directory)
        except OSError as exc:
            _fail(
                f"Cannot durably acknowledge existing execution evidence blob "
                f"{sha} in {directory}: {exc}"
            )
        return sha
    temp = directory / f".{sha}.{os.getpid()}-{os.urandom(4).hex()}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            existing = _read_blob(plan_id, sha, label)
            if existing != data:
                _fail(f"{label} collides with existing execution evidence blob {sha}")
        _fsync_dir(directory)
    finally:
        temp.unlink(missing_ok=True)
    return sha


def _publish_json_blob(
    plan_id: str, value: Any, label: str
) -> tuple[str, str]:
    data = _canonical_bytes(value)
    return _publish_blob(plan_id, data, label), _sha256_bytes(data)


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        _fail(f"{label} must be a valid identifier")
    return value


def _text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    stripped = value.strip()
    if len(stripped) < minimum:
        _fail(f"{label} must contain at least {minimum} substantive characters")
    if len(stripped.encode("utf-8")) > MAX_TEXT_BYTES:
        _fail(f"{label} exceeds {MAX_TEXT_BYTES} bytes")
    if "\x00" in stripped:
        _fail(f"{label} contains a NUL byte")
    return stripped


def _text_list(
    value: Any,
    label: str,
    *,
    minimum_items: int = 1,
    maximum_items: int = MAX_LIST_ITEMS,
    minimum_chars: int = 1,
) -> list[str]:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array of strings")
    if not minimum_items <= len(value) <= maximum_items:
        _fail(
            f"{label} must contain between {minimum_items} and "
            f"{maximum_items} items"
        )
    return [
        _text(item, f"{label}[{index}]", minimum_chars)
        for index, item in enumerate(value)
    ]


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        _fail(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        _fail(f"{label} has unknown fields: {', '.join(extra)}")
    return value


def _optional_keys(
    value: Any, required: set[str], optional: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required - optional)
    if missing:
        _fail(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        _fail(f"{label} has unknown fields: {', '.join(extra)}")
    return value


def _operation_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not OP_ID_RE.fullmatch(value):
        _fail(f"{label} must be a valid operation identifier")
    return value


def _next_operation(base: str, request_digest: str) -> str:
    # Operation IDs are bounded to 64 characters; the request digest keeps the
    # deterministic prefix unique without embedding unbounded user content.
    return f"{base}-{request_digest[:32]}"


def _process_probe(record: Any) -> str:
    return str(_b2().process_probe(record))


def _pid_record(meta: dict[str, Any], pid_key: str, start_key: str) -> dict[str, Any] | None:
    pid = meta.get(pid_key)
    if pid is None:
        return None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        _fail(f"Job evidence has an invalid {pid_key}")
    start = meta.get(start_key)
    if start is not None and not isinstance(start, str):
        _fail(f"Job evidence has an invalid {start_key}")
    return {"pid": pid, "start": start}


def _require_processes_dead(meta: dict[str, Any], label: str) -> None:
    """Require every recorded job process to be provably gone.

    A zombie is dead. A live or unprobeable identity fails closed; capturing a
    PID that is still running never authorizes ingestion or completion.
    """
    for pid_key, start_key in (
        ("worker_pid", "worker_start"),
        ("provider_pid", "provider_start"),
        ("child_pid", "provider_start"),
        ("supervisor_pid", "supervisor_start"),
    ):
        record = _pid_record(meta, pid_key, start_key)
        if record is None:
            continue
        probe = _process_probe(record)
        if probe != "dead":
            _fail(
                f"{label} cannot be ingested while recorded {pid_key} "
                f"pid {record['pid']} is {probe}"
            )


def _snapshot_signature(snapshot: Any) -> dict[str, Any]:
    """Return the deterministic workspace-context identity of a B2 snapshot."""
    if not isinstance(snapshot, dict) or not snapshot.get("supported"):
        _fail(
            "Execution evidence requires a supported workspace snapshot: "
            + str((snapshot or {}).get("unsupported_reason"))
        )
    entries = snapshot.get("entries") or {}
    if not isinstance(entries, dict):
        _fail("Workspace snapshot entries are malformed")
    entry_signatures = {
        path: [
            entry.get("kind"),
            entry.get("sha256"),
            entry.get("size"),
            entry.get("mode"),
        ]
        for path, entry in sorted(entries.items())
        if isinstance(entry, dict)
    }
    status = snapshot.get("status_entries") or []
    if not isinstance(status, list):
        _fail("Workspace snapshot status is malformed")
    status_signature = sorted(
        [
            str(entry.get("status")),
            str(entry.get("path")),
            str(entry.get("orig_path") or ""),
        ]
        for entry in status
        if isinstance(entry, dict)
    )
    index = snapshot.get("index") or {}
    staged = snapshot.get("staged") or {}
    return {
        "version": snapshot.get("version"),
        "head": snapshot.get("head"),
        "branch": snapshot.get("branch"),
        "detached": snapshot.get("detached"),
        "index_exists": bool(index.get("exists")),
        "index_sha256": index.get("sha256"),
        "status": status_signature,
        "staged": {
            "entries": staged.get("entries") if isinstance(staged, dict) else {},
            "renames": staged.get("renames") if isinstance(staged, dict) else [],
        },
        "entries": entry_signatures,
        "untracked": sorted(snapshot.get("untracked_paths") or []),
    }


def _snapshot_digest(snapshot: dict[str, Any]) -> str:
    return _digest(_snapshot_signature(snapshot))


def _user_baseline_digest(snapshot: dict[str, Any]) -> str:
    signature = _snapshot_signature(snapshot)
    return _digest(
        {
            "index_exists": signature["index_exists"],
            "index_sha256": signature["index_sha256"],
            "staged": signature["staged"],
            "entries": _user_entries(snapshot),
        }
    )


def _scope_for_contract(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "allowed_paths": list(contract.get("allowed_paths") or []),
        "denied_paths": list(contract.get("denied_paths") or []),
        "max_changed_files": contract.get("max_changed_files"),
    }


def _tracked_paths(workspace: Path, paths: list[str]) -> set[str]:
    """Return which concrete paths are clean tracked/index entries.

    B2 snapshots include the task scope even when those paths are clean, so a
    plain entry diff cannot tell an approved task edit from an overwritten user
    file. A read-only ``git ls-files --cached`` classification distinguishes
    clean tracked content (the approved writer scope) from dirty, untracked or
    ignored pre-existing bytes (the protected user baseline).
    """
    tracked: set[str] = set()
    if not paths:
        return tracked
    for start in range(0, len(paths), 400):
        batch = paths[start : start + 400]
        data = _git_capture(
            workspace,
            [
                "--literal-pathspecs",
                "ls-files",
                "-z",
                "--cached",
                "--",
                *batch,
            ],
            "tracked-path classification",
        )
        for item in data.split(b"\0"):
            if item:
                tracked.add(os.fsdecode(item))
    return tracked


def _decode_hidden_index(
    data: bytes, label: str
) -> dict[str, str]:
    hidden: dict[str, str] = {}
    for item in data.split(b"\0"):
        if not item:
            continue
        if len(item) < 3 or item[1:2] != b" ":
            _fail(f"Malformed output from {label}")
        tag = item[:1]
        path = _observation_path(item[2:], label)
        if tag != b"H":
            hidden[path] = "assume-unchanged" if tag.islower() else "skip-worktree"
    return hidden


def _hidden_index_paths(
    workspace: Path, paths: list[str]
) -> dict[str, str]:
    """Classify paths carrying assume-unchanged or skip-worktree index bits.

    Git status deliberately hides work-tree differences for these entries, so
    tracked membership alone cannot prove that their bytes are clean. The
    classification is read-only: no flag is cleared and the real index is never
    rewritten.
    """
    hidden: dict[str, str] = {}
    if not paths:
        return hidden
    for start in range(0, len(paths), 400):
        batch = paths[start : start + 400]
        data = _git_capture(
            workspace,
            [
                "--literal-pathspecs",
                "ls-files",
                "-v",
                "-z",
                "--cached",
                "--",
                *batch,
            ],
            "hidden index flag classification",
        )
        hidden.update(_decode_hidden_index(data, "hidden index flag classification"))
    return hidden


def _observation_path(value: bytes, label: str) -> str:
    path = os.fsdecode(value)
    if not path or path.startswith("/") or "\x00" in path:
        _fail(f"{label} returned an absolute or invalid workspace path")
    if any(part == ".." for part in Path(path).parts):
        _fail(f"{label} returned a workspace-escaping path")
    return path


def _bounded_protected_paths(paths: set[str], label: str) -> list[str]:
    ordered = sorted(paths)
    if len(ordered) > MAX_PROTECTED_OBSERVATION_PATHS:
        _fail(
            f"{label} exceeds the {MAX_PROTECTED_OBSERVATION_PATHS}-path "
            "protected-observation bound; this workspace structure is unsupported "
            "for a managed writer"
        )
    return ordered


def _ignored_root_entries(workspace: Path) -> list[tuple[str, bool]]:
    """Enumerate ignored work-tree entries at Git's directory level.

    ``--directory`` collapses an ignored tree to its top-level directory entry,
    so a 50,000-entry ``.venv`` or a huge cache is represented by one path.  No
    file content is read and no global ignored-content census is built.  The
    256-root bound applies later during manifest derivation; overflow is an
    explicit refusal, never truncation.
    """
    data = _git_capture(
        workspace,
        [
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
        ],
        "ignored protected roots",
    )
    entries: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for item in data.split(b"\0"):
        if not item:
            continue
        is_directory = item.endswith(b"/")
        raw = item[:-1] if is_directory else item
        path = _observation_path(raw, "ignored protected roots")
        if path in seen:
            continue
        seen.add(path)
        entries.append((path, is_directory))
    return entries


def _all_hidden_index_paths(workspace: Path) -> list[str]:
    """Enumerate every tracked path whose index entry hides work-tree state."""
    data = _git_capture(
        workspace,
        ["ls-files", "-v", "-z", "--cached"],
        "hidden index protected baseline",
    )
    hidden = _decode_hidden_index(data, "hidden index protected baseline")
    return _bounded_protected_paths(
        set(hidden), "hidden index protected baseline"
    )


def _protected_observation_paths(workspace: Path) -> list[str]:
    """Return the pre-existing hidden-index observation set.

    Ignored trees are deliberately absent: they are protected by read-only
    mount identity instead of being hashed recursively.  Only hidden-index
    tracked files, whose status bytes are otherwise unknowable, enter B2's
    bounded raw-hash observation.
    """
    return _bounded_protected_paths(
        set(_all_hidden_index_paths(workspace)),
        "protected observation baseline",
    )


def implementation_observation_paths(
    workspace: Path, scope: dict[str, Any] | None
) -> list[str]:
    """Observation extras shared by launch, intent, claim and worker checks.

    The launch-side B2 snapshot and every D1 observation must use the exact
    same path set so their content digests are comparable.
    """
    path = Path(workspace).expanduser()
    extras = set(_b2().scope_observation_paths(path, scope))
    extras.update(_protected_observation_paths(path))
    return _bounded_protected_paths(extras, "implementation observation")


def _status_related_paths(snapshot: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for key in ("dirty_paths", "untracked_paths"):
        values = snapshot.get(key)
        if isinstance(values, list):
            paths.update(item for item in values if isinstance(item, str))
    for entry in snapshot.get("status_entries") or []:
        if not isinstance(entry, dict):
            continue
        for key in ("path", "orig_path"):
            value = entry.get(key)
            if isinstance(value, str) and value:
                paths.add(value)
    staged = snapshot.get("staged")
    if isinstance(staged, dict):
        entries = staged.get("entries")
        if isinstance(entries, dict):
            paths.update(item for item in entries if isinstance(item, str))
        for rename in staged.get("renames") or []:
            if isinstance(rename, dict):
                for key in ("from", "to"):
                    if isinstance(rename.get(key), str):
                        paths.add(rename[key])
    return paths


def _fallback_user_entries(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Derive protected entries for snapshots created before annotation.

    The fallback deliberately protects every pre-existing dirty, untracked and
    staged path. It cannot distinguish ignored scope observations, so every
    new observation is annotated instead.
    """
    entries = snapshot.get("entries") or {}
    if not isinstance(entries, dict):
        return {}
    related = _status_related_paths(snapshot)
    return {
        path: entry
        for path, entry in entries.items()
        if path in related and isinstance(entry, dict)
    }


def _annotate_user_baseline(
    snapshot: dict[str, Any], workspace: Path
) -> dict[str, Any]:
    """Classify pre-existing bytes independently of status-only membership.

    A clean ``git status`` does not prove that a tracked entry's work-tree
    bytes are clean when the index entry carries assume-unchanged or
    skip-worktree. Those entries are protected exactly like dirty, untracked,
    ignored or staged content. A genuinely missing path has no bytes to
    protect, so it stays writable through an approved scope unless a hidden
    index flag makes its status unknowable.
    """
    entries = snapshot.get("entries") or {}
    if not isinstance(entries, dict):
        _fail("Workspace snapshot entries are malformed")
    related = _status_related_paths(snapshot)
    candidates = sorted(set(entries) - related)
    tracked = _tracked_paths(workspace, candidates)
    hidden = _hidden_index_paths(workspace, sorted(entries))
    protected: dict[str, Any] = {}
    for path, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        if path in hidden:
            protected[path] = entry
        elif entry.get("kind") == "missing":
            continue
        elif path in related or path not in tracked:
            protected[path] = entry
    snapshot["user_baseline_entries"] = protected
    snapshot["hidden_index_paths"] = sorted(hidden)
    return snapshot


def _annotated_snapshot(
    snapshot: dict[str, Any], workspace: Path
) -> dict[str, Any]:
    """Return a snapshot carrying protected-baseline classification.

    Launch-side snapshots are produced by B2 and shared with later job
    metadata, so the classification is added to a shallow copy rather than
    mutating the caller's evidence object.
    """
    if isinstance(snapshot.get("user_baseline_entries"), dict):
        return snapshot
    annotated = dict(snapshot)
    return _annotate_user_baseline(annotated, workspace)


def _user_entries(snapshot: dict[str, Any]) -> dict[str, Any]:
    annotated = snapshot.get("user_baseline_entries")
    if isinstance(annotated, dict):
        return annotated
    return _fallback_user_entries(snapshot)


def _require_no_protected_scope_overlap(
    snapshot: dict[str, Any], contract: dict[str, Any], label: str
) -> None:
    """Refuse a fresh writer when protected pre-existing bytes sit in scope.

    This check does not rely on ``git status``: dirty, untracked, ignored,
    staged and hidden-index entries are all part of the protected baseline.
    Unrelated protected bytes are preserved and remain outside the writer's
    approved scope. Same-attempt continuation deliberately skips this gate
    because its residue was already classified by the coordinator and bound to
    the exact continuation snapshot digest.
    """
    allowed = [str(value) for value in (contract.get("allowed_paths") or []) if value]
    protected = _user_entries(snapshot)
    overlap = sorted(
        path
        for path in protected
        if any(fnmatch.fnmatch(path, pattern) for pattern in allowed)
    )
    if not overlap:
        return
    hidden = set(snapshot.get("hidden_index_paths") or [])
    details = ", ".join(
        path + (" (hidden index flag)" if path in hidden else "")
        for path in overlap[:20]
    )
    _fail(
        f"{label}: pre-existing protected user content overlaps the writer's "
        f"approved scope: {details}. Refusing writer admission before provider "
        "startup; hidden index flags are not cleared and their bytes are not "
        "adopted as clean"
    )


def _protection_pattern_prefix(pattern: str) -> str:
    indexes = [pattern.find(char) for char in "*?[" if char in pattern]
    head = pattern[: min(indexes)] if indexes else pattern
    return head.rsplit("/", 1)[0] if "/" in head else ""


def _protection_path_matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _protection_patterns_intersect(
    path: str, is_directory: bool, patterns: list[str]
) -> bool:
    """Return whether an approved writable pattern can reach into a path.

    This is structural pattern logic, not a write attempt: a literal pattern
    below a protected directory, or a glob whose static prefix is at/below it,
    means the directory cannot be collapsed into a single read-only root.
    """
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
        has_glob = any(char in pattern for char in "*?[")
        prefix = _protection_pattern_prefix(pattern) if has_glob else pattern
        if is_directory:
            if prefix == path or prefix.startswith(path + "/"):
                return True
        else:
            if not has_glob and path == pattern:
                return True
    return False


def _tracked_child_prefixes(
    workspace: Path, child_paths: list[str]
) -> set[str]:
    """Return which direct children contain tracked work-tree entries."""
    if not child_paths:
        return set()
    data = _git_capture(
        workspace,
        ["--literal-pathspecs", "ls-files", "-z", "--cached", "--", *child_paths],
        "protected root refinement tracked classification",
    )
    tracked: set[str] = set()
    for item in data.split(b"\0"):
        if not item:
            continue
        path = _observation_path(
            item, "protected root refinement tracked classification"
        )
        for child in child_paths:
            if path == child or path.startswith(child + "/"):
                tracked.add(child)
                break
    return tracked


def _refine_ignored_root(
    workspace: Path,
    root_path: str,
    allowed: list[str],
    *,
    depth: int,
    budget: dict[str, int],
) -> list[tuple[str, bool, str]]:
    """Bounded refinement of an ignored directory that meets writable paths.

    Git's ``--directory`` form can collapse a whole ignored parent even when a
    currently missing approved writable path lives beneath it.  Direct children
    are therefore classified from the filesystem plus a read-only tracked-set
    query: ignored/untracked children are protected individually (or refined
    recursively), clean tracked children stay writable, and exceeding the bound
    is an explicit refusal.
    """
    if depth > MAX_PROTECTION_REFINEMENT_DEPTH:
        _fail(
            "protected ignored root refinement exceeds the bounded depth; "
            f"the mixed layout at {root_path!r} is unsupported"
        )
    target = workspace / root_path
    try:
        with os.scandir(target) as iterator:
            entries = sorted(
                ((entry.name, entry) for entry in iterator),
                key=lambda item: item[0],
            )
    except OSError as exc:
        _fail(f"Cannot enumerate protected ignored root {root_path}: {exc}")
    if len(entries) > MAX_PROTECTED_ROOTS * 4:
        _fail(
            "protected ignored root refinement exceeds its bounded entry count "
            f"at {root_path!r}; the mixed layout is unsupported"
        )
    child_paths = [
        root_path + "/" + name for name, _entry in entries if name not in {".", ".."}
    ]
    tracked = _tracked_child_prefixes(workspace, child_paths)
    refined: list[tuple[str, bool, str]] = []
    for (name, entry), path in zip(entries, child_paths):
        budget["refined"] += 1
        if budget["refined"] > MAX_PROTECTED_ROOTS * 4:
            _fail(
                "protected ignored root refinement exceeds its bounded entry "
                f"count at {root_path!r}; the mixed layout is unsupported"
            )
        is_directory = entry.is_dir(follow_symlinks=False)
        is_tracked = path in tracked
        if not is_directory and is_tracked:
            # Public clean tracked source (or a dirty tracked file already
            # protected through the observed user baseline) stays writable.
            continue
        if _protection_path_matches(path, allowed):
            if is_tracked and not is_directory:
                continue
            _fail(
                "implementation intent: pre-existing protected user content "
                f"overlaps the writer's approved scope: {path}. Refusing writer "
                "admission before provider startup; protected bytes are never "
                "reopened or adopted as clean"
            )
        if is_directory and _protection_patterns_intersect(path, True, allowed):
            refined.extend(
                _refine_ignored_root(
                    workspace,
                    path,
                    allowed,
                    depth=depth + 1,
                    budget=budget,
                )
            )
            continue
        if not is_directory and _protection_patterns_intersect(
            path, False, allowed
        ):
            if is_tracked:
                continue
            _fail(
                "implementation intent: pre-existing protected user content "
                f"overlaps the writer's approved scope: {path}"
            )
        refined.append((path, is_directory, "ignored"))
    return refined


def _collect_protected_roots(
    workspace: Path,
    snapshot: dict[str, Any],
    contract: dict[str, Any],
    known_owned: list[str] | tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Derive original protected-user roots without an ignored-content census.

    Dirty, untracked, staged and hidden-index content is protected as concrete
    paths.  Ignored content is enumerated at Git's directory level: a disjoint
    ignored tree becomes one read-only root, while a root that meets an
    approved writable path is refined or refused before startup.
    """
    allowed = [
        str(value) for value in (contract.get("allowed_paths") or []) if value
    ]
    entries = snapshot.get("entries") or {}
    owned_paths = {
        str(path) for path in known_owned if isinstance(path, str) and path
    }

    def is_owned(path: str) -> bool:
        if path in owned_paths:
            return True
        return any(
            path.startswith(owned.rstrip("/") + "/") for owned in owned_paths
        )

    candidates: list[tuple[str, bool, str]] = []
    user_entries = _user_entries(snapshot)
    for path, entry in sorted(user_entries.items()):
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") == "missing":
            continue
        if is_owned(path):
            # A formal repair's exact attributed parent delta is owned source,
            # never original user bytes.
            continue
        candidates.append(
            (path, entry.get("kind") == "directory", "user_baseline")
        )
    hidden_paths = sorted(
        set(snapshot.get("hidden_index_paths") or [])
        | set(_all_hidden_index_paths(workspace))
    )
    for path in hidden_paths:
        target = workspace / path
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _fail(f"Cannot inspect hidden-index protected path {path}: {exc}")
        candidates.append(
            (path, stat.S_ISDIR(info.st_mode), "hidden_index")
        )
    budget = {"refined": 0}
    for path, is_directory in _ignored_root_entries(workspace):
        if _protection_path_matches(path, allowed):
            _fail(
                "implementation intent: pre-existing protected user content "
                f"overlaps the writer's approved scope: {path}. Refusing writer "
                "admission before provider startup; ignored bytes are never "
                "adopted as clean"
            )
        if is_directory and _protection_patterns_intersect(path, True, allowed):
            candidates.extend(
                _refine_ignored_root(
                    workspace,
                    path,
                    allowed,
                    depth=0,
                    budget=budget,
                )
            )
            continue
        if not is_directory and _protection_patterns_intersect(
            path, False, allowed
        ):
            _fail(
                "implementation intent: pre-existing protected user content "
                f"overlaps the writer's approved scope: {path}"
            )
        candidates.append((path, is_directory, "ignored"))
    candidates.sort(key=lambda item: (item[0], item[2]))
    kept: list[dict[str, Any]] = []
    directory_prefixes: list[str] = []
    seen: set[str] = set()
    for path, is_directory, source in candidates:
        if path in seen:
            continue
        covered = any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in directory_prefixes
        )
        if covered:
            continue
        target = workspace / path
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            _fail(
                f"Protected user content disappeared before protection: {path}"
            )
        except OSError as exc:
            _fail(f"Cannot inspect protected user content {path}: {exc}")
        if stat.S_ISLNK(info.st_mode):
            _fail(
                "Protected user content is a symlink whose target cannot be "
                f"pinned safely: {path}"
            )
        actual_directory = stat.S_ISDIR(info.st_mode)
        actual_file = stat.S_ISREG(info.st_mode)
        if not actual_directory and not actual_file:
            _fail(
                "Protected user content is a special file whose bytes cannot be "
                f"protected: {path}"
            )
        if actual_directory != is_directory:
            _fail(f"Protected user content changed type during derivation: {path}")
        entry = {
            "path": path,
            "kind": "directory" if actual_directory else "file",
            "source": source,
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "dev": info.st_dev,
            "ino": info.st_ino,
        }
        snapshot_entry = entries.get(path)
        if (
            isinstance(snapshot_entry, dict)
            and snapshot_entry.get("kind") == "file"
            and isinstance(snapshot_entry.get("sha256"), str)
            and not actual_directory
        ):
            entry["observed_sha256"] = snapshot_entry["sha256"]
        kept.append(entry)
        seen.add(path)
        if actual_directory:
            directory_prefixes.append(path)
        if len(kept) > MAX_PROTECTED_ROOTS:
            _fail(
                f"Protected user roots exceed the {MAX_PROTECTED_ROOTS}-root "
                "bound; this workspace layout is unsupported for a managed writer"
            )
    return sorted(kept, key=lambda item: item["path"])


def _collect_protection_anchors(
    workspace: Path,
    roots: list[dict[str, Any]],
    contract: dict[str, Any],
) -> list[dict[str, Any]]:
    """Derive deduplicated, parent-first same-path RW ancestor anchors."""
    root_paths = {entry["path"] for entry in roots}
    directory_roots = [
        entry["path"] for entry in roots if entry["kind"] == "directory"
    ]
    anchors: dict[str, dict[str, Any]] = {}
    for root in roots:
        parts = root["path"].split("/")[:-1]
        for index in range(1, len(parts) + 1):
            ancestor = "/".join(parts[:index])
            if ancestor in root_paths:
                continue
            if any(
                ancestor == prefix or ancestor.startswith(prefix + "/")
                for prefix in directory_roots
            ):
                _fail(
                    "Protected ancestor anchor lies inside a protected root: "
                    f"{ancestor}"
                )
            if ancestor in anchors:
                continue
            target = workspace / ancestor
            try:
                info = os.lstat(target)
            except FileNotFoundError:
                _fail(
                    f"Protected path ancestor is missing: {ancestor}"
                )
            except OSError as exc:
                _fail(f"Cannot inspect protected ancestor {ancestor}: {exc}")
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                _fail(
                    "Protected path ancestor is not a normal directory and "
                    f"cannot be pinned: {ancestor}"
                )
            anchors[ancestor] = {
                "path": ancestor,
                "mode": stat.S_IMODE(info.st_mode),
                "dev": info.st_dev,
                "ino": info.st_ino,
            }
    ordered = sorted(
        anchors.values(), key=lambda item: (item["path"].count("/"), item["path"])
    )
    if len(ordered) > MAX_ANCESTOR_ANCHORS:
        _fail(
            f"Protected ancestor anchors exceed the {MAX_ANCESTOR_ANCHORS}-anchor "
            "bound; this workspace layout is unsupported for a managed writer"
        )
    return ordered


def _protection_extra_mount_bytes(
    workspace: Path, roots: list[dict[str, Any]], anchors: list[dict[str, Any]]
) -> int:
    total = 0
    for mount, entries in (("--ro-bind", roots), ("--bind", anchors)):
        for entry in entries:
            absolute = os.fsencode(str(workspace / entry["path"]))
            total += len(mount.encode("ascii")) + 1 + 2 * (len(absolute) + 1)
    return total


def _protection_inputs(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": PROTECTION_VERSION,
        "manifest_sha256": manifest["manifest_sha256"],
        "roots": [
            {"path": entry["path"], "kind": entry["kind"]}
            for entry in manifest["roots"]
        ],
        "anchors": [{"path": entry["path"]} for entry in manifest["anchors"]],
    }


def _writable_alias_guard(
    workspace: Path,
    roots: list[dict[str, Any]],
    *,
    known_owned: list[str] | tuple[str, ...] = (),
) -> int:
    """Refuse pre-existing writable regular-file hardlink aliases.

    Every non-ignored tracked/untracked path plus explicitly attributed ignored
    residue is inspected.  Protected roots, Git metadata and directory entries
    are excluded; a huge already-read-only ignored tree is never traversed for
    this check.  Directory link counts are normal and are never rejected.
    """
    data = _git_capture(
        workspace,
        ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        "writable mutable path enumeration",
    )
    candidates = {
        _observation_path(item, "writable mutable path enumeration")
        for item in data.split(b"\0")
        if item
    }
    candidates.update(
        path for path in known_owned if isinstance(path, str) and path
    )
    if len(candidates) > MAX_MUTABLE_STAT_PATHS:
        _fail(
            f"Writable mutable path count {len(candidates)} exceeds the "
            f"{MAX_MUTABLE_STAT_PATHS}-path stat bound"
        )
    root_files = {
        entry["path"] for entry in roots if entry["kind"] == "file"
    }
    root_directories = [
        entry["path"] for entry in roots if entry["kind"] == "directory"
    ]
    aliases: list[str] = []
    for path in sorted(candidates):
        if path == ".git" or path.startswith(".git/"):
            continue
        if path in root_files:
            continue
        if any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in root_directories
        ):
            continue
        target = workspace / path
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _fail(f"Cannot inspect writable path {path}: {exc}")
        if stat.S_ISLNK(info.st_mode):
            resolved = Path(os.path.realpath(target))
            try:
                relative = resolved.relative_to(workspace)
            except ValueError:
                # External targets remain read-only through the read-only root.
                continue
            relative_text = str(relative)
            if relative_text in root_files or any(
                relative_text == prefix
                or relative_text.startswith(prefix + "/")
                for prefix in root_directories
            ):
                continue
            try:
                info = os.lstat(resolved)
            except OSError:
                continue
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            _fail(
                f"Writable workspace path {path} is a special file whose alias "
                "safety cannot be attested"
            )
        if info.st_nlink > 1:
            aliases.append(path)
    if aliases:
        _fail(
            "Pre-existing writable hardlink aliases could bypass read-only "
            "protected roots: "
            + ", ".join(sorted(aliases)[:20])
            + ". Refusing writer admission before provider startup"
        )
    return len(candidates)


def _validate_protection_identity(
    workspace: Path, manifest: dict[str, Any], label: str
) -> None:
    """Require every declared protected root and anchor to keep its identity."""
    problems: list[str] = []
    for root in manifest.get("roots") or []:
        target = workspace / root["path"]
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            problems.append(root["path"] + " (missing)")
            continue
        except OSError as exc:
            _fail(f"{label}: cannot inspect protected root {root['path']}: {exc}")
        if stat.S_ISLNK(info.st_mode):
            problems.append(root["path"] + " (became a symlink)")
            continue
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
        if (
            kind != root.get("kind")
            or stat.S_IMODE(info.st_mode) != root.get("mode")
            or info.st_size != root.get("size")
            or info.st_mtime_ns != root.get("mtime_ns")
            or info.st_dev != root.get("dev")
            or info.st_ino != root.get("ino")
        ):
            problems.append(root["path"] + " (identity changed)")
    for anchor in manifest.get("anchors") or []:
        target = workspace / anchor["path"]
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            problems.append(anchor["path"] + " (missing anchor)")
            continue
        except OSError as exc:
            _fail(f"{label}: cannot inspect protected ancestor {anchor['path']}: {exc}")
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_dev != anchor.get("dev")
            or info.st_ino != anchor.get("ino")
        ):
            problems.append(anchor["path"] + " (anchor identity changed)")
    if problems:
        _fail(
            f"{label}: original protected user content changed at: "
            + ", ".join(problems[:20])
            + ". Bytes and paths are frozen; damaged or user-edited content is "
            "never adopted by capture"
        )


def derive_protection_manifest(
    workspace: Path,
    snapshot: dict[str, Any],
    contract: dict[str, Any],
    *,
    plan_id: str,
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract_digest: str,
    plan_sha256: str,
    b1_manifest_digest: str,
    known_owned: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Derive the coordinator-owned original protected-user manifest."""
    workspace = Path(workspace)
    roots = _collect_protected_roots(
        workspace, snapshot, contract, known_owned=known_owned
    )
    anchors = _collect_protection_anchors(workspace, roots, contract)
    mutable_stat_paths = _writable_alias_guard(
        workspace, roots, known_owned=known_owned
    )
    extra_bytes = _protection_extra_mount_bytes(workspace, roots, anchors)
    if extra_bytes > MAX_EXTRA_MOUNT_ARGV_BYTES:
        _fail(
            "Protected execution exceeds the "
            f"{MAX_EXTRA_MOUNT_ARGV_BYTES}-byte encoded extra mount argv bound"
        )
    identity = _hook("canonical_workspace")(workspace)
    git_marker = workspace / ".git"
    git_paths: list[str] = []
    if os.path.lexists(git_marker):
        git_paths.append(str(git_marker))
    git_common = identity.get("git_common_dir")
    if isinstance(git_common, str) and git_common:
        git_paths.append(str(Path(git_common)))
    for entry in roots + anchors:
        absolute = str(workspace / entry["path"])
        for git_path in git_paths:
            if absolute == git_path or absolute.startswith(
                git_path.rstrip("/") + "/"
            ):
                _fail(
                    "Protected user content collides with Git custody: "
                    + entry["path"]
                )
    manifest = {
        "version": PROTECTION_VERSION,
        "kind": "d1_protection_manifest",
        "plan_id": plan_id,
        "step_id": step_id,
        "cycle": cycle,
        "candidate_sha256": candidate_sha256,
        "contract_digest": contract_digest,
        "plan_sha256": plan_sha256,
        "b1_manifest_digest": b1_manifest_digest,
        "repository": {
            "root": str(workspace),
            "head": snapshot.get("head"),
            "branch": snapshot.get("branch"),
            "index_sha256": (snapshot.get("index") or {}).get("sha256"),
        },
        "roots": roots,
        "anchors": anchors,
        "hidden_index_paths": sorted(
            set(snapshot.get("hidden_index_paths") or [])
        ),
        "counts": {
            "protected_roots": len(roots),
            "ancestor_anchors": len(anchors),
            "extra_mount_argv_bytes": extra_bytes,
            "mutable_stat_paths": mutable_stat_paths,
        },
        "limits": {
            "max_protected_roots": MAX_PROTECTED_ROOTS,
            "max_ancestor_anchors": MAX_ANCESTOR_ANCHORS,
            "max_extra_mount_argv_bytes": MAX_EXTRA_MOUNT_ARGV_BYTES,
            "max_mutable_stat_paths": MAX_MUTABLE_STAT_PATHS,
        },
        "observed_user_baseline_digest": _user_baseline_digest(snapshot),
        "coverage": {
            "mode": "ro_roots_plus_observed_raw_hashes",
            "recursive_ignored_content_hashes": False,
            "note": (
                "Ignored directory roots are covered by read-only mount identity "
                "and metadata; their file contents are not recursively hashed. "
                "B2 raw hashes are retained only for dirty/untracked/staged and "
                "hidden-index material actually observed."
            ),
        },
    }
    manifest["manifest_sha256"] = _digest(manifest)
    return manifest


def _observe_workspace(
    workspace: Path,
    contract: dict[str, Any] | None,
    extra_paths: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    extra: list[str] = list(extra_paths or [])
    if contract is not None:
        extra.extend(_b2().scope_observation_paths(workspace, _scope_for_contract(contract)))
        # Status-only tracked membership cannot attest hidden-index bytes, so
        # those bounded files remain in the raw-hash observation.  Ignored
        # trees are protected by read-only mount identity instead and are
        # deliberately not hashed here.
        extra.extend(_protected_observation_paths(workspace))
    try:
        snapshot = _b2().snapshot_workspace(
            workspace, strict=True, extra_paths=sorted(set(extra))
        )
    except Exception as exc:
        _fail(f"Workspace integrity observation refused for {workspace}: {exc}")
    if not snapshot.get("supported"):
        _fail(
            "Workspace integrity observation is unsupported: "
            + str(snapshot.get("unsupported_reason"))
        )
    return _annotate_user_baseline(snapshot, workspace)


def _workspace_changes(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    try:
        return _b2().changed_paths(baseline, current)
    except Exception as exc:
        _fail(f"Workspace change attribution failed: {exc}")


def _require_unchanged_user_baseline(
    original_base: dict[str, Any], current: dict[str, Any], label: str
) -> None:
    """Require every pre-existing user dirty/untracked/staged byte to persist.

    The job cannot stage or commit (Git metadata is read-only for the provider)
    and cannot touch dirty paths that overlap its allowed scope. Any difference
    in the protected user baseline means a user edit or unknown residue, which
    blocks completion and continuation rather than being authorized by capture.
    Clean tracked files inside the approved scope are deliberately excluded so
    an ordinary task edit is not mistaken for user residue.
    """
    before = _user_entries(original_base)
    after = current.get("entries") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        _fail(f"{label}: workspace baseline entries are malformed")
    problems: list[str] = []
    for path, entry in sorted(before.items()):
        before_signature = (
            entry.get("kind"),
            entry.get("sha256"),
            entry.get("size"),
            entry.get("mode"),
        )
        current_entry = after.get(path)
        after_signature = (
            (
                current_entry.get("kind"),
                current_entry.get("sha256"),
                current_entry.get("size"),
                current_entry.get("mode"),
            )
            if isinstance(current_entry, dict)
            else None
        )
        if before_signature != after_signature:
            problems.append(path)
    before_index = original_base.get("index") or {}
    after_index = current.get("index") or {}
    if (
        before_index.get("exists") != after_index.get("exists")
        or before_index.get("sha256") != after_index.get("sha256")
    ):
        problems.append("<git-index>")
    before_staged = original_base.get("staged") or {}
    after_staged = current.get("staged") or {}
    if before_staged != after_staged:
        problems.append("<git-index-staging>")
    if problems:
        _fail(
            f"{label}: protected user/index baseline changed at: "
            + ", ".join(sorted(set(problems))[:20])
            + ". Unknown or user-edited residue is not authorized by capturing its bytes"
        )


def _require_branch_and_head(
    snapshot: dict[str, Any],
    contract: dict[str, Any],
    label: str,
) -> None:
    branch = snapshot.get("branch")
    head = snapshot.get("head")
    if branch is None:
        _fail(f"{label}: repository HEAD is detached")
    if branch in contract["protected_branches"]:
        _fail(f"{label}: repository HEAD branch {branch!r} is protected")
    if branch != contract["target_branch"]:
        _fail(
            f"{label}: repository HEAD branch {branch!r} is not the approved "
            f"target {contract['target_branch']!r}"
        )
    if head != contract["base_head"]:
        _fail(
            f"{label}: repository HEAD changed from the frozen base "
            f"{contract['base_head']} to {head}"
        )


def _live_reservations(identity: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        return _b1().active_repository_reservations(identity)
    except Exception as exc:
        _fail(f"Cannot read repository job reservations; failing closed: {exc}")


def _job_dir_for(job_id: str) -> Path:
    _require_id(job_id, "job_id")
    path = _jobs_dir() / job_id
    if not path.is_dir():
        _fail(f"Provider job directory does not exist: {job_id}")
    return path


def _bounded_file_bytes(path: Path, label: str, maximum: int = MAX_JOB_FILE_BYTES) -> bytes:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        _fail(f"{label} does not exist: {path}")
    except OSError as exc:
        _fail(f"{label} cannot be inspected: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail(f"{label} is not a regular file: {path}")
    if info.st_size > maximum:
        _fail(f"{label} exceeds {maximum} bytes: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        _fail(f"{label} cannot be read: {exc}")


def _job_evidence(
    job_id: str,
    operation: str,
    provider: str,
    *,
    require_validated: bool = True,
) -> dict[str, Any]:
    """Load and independently validate one settled C provider job.

    Returns the raw proof bytes plus parsed records. Every hash and capability
    is recomputed from the stored files; a forged job ID, another provider,
    another operation, a failed capture or a live process fails closed.
    """
    path = _job_dir_for(job_id)
    meta_bytes = _bounded_file_bytes(path / "meta.json", "job meta")
    result_bytes = _bounded_file_bytes(path / "result.json", "job result")
    provider_bytes = _bounded_file_bytes(
        path / "provider-result.json", "provider result"
    )
    try:
        meta = json.loads(meta_bytes.decode("utf-8"))
        result = json.loads(result_bytes.decode("utf-8"))
        provider_result = json.loads(provider_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Provider job {job_id} evidence is not valid JSON: {exc}")
    if not all(isinstance(item, dict) for item in (meta, result, provider_result)):
        _fail(f"Provider job {job_id} evidence is not a JSON object")
    if meta.get("job_id") != job_id:
        _fail(f"Provider job {job_id} meta names another job")
    if meta.get("agent") != provider or meta.get("cli") != provider:
        _fail(f"Provider job {job_id} does not belong to the {provider} provider")
    if meta.get("provider") not in {None, provider}:
        _fail(f"Provider job {job_id} provider metadata is inconsistent")
    if meta.get("operation") not in {None, operation}:
        _fail(f"Provider job {job_id} operation metadata is inconsistent")
    try:
        binding = _c().binding_from_meta(meta)
    except Exception as exc:
        _fail(f"Provider job {job_id} binding is not a settled reserved job: {exc}")
    if binding.get("provider") != provider or binding.get("operation") != operation:
        _fail(
            f"Provider job {job_id} binding does not match the required "
            f"{provider}/{operation} provenance"
        )
    if binding.get("capability") not in {"readonly", "workspace_write"}:
        _fail(f"Provider job {job_id} has an unsupported capability")
    digest = _c().provider_result_sha256(provider_result)
    summary = meta.get("provider_result")
    if not isinstance(summary, dict):
        _fail(f"Provider job {job_id} has no normalized provider-result summary")
    if summary.get("result_sha256") != digest:
        _fail(f"Provider job {job_id} provider-result hash does not match its file")
    if provider_result.get("provider") != provider:
        _fail(f"Provider job {job_id} provider result names another provider")
    if provider_result.get("operation") != operation:
        _fail(f"Provider job {job_id} provider result names another operation")
    if provider_result.get("capability") != binding.get("capability"):
        _fail(f"Provider job {job_id} provider capability was altered")
    payload = provider_result.get("payload")
    normalized_payload: dict[str, Any] | None = None
    if payload is not None and isinstance(payload, dict):
        try:
            normalized_payload = _c().validate_payload(operation, payload)
        except Exception as exc:
            if require_validated:
                _fail(f"Provider job {job_id} payload is invalid: {exc}")
            normalized_payload = None
        if (
            normalized_payload is not None
            and _digest(normalized_payload) != provider_result.get("payload_sha256")
        ):
            _fail(f"Provider job {job_id} provider payload hash does not match")
    if require_validated:
        if (
            summary.get("validated") is not True
            or provider_result.get("validated") is not True
        ):
            _fail(f"Provider job {job_id} provider result was not validated")
        if provider_result.get("error") is not None:
            _fail(f"Provider job {job_id} provider result records an error")
        if normalized_payload is None:
            _fail(f"Provider job {job_id} has no validated provider payload")
    if meta.get("task_sha256") is not None:
        task_bytes = _bounded_file_bytes(
            path / "task.md", "job task", maximum=MAX_TASK_BYTES + MAX_CONTRACT_BYTES
        )
        if _sha256_bytes(task_bytes) != meta.get("task_sha256"):
            _fail(f"Provider job {job_id} task bytes do not match the recorded hash")
    original_task_bytes = _bounded_file_bytes(
        path / "task-original.md", "job original task", maximum=MAX_TASK_BYTES
    )
    _require_processes_dead(meta, f"Provider job {job_id}")
    return {
        "path": path,
        "meta": meta,
        "result": result,
        "provider_result": provider_result,
        "payload": payload,
        "normalized_payload": normalized_payload,
        "binding": binding,
        "meta_bytes": meta_bytes,
        "result_bytes": result_bytes,
        "provider_result_bytes": provider_bytes,
        "task_original_bytes": original_task_bytes,
        "meta_sha256": _sha256_bytes(meta_bytes),
        "result_sha256": _sha256_bytes(result_bytes),
        "provider_result_sha256": digest,
        "provider_payload_sha256": provider_result.get("payload_sha256"),
        "task_sha256": meta.get("task_sha256"),
        "task_original_sha256": _sha256_bytes(original_task_bytes),
    }


def _require_job_settled(
    identity: dict[str, Any], job_id: str, label: str
) -> None:
    for record in _live_reservations(identity):
        if record.get("job_id") == job_id:
            _fail(
                f"{label} is still draining: a live repository reservation records "
                f"job {job_id}"
            )


# ---------------------------------------------------------------------------
# Versioned execution-fact journal
# ---------------------------------------------------------------------------

EVENT_KEYS = {
    "version",
    "sequence",
    "event_id",
    "operation_id",
    "request_digest",
    "type",
    "at",
    "plan_id",
    "step_id",
    "cycle",
    "payload",
    "prev_digest",
    "digest",
}

PAYLOAD_KEYS: dict[str, set[str]] = {
    TYPE_ASSIGNMENT: {
        "version",
        "role",
        "provider",
        "operation",
        "round",
        "cycle",
        "job_id",
        "issuer",
        "candidate_sha256",
        "task_source_sha256",
        "task_source_bytes",
    },
    TYPE_EVIDENCE: {
        "version",
        "role",
        "provider",
        "operation",
        "round",
        "cycle",
        "job_id",
        "assignment_event_id",
        "assignment_digest",
        "candidate_sha256",
        "task_source_sha256",
        "job_meta_sha256",
        "job_result_sha256",
        "provider_result_sha256",
        "provider_payload_sha256",
        "original_payload_sha256",
        "mapped_sha256",
        "observed_workspace_digest",
        "workspace",
        "evidence_blob_sha256",
        "evidence_digest",
    },
    TYPE_CONTRACT: {
        "version",
        "candidate_sha256",
        "cycle",
        "plan_sha256",
        "manifest_digest",
        "base_head",
        "base_branch",
        "base_index_sha256",
        "contract_digest",
        "contract_blob_sha256",
        "target_branch",
        "protected_branches",
    },
    TYPE_INTENT: {
        "version",
        "attempt_id",
        "job_id",
        "invocation",
        "cycle",
        "candidate_sha256",
        "contract_digest",
        "plan_sha256",
        "manifest_digest",
        "provider",
        "operation",
        "capability",
        "issuer",
        "base_snapshot_digest",
        "base_snapshot_blob_sha256",
        "original_base_snapshot_digest",
        "original_base_blob_sha256",
        "head",
        "branch",
        "index_sha256",
        "user_baseline_digest",
        "task_source_sha256",
        "continuation_of",
    },
    TYPE_CLAIM: {
        "version",
        "attempt_id",
        "job_id",
        "invocation",
        "cycle",
        "candidate_sha256",
        "contract_digest",
        "lease",
        "base_snapshot_digest",
        "head",
        "branch",
        "index_sha256",
        "claim_digest",
    },
    TYPE_RESULT: {
        "version",
        "attempt_id",
        "job_id",
        "invocation",
        "classification",
        "state",
        "job_meta_sha256",
        "job_result_sha256",
        "provider_result_sha256",
        "final_check_sha256",
        "receipt_sha256",
        "evidence_digest",
        "evidence_blob_sha256",
        "reasons",
        "residue",
    },
    TYPE_COMPLETE: {
        "version",
        "attempt_id",
        "job_id",
        "invocation",
        "candidate_sha256",
        "contract_digest",
        "original_base_snapshot_digest",
        "final_snapshot_digest",
        "cumulative_changed_paths",
        "cumulative_changed_digest",
        "evidence_digest",
        "evidence_blob_sha256",
        "diff_blob_sha256",
        "changed_count",
        "report",
    },
    TYPE_BLOCKED: {
        "version",
        "attempt_id",
        "job_id",
        "invocation",
        "state",
        "reasons",
        "evidence_digest",
    },
    TYPE_CONTINUATION: {
        "version",
        "attempt_id",
        "previous_job_id",
        "previous_invocation",
        "evidence_digest",
        "authorization",
        "new_base_snapshot_digest",
        "invocation",
    },
    TYPE_ABORTED: {
        "version",
        "attempt_id",
        "job_id",
        "invocation",
        "reason",
        "evidence_digest",
    },
}

PROCESS_RECORD_KEYS = {"pid", "start"}

# New strict-mode attempts carry protection evidence.  These fields are
# optional in the schema so historical events without them replay byte-for-byte;
# current writer admission requires them explicitly.
PAYLOAD_OPTIONAL_KEYS: dict[str, set[str]] = {
    TYPE_INTENT: {
        "protection_version",
        "protection_manifest_digest",
        "protection_manifest_blob_sha256",
        # D2 formal repair intents keep the same writer reducer while binding
        # the durable allocation, frozen repair contract and parent lineage.
        "repair_allocation_id",
        "repair_contract_digest",
        "parent_attempt_id",
        "parent_job_id",
        "repair_generation",
    },
    TYPE_CLAIM: {
        "protection_manifest_digest",
        "repair_allocation_id",
        "repair_contract_digest",
    },
    TYPE_RESULT: {
        "protection_manifest_digest",
        "confinement_digest",
        "repair_allocation_id",
    },
    TYPE_COMPLETE: {
        "protection_manifest_digest",
        "confinement_digest",
        "repair_allocation_id",
        "parent_attempt_id",
    },
}


def _validate_process_issuer(value: Any, label: str) -> dict[str, Any]:
    record = _exact_keys(value, PROCESS_RECORD_KEYS, label)
    pid = record.get("pid")
    start = record.get("start")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        _fail(f"{label}.pid must be a positive integer")
    if not isinstance(start, str) or not start:
        _fail(f"{label}.start must be a process start identity")
    return {"pid": pid, "start": start}


def _validate_lease_payload(value: Any, label: str) -> dict[str, Any]:
    record = _exact_keys(
        value,
        {
            "epoch",
            "owner_path",
            "lock_path",
            "lock_dev",
            "lock_ino",
            "job_dir",
            "receipt_path",
        },
        label,
    )
    if not isinstance(record.get("epoch"), str) or not re.fullmatch(
        r"^[0-9a-f]{32}$", record["epoch"]
    ):
        _fail(f"{label}.epoch must be a 32-character B2 epoch")
    for key in ("owner_path", "lock_path", "job_dir", "receipt_path"):
        if not isinstance(record.get(key), str) or not record[key]:
            _fail(f"{label}.{key} must be a non-empty path")
    for key in ("lock_dev", "lock_ino"):
        item = record.get(key)
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            _fail(f"{label}.{key} must be a positive integer")
    return record


def _validate_workspace_evidence(value: Any, label: str) -> dict[str, Any]:
    record = _exact_keys(
        value,
        {
            "canonical_workspace",
            "head",
            "branch",
            "detached",
            "index_sha256",
            "snapshot_digest",
        },
        label,
    )
    for key in ("canonical_workspace", "head", "branch"):
        if not isinstance(record.get(key), str) or not record[key]:
            _fail(f"{label}.{key} must be a non-empty string")
    if not isinstance(record.get("detached"), bool):
        _fail(f"{label}.detached must be a boolean")
    if record.get("index_sha256") is not None:
        _require_digest(record.get("index_sha256"), f"{label}.index_sha256")
    _require_digest(record.get("snapshot_digest"), f"{label}.snapshot_digest")
    return record


def _validate_event_payload(event: dict[str, Any]) -> None:
    event_type = event["type"]
    payload = event["payload"]
    if event_type in D2_EVENT_TYPES:
        # D2 owns its strict schemas. The hook is mandatory: an unregistered
        # D2 event must fail closed rather than be treated as an unknown type
        # or silently accepted.
        _hook("d2_event_validator")(event_type, payload)
        return
    _optional_keys(
        payload,
        PAYLOAD_KEYS[event_type],
        PAYLOAD_OPTIONAL_KEYS.get(event_type, set()),
        f"{event_type} payload",
    )
    version = payload.get("version")
    if type(version) is not int or version != EXECUTION_VERSION:
        _fail(f"{event_type} payload has an unsupported version")
    step_id = event.get("step_id")
    cycle = event.get("cycle")
    if not isinstance(step_id, str) or not ID_RE.fullmatch(step_id):
        _fail(f"{event_type} payload is not bound to a valid step")
    if not isinstance(cycle, int) or isinstance(cycle, bool) or cycle < 1:
        _fail(f"{event_type} payload has an invalid cycle")
    for key in ("candidate_sha256", "contract_digest", "plan_sha256", "manifest_digest"):
        if key in payload and payload.get(key) is not None:
            _require_digest(payload.get(key), f"{event_type}.{key}")
    if event_type == TYPE_ASSIGNMENT:
        if payload.get("role") not in {"deepseek", "glm"}:
            _fail("discussion_assignment.role must be a reserved provider role")
        if payload.get("provider") != payload.get("role"):
            _fail("discussion_assignment provider does not match its role")
        expected_operation = SLOT_ROUNDS.get(payload.get("round"))
        if expected_operation is None or payload.get("operation") != expected_operation:
            _fail("discussion_assignment operation does not match its round")
        if payload.get("cycle") != cycle:
            _fail("discussion_assignment cycle does not match the event")
        _require_id(payload.get("job_id"), "discussion_assignment.job_id")
        _validate_process_issuer(payload.get("issuer"), "discussion_assignment.issuer")
        if payload.get("round") == 3:
            _require_digest(
                payload.get("candidate_sha256"),
                "discussion_assignment.candidate_sha256",
            )
        elif payload.get("candidate_sha256") is not None:
            _fail("Only ballot assignments may name a candidate digest")
        _require_digest(
            payload.get("task_source_sha256"),
            "discussion_assignment.task_source_sha256",
        )
        size = payload.get("task_source_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            _fail("discussion_assignment.task_source_bytes is invalid")
    elif event_type == TYPE_EVIDENCE:
        if payload.get("role") not in {"deepseek", "glm"}:
            _fail("discussion_evidence.role must be a reserved provider role")
        if payload.get("provider") != payload.get("role"):
            _fail("discussion_evidence provider does not match its role")
        expected_operation = SLOT_ROUNDS.get(payload.get("round"))
        if expected_operation is None or payload.get("operation") != expected_operation:
            _fail("discussion_evidence operation does not match its round")
        if payload.get("cycle") != cycle:
            _fail("discussion_evidence cycle does not match the event")
        _require_id(payload.get("job_id"), "discussion_evidence.job_id")
        for key in (
            "assignment_digest",
            "task_source_sha256",
            "job_meta_sha256",
            "job_result_sha256",
            "provider_result_sha256",
            "provider_payload_sha256",
            "original_payload_sha256",
            "mapped_sha256",
            "observed_workspace_digest",
            "evidence_blob_sha256",
            "evidence_digest",
        ):
            _require_digest(payload.get(key), f"discussion_evidence.{key}")
        if payload.get("round") == 3:
            _require_digest(
                payload.get("candidate_sha256"),
                "discussion_evidence.candidate_sha256",
            )
        elif payload.get("candidate_sha256") is not None:
            _fail("Only ballot evidence may name a candidate digest")
        _validate_workspace_evidence(
            payload.get("workspace"), "discussion_evidence.workspace"
        )
    elif event_type == TYPE_CONTRACT:
        if payload.get("cycle") != cycle:
            _fail("contract_frozen cycle does not match the event")
        for key in (
            "contract_digest",
            "contract_blob_sha256",
            "base_index_sha256",
        ):
            if payload.get(key) is not None:
                _require_digest(payload.get(key), f"contract_frozen.{key}")
        for key in ("base_head", "base_branch", "target_branch"):
            if not isinstance(payload.get(key), str) or not payload[key]:
                _fail(f"contract_frozen.{key} must be a non-empty string")
        protected = payload.get("protected_branches")
        if not isinstance(protected, list) or not all(
            isinstance(item, str) and item for item in protected
        ):
            _fail("contract_frozen.protected_branches must be string names")
    elif event_type in {TYPE_INTENT, TYPE_CLAIM, TYPE_RESULT, TYPE_COMPLETE, TYPE_BLOCKED, TYPE_ABORTED, TYPE_CONTINUATION}:
        _require_id(payload.get("job_id") or payload.get("previous_job_id"), f"{event_type}.job_id")
        attempt_id = payload.get("attempt_id")
        if not isinstance(attempt_id, str) or not DIGEST_RE.fullmatch(attempt_id):
            _fail(f"{event_type}.attempt_id must be a digest")
        invocation = payload.get("invocation")
        if not isinstance(invocation, int) or isinstance(invocation, bool) or invocation < 1:
            _fail(f"{event_type}.invocation must be a positive integer")
        if payload.get("cycle") != cycle if "cycle" in payload else False:
            _fail(f"{event_type} cycle does not match the event")
        for key in ("evidence_blob_sha256", "diff_blob_sha256", "base_snapshot_blob_sha256", "original_base_blob_sha256"):
            if key in payload:
                _require_digest(payload.get(key), f"{event_type}.{key}")
        for key in ("evidence_digest", "claim_digest", "final_snapshot_digest", "cumulative_changed_digest", "base_snapshot_digest", "original_base_snapshot_digest", "user_baseline_digest", "task_source_sha256", "protection_manifest_digest", "protection_manifest_blob_sha256", "confinement_digest"):
            if key in payload and payload.get(key) is not None:
                _require_digest(payload.get(key), f"{event_type}.{key}")
        if "protection_version" in payload:
            if payload.get("protection_version") != PROTECTION_VERSION:
                _fail(f"{event_type} protection version is unsupported")
            for key in (
                "protection_manifest_digest",
                "protection_manifest_blob_sha256",
            ):
                _require_digest(payload.get(key), f"{event_type}.{key}")
        if event_type == TYPE_INTENT:
            if payload.get("provider") != "deepseek":
                _fail("implementation_intent must bind the reserved deepseek writer")
            repair_allocation = payload.get("repair_allocation_id")
            if repair_allocation is None:
                if payload.get("operation") != "implementation":
                    _fail(
                        "implementation_intent must bind the implementation operation"
                    )
                for key in (
                    "repair_contract_digest",
                    "parent_attempt_id",
                    "parent_job_id",
                    "repair_generation",
                ):
                    if payload.get(key) is not None:
                        _fail(
                            f"implementation_intent cannot carry {key} without a "
                            "repair allocation"
                        )
            else:
                _require_id(
                    repair_allocation, "implementation_intent.repair_allocation_id"
                )
                if payload.get("operation") != "repair":
                    _fail(
                        "A repair intent must bind the reserved repair operation"
                    )
                _require_digest(
                    payload.get("repair_contract_digest"),
                    "implementation_intent.repair_contract_digest",
                )
                _require_digest(
                    payload.get("parent_attempt_id"),
                    "implementation_intent.parent_attempt_id",
                )
                _require_id(
                    payload.get("parent_job_id"),
                    "implementation_intent.parent_job_id",
                )
                generation = payload.get("repair_generation")
                if (
                    not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or not 1 <= generation <= FORMAL_REPAIR_LIMIT
                ):
                    _fail(
                        "implementation_intent.repair_generation must be 1.."
                        f"{FORMAL_REPAIR_LIMIT}"
                    )
            if payload.get("capability") != "workspace_write":
                _fail("implementation_intent must bind a workspace-write capability")
            _validate_process_issuer(payload.get("issuer"), "implementation_intent.issuer")
            for key in ("base_snapshot_blob_sha256", "original_base_blob_sha256"):
                _require_digest(payload.get(key), f"implementation_intent.{key}")
        if event_type == TYPE_CLAIM:
            _validate_lease_payload(payload.get("lease"), "implementation_claim.lease")
            _require_digest(payload.get("claim_digest"), "implementation_claim.claim_digest")
        if event_type == TYPE_RESULT:
            if payload.get("classification") not in {
                "drained_success",
                "drained_failure",
                "uncertain",
                "pre_invocation_abort",
            }:
                _fail("invocation_result classification is unsupported")
            if not isinstance(payload.get("reasons"), list):
                _fail("invocation_result.reasons must be a JSON array")
        if event_type == TYPE_COMPLETE:
            paths = payload.get("cumulative_changed_paths")
            if not isinstance(paths, list) or not all(
                isinstance(item, str) for item in paths
            ):
                _fail("implementation_complete cumulative paths are malformed")
        if event_type == TYPE_BLOCKED:
            if payload.get("state") not in {"BLOCKED", "SUSPECT"}:
                _fail("implementation_blocked state must be BLOCKED or SUSPECT")
            if not isinstance(payload.get("reasons"), list):
                _fail("implementation_blocked.reasons must be a JSON array")


def _event_operation_state() -> dict[str, Any]:
    return {"seen": set()}


def _validate_event_header(
    event: Any,
    index: int,
    plan_id: str,
    previous_digest: str,
    operation_state: dict[str, Any],
) -> None:
    if not isinstance(event, dict):
        _fail(f"Execution journal event {index} is not a JSON object")
    if set(event) != EVENT_KEYS:
        _fail(f"Execution journal event {index} has an invalid schema")
    if event.get("version") != JOURNAL_VERSION:
        _fail(f"Execution journal event {index} has an unsupported version")
    if event.get("sequence") != index:
        _fail(
            f"Execution journal event {index} has sequence "
            f"{event.get('sequence')!r}; expected {index}"
        )
    event_type = event.get("type")
    if event_type not in EVENT_TYPES:
        _fail(f"Execution journal event {index} has an unknown type")
    if event.get("plan_id") != plan_id:
        _fail(f"Execution journal event {index} belongs to another plan")
    if not isinstance(event.get("at"), str) or not event["at"]:
        _fail(f"Execution journal event {index} has no timestamp")
    digest = event.get("digest")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        _fail(f"Execution journal event {index} has an invalid digest")
    if event.get("prev_digest") != previous_digest:
        _fail(
            f"Execution journal event {index} does not reference the previous digest"
        )
    computed = _digest({key: value for key, value in event.items() if key != "digest"})
    if computed != digest:
        _fail(f"Execution journal event {index} content digest does not match")
    operation_id = event.get("operation_id")
    if not isinstance(operation_id, str) or not OP_ID_RE.fullmatch(operation_id):
        _fail(f"Execution journal event {index} has an invalid operation ID")
    request_digest = event.get("request_digest")
    if not isinstance(request_digest, str) or not DIGEST_RE.fullmatch(request_digest):
        _fail(f"Execution journal event {index} has an invalid request digest")
    last_operation = operation_state.get("operation_id")
    if operation_id == last_operation:
        operation_state["ordinal"] = operation_state.get("ordinal", 0) + 1
    else:
        if operation_id in operation_state["seen"]:
            _fail(
                f"Execution operation {operation_id} was published in non-contiguous events"
            )
        operation_state["seen"].add(operation_id)
        operation_state["operation_id"] = operation_id
        operation_state["ordinal"] = 1
        operation_state["request_digest"] = request_digest
    if operation_state.get("request_digest") != request_digest:
        _fail(f"Execution operation {operation_id} has inconsistent request digests")
    if event.get("event_id") != f"{operation_id}:{operation_state['ordinal']}":
        _fail(f"Execution journal event {index} has an invalid event ID")
    step_id = event.get("step_id")
    if not isinstance(step_id, str) or not ID_RE.fullmatch(step_id):
        _fail(f"Execution journal event {index} has an invalid step ID")
    cycle = event.get("cycle")
    if not isinstance(cycle, int) or isinstance(cycle, bool) or cycle < 1:
        _fail(f"Execution journal event {index} has an invalid cycle")
    payload = event.get("payload")
    if not isinstance(payload, dict):
        _fail(f"Execution journal event {index} has an invalid payload")
    if len(_canonical_bytes(event)) > MAX_EVENT_BYTES:
        _fail(f"Execution journal event {index} exceeds {MAX_EVENT_BYTES} bytes")
    _validate_event_payload(event)


def _empty_journal(plan_id: str) -> dict[str, Any]:
    return {
        "plan_id": plan_id,
        "events": [],
        "assignments": [],
        "evidence": [],
        "contracts": [],
        "intents": [],
        "claims": [],
        "results": [],
        "completions": [],
        "blocks": [],
        "continuations": [],
        "aborts": [],
        **{name: [] for name in D2_JOURNAL_LISTS.values()},
    }


def _replay_journal(plan_id: str) -> dict[str, Any]:
    """Replay and cryptographically verify the execution journal.

    Historical facts are validated from recorded hashes only; replay never
    probes a live process or network to reinterpret what happened.
    """
    state = _empty_journal(plan_id)
    files = _published_event_files(plan_id)
    operation_state = _event_operation_state()
    previous = ZERO_DIGEST
    for index, path in enumerate(files, start=1):
        if path.name != f"{index:06d}.json":
            _fail(
                f"Execution journal filename {path.name!r} does not match its "
                f"ordered sequence {index}"
            )
        event = _read_json(path)
        _validate_event_header(event, index, plan_id, previous, operation_state)
        previous = event["digest"]
        event_type = event["type"]
        if event_type == TYPE_ASSIGNMENT:
            state["assignments"].append(event)
        elif event_type == TYPE_EVIDENCE:
            state["evidence"].append(event)
        elif event_type == TYPE_CONTRACT:
            state["contracts"].append(event)
        elif event_type == TYPE_INTENT:
            state["intents"].append(event)
        elif event_type == TYPE_CLAIM:
            state["claims"].append(event)
        elif event_type == TYPE_RESULT:
            state["results"].append(event)
        elif event_type == TYPE_COMPLETE:
            state["completions"].append(event)
        elif event_type == TYPE_BLOCKED:
            state["blocks"].append(event)
        elif event_type == TYPE_CONTINUATION:
            state["continuations"].append(event)
        elif event_type == TYPE_ABORTED:
            state["aborts"].append(event)
        elif event_type in D2_EVENT_TYPES:
            state[D2_JOURNAL_LISTS[event_type]].append(event)
        state["events"].append(event)
    return state


def _journal_exists(plan_id: str) -> bool:
    return bool(_published_event_files(plan_id))


def _append_journal(
    plan_id: str,
    specs: list[dict[str, Any]],
    operation_id: str,
    request_digest: str,
) -> list[dict[str, Any]]:
    """Append events under the caller-held B1 plan lock.

    Identical operation and inputs return the existing events. Reusing an
    operation ID with different content fails. Blob publication is the caller's
    responsibility and must already have completed.
    """
    operation_id = _operation_id(operation_id, "execution operation ID")
    _require_digest(request_digest, "execution request digest")
    state = _replay_journal(plan_id)
    existing = [
        event
        for event in state["events"]
        if event["operation_id"] == operation_id
    ]
    if existing:
        if existing[0]["request_digest"] != request_digest:
            _fail(
                f"Execution operation ID {operation_id} was already used with "
                "different content"
            )
        return existing
    sequence = len(state["events"]) + 1
    previous = state["events"][-1]["digest"] if state["events"] else ZERO_DIGEST
    timestamp = _now()
    planned: list[dict[str, Any]] = []
    operation_state = _event_operation_state()
    for ordinal, spec in enumerate(specs, start=1):
        event = {
            "version": JOURNAL_VERSION,
            "sequence": sequence,
            "event_id": f"{operation_id}:{ordinal}",
            "operation_id": operation_id,
            "request_digest": request_digest,
            "type": spec["type"],
            "at": timestamp,
            "plan_id": plan_id,
            "step_id": spec.get("step_id"),
            "cycle": spec["cycle"],
            "payload": spec["payload"],
            "prev_digest": previous,
        }
        event["digest"] = _digest(event)
        _validate_event_header(event, sequence, plan_id, previous, operation_state)
        planned.append(event)
        sequence += 1
        previous = event["digest"]
    for event in planned:
        _write_event_file(
            plan_id,
            _events_dir(plan_id) / f"{event['sequence']:06d}.json",
            event,
        )
    return planned


def _request_digest(command: str, **fields: Any) -> str:
    return _digest({"command": command, **fields})


def _events_for_step(state: dict[str, Any], step_id: str) -> list[dict[str, Any]]:
    return [event for event in state["events"] if event.get("step_id") == step_id]


def _latest(
    events: list[dict[str, Any]], event_type: str, **match: Any
) -> dict[str, Any] | None:
    for event in reversed(events):
        if event["type"] != event_type:
            continue
        payload = event["payload"]
        if all(payload.get(key) == value for key, value in match.items()):
            return event
    return None


def _latest_any(
    events: list[dict[str, Any]], types: set[str], **match: Any
) -> dict[str, Any] | None:
    for event in reversed(events):
        if event["type"] not in types:
            continue
        payload = event["payload"]
        if all(payload.get(key) == value for key, value in match.items()):
            return event
    return None


def _attempt_events(
    state: dict[str, Any], step_id: str, attempt_id: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in _events_for_step(state, step_id)
        if event["payload"].get("attempt_id") == attempt_id
    ]


def _plan_static(b1_state: dict[str, Any]) -> dict[str, Any]:
    static = b1_state.get("static")
    if not isinstance(static, dict):
        _fail("Managed plan has no immutable enrollment state")
    return static


def _require_strict_plan(b1_state: dict[str, Any]) -> dict[str, Any]:
    static = _plan_static(b1_state)
    if static.get("strict_execution") is not True:
        _fail(
            "Execution commands require a strict-execution managed plan; legacy or "
            "manual discussion records never grant source-write authority"
        )
    return static


def _step_b1_state(b1_state: dict[str, Any], step_id: str) -> dict[str, Any]:
    steps = b1_state.get("steps")
    if not isinstance(steps, dict) or step_id not in steps:
        _fail(f"Unknown managed step {step_id!r}")
    return steps[step_id]


def _require_consensus(
    b1_state: dict[str, Any], step_id: str
) -> dict[str, Any]:
    current = _step_b1_state(b1_state, step_id)
    if current.get("outcome") != "CONSENSUS_REACHED":
        _fail(
            f"Step {step_id} is not at CONSENSUS_REACHED; D1 implementation "
            "requires unanimous consensus for the current cycle"
        )
    candidate = current.get("candidate") or {}
    if not isinstance(candidate, dict) or not candidate.get("digest"):
        _fail(f"Step {step_id} has no frozen candidate digest")
    return current


def _candidate_constraints(
    b1_state: dict[str, Any], step_id: str
) -> tuple[dict[str, Any], str]:
    current = _require_consensus(b1_state, step_id)
    document = current["candidate"].get("candidate") or {}
    constraints = document.get("execution_constraints")
    if not isinstance(constraints, dict):
        _fail(
            "Strict-execution implementation requires version 1 candidate "
            "execution_constraints approved by every role"
        )
    return constraints, current["candidate"]["digest"]


def _repo_identity(static: dict[str, Any]) -> dict[str, Any]:
    try:
        identity = _hook("canonical_workspace")(Path(static["canonical_workspace"]))
    except Exception as exc:
        _fail(f"Cannot resolve the managed repository identity: {exc}")
    if not identity.get("is_git") or not identity.get("is_work_tree"):
        _fail("Managed execution requires the canonical Git work tree")
    if identity.get("root") != static.get("canonical_workspace"):
        _fail(
            "Managed plan workspace is no longer the canonical enrollment checkout"
        )
    return identity


def _assignment_for_job(
    journal: dict[str, Any], job_id: str
) -> dict[str, Any]:
    matches = [
        event
        for event in journal["assignments"]
        if event["payload"].get("job_id") == job_id
    ]
    if not matches:
        _fail(
            f"Provider job {job_id} has no protected discussion assignment in this "
            "plan's execution journal"
        )
    if len(matches) > 1:
        _fail(f"Provider job {job_id} has ambiguous discussion assignments")
    return matches[0]


def _evidence_for_job(
    journal: dict[str, Any], job_id: str
) -> dict[str, Any] | None:
    matches = [
        event for event in journal["evidence"] if event["payload"].get("job_id") == job_id
    ]
    if len(matches) > 1:
        _fail(f"Provider job {job_id} has ambiguous discussion evidence")
    return matches[0] if matches else None


def _load_evidence_blob(
    plan_id: str, sha: Any, expected_digest: Any, label: str
) -> dict[str, Any]:
    data = _read_blob(plan_id, sha, label)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        _fail(f"{label} is not a JSON object")
    digest = value.pop("evidence_digest", None)
    if digest != expected_digest:
        _fail(f"{label} embedded digest does not match the journal event")
    if _digest(value) != digest:
        _fail(f"{label} content does not match its recorded digest")
    value["evidence_digest"] = digest
    return value


def _require_assignment_binding(
    assignment: dict[str, Any],
    *,
    plan_id: str,
    step_id: str,
    role: str,
    round_number: int,
    cycle: int,
    candidate_sha256: str | None,
    job_id: str,
) -> None:
    payload = assignment["payload"]
    if payload.get("job_id") != job_id:
        _fail("Discussion assignment names another job")
    if payload.get("role") != role or payload.get("provider") != role:
        _fail(
            "Provider job role does not match the protected discussion assignment"
        )
    if payload.get("round") != round_number:
        _fail("Provider job round does not match the protected assignment")
    if payload.get("cycle") != cycle:
        _fail("Provider job cycle does not match the protected assignment")
    if assignment.get("step_id") != step_id:
        _fail("Provider job step does not match the protected assignment")
    if assignment.get("plan_id") != plan_id:
        _fail("Provider job plan does not match the protected assignment")
    expected_operation = SLOT_ROUNDS.get(round_number)
    if expected_operation is None or payload.get("operation") != expected_operation:
        _fail("Provider job operation does not match its discussion round")
    if payload.get("candidate_sha256") != candidate_sha256:
        _fail(
            "Provider job does not bind the current frozen candidate digest"
        )


def _require_b1_slot(
    b1_state: dict[str, Any],
    step_id: str,
    role: str,
    round_number: int,
    cycle: int,
    candidate_sha256: str | None,
) -> None:
    current = _step_b1_state(b1_state, step_id)
    if current.get("cycle") != cycle:
        _fail(
            "Provider evidence is stale: the managed plan has moved to another cycle"
        )
    stage = _b1().stage_of(current)
    expected_stage = {
        1: _b1().STAGE_PROPOSALS,
        2: _b1().STAGE_CROSS,
        3: _b1().STAGE_BALLOTS,
    }[round_number]
    if stage != expected_stage:
        _fail(
            f"Provider evidence is stale: cycle {cycle} is at {stage}, not "
            f"{expected_stage}"
        )
    submitted = (
        current.get("proposals")
        if round_number == 1
        else current.get("cross_examinations")
        if round_number == 2
        else current.get("ballots")
    )
    if role in submitted:
        _fail(f"{role} already has a recorded round {round_number} receipt")
    if round_number == 3:
        frozen = (current.get("candidate") or {}).get("digest")
        if frozen != candidate_sha256:
            _fail("Provider ballot evidence is stale against the frozen candidate")


def _source_workspace_evidence(
    workspace: Path,
    baseline: dict[str, Any],
    expected_canonical: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    extra = sorted(set((baseline.get("entries") or {}).keys()))
    current = _observe_workspace(workspace, None, extra_paths=extra)
    if not baseline.get("supported"):
        _fail("Provider job has no supported content-attributed baseline")
    report = _workspace_changes(baseline, current)
    if report.get("count"):
        _fail(
            "The provider job's source context changed after it ran: "
            + ", ".join(report.get("paths") or [])
        )
    if report.get("head_changed") or report.get("branch_changed"):
        _fail("The provider job's repository HEAD or branch changed after it ran")
    if report.get("index_changed"):
        _fail("The provider job's Git index changed after it ran")
    if current.get("branch") is None:
        _fail("The provider job's repository HEAD is detached")
    if _snapshot_signature(current)["head"] is None:
        _fail("The provider job's repository has no HEAD commit")
    evidence = {
        "canonical_workspace": expected_canonical,
        "head": str(current.get("head")),
        "branch": str(current.get("branch")),
        "detached": bool(current.get("detached")),
        "index_sha256": (current.get("index") or {}).get("sha256"),
        "snapshot_digest": _snapshot_digest(current),
    }
    return evidence, current


def _ingest_discussion_locked(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    round_number: int,
    cycle: int,
    candidate_sha256: str | None,
    job_id: str,
) -> dict[str, Any]:
    """Ingest one settled readonly C job for an exact discussion slot.

    The caller holds B1's plan lock. The function appends the immutable
    discussion_evidence event and returns the record B1 needs for its strict
    source gate. It never fabricates a payload or accepts a partial response.
    """
    b1_state = _b1().replay_plan_state_unlocked(plan_id)
    static = _require_strict_plan(b1_state)
    journal = _replay_journal(plan_id)
    assignment = _assignment_for_job(journal, job_id)
    _require_assignment_binding(
        assignment,
        plan_id=plan_id,
        step_id=step_id,
        role=role,
        round_number=round_number,
        cycle=cycle,
        candidate_sha256=candidate_sha256,
        job_id=job_id,
    )
    existing = _evidence_for_job(journal, job_id)
    if existing is not None:
        if existing["step_id"] != step_id or existing["cycle"] != cycle:
            _fail("Provider job evidence is already bound to another discussion slot")
        payload = existing["payload"]
        source = _load_evidence_blob(
            plan_id,
            payload["evidence_blob_sha256"],
            payload["evidence_digest"],
            f"discussion evidence for job {job_id}",
        )
        return {
            **{
                key: payload[key]
                for key in (
                    "role",
                    "provider",
                    "operation",
                    "task_source_sha256",
                    "job_meta_sha256",
                    "job_result_sha256",
                    "provider_result_sha256",
                    "provider_payload_sha256",
                    "original_payload_sha256",
                    "mapped_sha256",
                    "observed_workspace_digest",
                    "assignment_digest",
                    "candidate_sha256",
                    "evidence_digest",
                )
            },
            "job_id": job_id,
            "evidence_event_id": existing["event_id"],
            "payload": source["original_payload"],
        }
    _require_b1_slot(
        b1_state, step_id, role, round_number, cycle, candidate_sha256
    )
    identity = _repo_identity(static)
    _require_job_settled(identity, job_id, f"Provider job {job_id}")
    evidence = _job_evidence(job_id, SLOT_ROUNDS[round_number], role)
    if evidence["binding"].get("capability") != "readonly":
        _fail("Discussion provenance requires a readonly provider capability")
    if evidence["binding"].get("operation") != SLOT_ROUNDS[round_number]:
        _fail("Provider job binding does not match the discussion operation")
    if evidence["result"].get("state") != "succeeded":
        _fail(
            f"Provider job {job_id} is not a successful settled discussion job: "
            f"{evidence['result'].get('state')!r}"
        )
    if evidence["result"].get("scope_violations"):
        _fail(f"Provider job {job_id} recorded workspace scope violations")
    meta = evidence["meta"]
    managed = meta.get("managed_execution")
    if not isinstance(managed, dict):
        _fail(
            f"Provider job {job_id} has no protected managed discussion descriptor"
        )
    if managed.get("kind") != "discussion" or managed.get("version") != EXECUTION_VERSION:
        _fail(f"Provider job {job_id} is not a managed discussion job")
    if managed.get("assignment_digest") != assignment["digest"]:
        _fail(
            f"Provider job {job_id} was not launched for its protected assignment"
        )
    if managed.get("job_id") != job_id:
        _fail(f"Provider job {job_id} descriptor names another job")
    if managed.get("plan_id") != plan_id or managed.get("step_id") != step_id:
        _fail(f"Provider job {job_id} descriptor names another managed step")
    if evidence["task_original_sha256"] != assignment["payload"]["task_source_sha256"]:
        _fail(f"Provider job {job_id} task bytes do not match its assignment")
    workspace = Path(str(meta.get("workspace") or ""))
    if not workspace.is_absolute():
        _fail(f"Provider job {job_id} has no absolute workspace")
    canonical = identity["root"]
    if meta.get("canonical_workspace") not in {None, canonical}:
        _fail(f"Provider job {job_id} ran in another canonical workspace")
    baseline = meta.get("git_baseline")
    if not isinstance(baseline, dict):
        _fail(f"Provider job {job_id} has no Git baseline evidence")
    workspace_evidence, _current = _source_workspace_evidence(
        workspace, baseline, canonical
    )
    operation = SLOT_ROUNDS[round_number]
    mapped = _b1().normalize_provider_mapping(operation, evidence["payload"])
    mapped_sha256 = _digest(mapped)
    original_payload_sha256 = _digest(evidence["payload"])
    blob = {
        "version": EXECUTION_VERSION,
        "kind": "discussion",
        "plan_id": plan_id,
        "step_id": step_id,
        "cycle": cycle,
        "round": round_number,
        "role": role,
        "job_id": job_id,
        "assignment_event_id": assignment["event_id"],
        "assignment_digest": assignment["digest"],
        "candidate_sha256": candidate_sha256,
        "workspace": workspace_evidence,
        "job": {
            "meta": evidence["meta"],
            "result": evidence["result"],
            "provider_result": evidence["provider_result"],
        },
        "hashes": {
            "task_source_sha256": evidence["task_original_sha256"],
            "job_meta_sha256": evidence["meta_sha256"],
            "job_result_sha256": evidence["result_sha256"],
            "provider_result_sha256": evidence["provider_result_sha256"],
            "provider_payload_sha256": evidence["provider_payload_sha256"],
            "original_payload_sha256": original_payload_sha256,
            "mapped_sha256": mapped_sha256,
            "observed_workspace_digest": workspace_evidence["snapshot_digest"],
        },
        "original_payload": evidence["payload"],
        "mapped": mapped,
    }
    blob["evidence_digest"] = _digest(blob)
    # The content-addressed copy embeds its own digest, so a reader can verify
    # both the blob hash and the recorded evidence digest without a side channel.
    blob_sha, _blob_bytes_sha = _publish_json_blob(
        plan_id, blob, f"discussion evidence for job {job_id}"
    )
    payload_spec = {
        "version": EXECUTION_VERSION,
        "role": role,
        "provider": role,
        "operation": operation,
        "round": round_number,
        "cycle": cycle,
        "job_id": job_id,
        "assignment_event_id": assignment["event_id"],
        "assignment_digest": assignment["digest"],
        "candidate_sha256": candidate_sha256,
        "task_source_sha256": evidence["task_original_sha256"],
        "job_meta_sha256": evidence["meta_sha256"],
        "job_result_sha256": evidence["result_sha256"],
        "provider_result_sha256": evidence["provider_result_sha256"],
        "provider_payload_sha256": evidence["provider_payload_sha256"],
        "original_payload_sha256": original_payload_sha256,
        "mapped_sha256": mapped_sha256,
        "observed_workspace_digest": workspace_evidence["snapshot_digest"],
        "workspace": workspace_evidence,
        "evidence_blob_sha256": blob_sha,
        "evidence_digest": blob["evidence_digest"],
    }
    request_digest = _request_digest(
        "discussion-evidence",
        plan_id=plan_id,
        step_id=step_id,
        slot={
            "role": role,
            "round": round_number,
            "cycle": cycle,
            "candidate_sha256": candidate_sha256,
        },
        job_id=job_id,
        evidence_digest=blob["evidence_digest"],
    )
    events = _append_journal(
        plan_id,
        [
            {
                "type": TYPE_EVIDENCE,
                "step_id": step_id,
                "cycle": cycle,
                "payload": payload_spec,
            }
        ],
        _next_operation("dprov", request_digest),
        request_digest,
    )
    payload_spec = events[0]["payload"]
    return {
        **{
            key: payload_spec[key]
            for key in (
                "role",
                "provider",
                "operation",
                "task_source_sha256",
                "job_meta_sha256",
                "job_result_sha256",
                "provider_result_sha256",
                "provider_payload_sha256",
                "original_payload_sha256",
                "mapped_sha256",
                "observed_workspace_digest",
                "assignment_digest",
                "candidate_sha256",
                "evidence_digest",
            )
        },
        "job_id": job_id,
        "evidence_event_id": events[0]["event_id"],
        "payload": evidence["payload"],
    }


def wait_for_source_settled(job_id: str, timeout: float = 15.0) -> None:
    """Best-effort wait outside the plan lock for a readonly job to stop.

    The CLI calls this before submitting provider provenance so the strict
    ingestion path rarely observes the final few milliseconds in which the
    worker is still writing its result. It never infers success; the ingestion
    re-validates every recorded fact and process identity afterwards.
    """
    _require_id(job_id, "job_id")
    path = _jobs_dir() / job_id
    if not path.is_dir():
        _fail(f"Provider job directory does not exist: {job_id}")
    deadline = time.monotonic() + timeout
    while True:
        meta: dict[str, Any] = {}
        if (path / "meta.json").is_file():
            try:
                meta = _read_json(path / "meta.json")
            except Exception:
                meta = {}
        settled = bool(meta) and (path / "result.json").is_file()
        if settled:
            try:
                _require_processes_dead(meta, f"Provider job {job_id}")
            except Exception:
                settled = False
            if settled:
                workspace = meta.get("workspace")
                identity = None
                if isinstance(workspace, str) and workspace:
                    try:
                        identity = _hook("canonical_workspace")(Path(workspace))
                    except Exception:
                        identity = None
                if identity is not None:
                    for record in _live_reservations(identity):
                        if record.get("job_id") == job_id:
                            settled = False
                            break
        if settled:
            return
        if time.monotonic() >= deadline:
            _fail(
                f"Provider job {job_id} did not settle into a drained readonly "
                "state within the bounded wait"
            )
        time.sleep(0.05)


def _assert_no_live_discussion_job(
    journal: dict[str, Any],
    *,
    plan_id: str,
    step_id: str,
    cycle: int,
    round_number: int,
    role: str,
) -> None:
    """Refuse a second live discussion assignment for the same exact slot."""
    for assignment in journal["assignments"]:
        payload = assignment["payload"]
        if (
            assignment["step_id"] != step_id
            or assignment["cycle"] != cycle
            or payload.get("round") != round_number
            or payload.get("role") != role
        ):
            continue
        job_id = payload["job_id"]
        if _evidence_for_job(journal, job_id) is not None:
            continue
        path = _jobs_dir() / job_id
        if not path.is_dir():
            continue
        meta = (
            _read_json(path / "meta.json")
            if (path / "meta.json").is_file()
            else {}
        )
        if meta:
            try:
                _require_processes_dead(meta, f"Prior discussion job {job_id}")
            except Exception as exc:
                _fail(
                    f"Discussion slot {role} round {round_number} already has a "
                    f"live provider job {job_id}: {exc}"
                )
            if not (path / "result.json").is_file():
                _fail(
                    f"Discussion slot {role} round {round_number} has an unsettled "
                    f"provider job {job_id}; wait for its result or preserve it "
                    "before assigning another"
                )


def prepare_discussion(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    round_number: int,
    task_file: Path,
) -> dict[str, Any]:
    """Publish one protected assignment for a readonly discussion job."""
    if role not in {"deepseek", "glm"}:
        _fail(
            "Managed discussion jobs exist only for the reserved deepseek and glm "
            "readonly providers; Codex submits as the trusted coordinator"
        )
    if round_number not in (1, 2, 3):
        _fail("Managed discussion rounds are 1 (proposal), 2 (cross), and 3 (ballot)")
    source = Path(task_file).expanduser().resolve()
    if not source.is_file():
        _fail(f"Discussion task file does not exist: {source}")
    if source.stat().st_size > MAX_TASK_BYTES:
        _fail(f"Discussion task file exceeds {MAX_TASK_BYTES} bytes")
    task_bytes = source.read_bytes()
    task_sha = _sha256_bytes(task_bytes)
    start = _b2().process_start_identity(os.getpid())
    if not isinstance(start, str) or not start:
        _fail("Cannot record a deterministic issuer process-start identity")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        journal = _replay_journal(plan_id)
        current = _step_b1_state(b1_state, step_id)
        candidate_sha256: str | None = None
        if round_number == 3:
            candidate_sha256 = (current.get("candidate") or {}).get("digest")
            if not candidate_sha256:
                _fail("A ballot assignment requires the frozen candidate")
        _require_b1_slot(
            b1_state,
            step_id,
            role,
            round_number,
            current.get("cycle"),
            candidate_sha256,
        )
        _assert_no_live_discussion_job(
            journal,
            plan_id=plan_id,
            step_id=step_id,
            cycle=current["cycle"],
            round_number=round_number,
            role=role,
        )
        next_sequence = len(journal["events"]) + 1
        job_id = "disc-" + _digest(
            {
                "plan_id": plan_id,
                "step_id": step_id,
                "cycle": current["cycle"],
                "round": round_number,
                "role": role,
                "sequence": next_sequence,
            }
        )[:48]
        payload = {
            "version": EXECUTION_VERSION,
            "role": role,
            "provider": role,
            "operation": SLOT_ROUNDS[round_number],
            "round": round_number,
            "cycle": current["cycle"],
            "job_id": job_id,
            "issuer": {"pid": os.getpid(), "start": start},
            "candidate_sha256": candidate_sha256,
            "task_source_sha256": task_sha,
            "task_source_bytes": len(task_bytes),
        }
        request_digest = _request_digest(
            "discussion-assignment",
            plan_id=plan_id,
            step_id=step_id,
            payload=payload,
        )
        events = _append_journal(
            plan_id,
            [
                {
                    "type": TYPE_ASSIGNMENT,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "payload": payload,
                }
            ],
            _next_operation("dassign", request_digest),
            request_digest,
        )
        event = events[0]
        return {
            "version": EXECUTION_VERSION,
            "kind": "discussion",
            "plan_id": plan_id,
            "step_id": step_id,
            "cycle": current["cycle"],
            "round": round_number,
            "role": role,
            "provider": role,
            "operation": SLOT_ROUNDS[round_number],
            "job_id": job_id,
            "candidate_sha256": candidate_sha256,
            "assignment_digest": event["digest"],
            "assignment_event_id": event["event_id"],
            "task_source_sha256": task_sha,
            "workspace": static["canonical_workspace"],
            "task_file": str(source),
        }


def execution_source_validator(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    round_number: int,
    cycle: int,
    candidate_sha256: str | None,
    source: Any,
) -> dict[str, Any]:
    """B1 hook: ingest and return protected provenance for one strict slot."""
    source = _optional_keys(source or {}, {"job_id"}, {"evidence_digest"}, "source")
    job_id = _require_id(source.get("job_id"), "source.job_id")
    indexed = _ingest_discussion_locked(
        plan_id=plan_id,
        step_id=step_id,
        role=role,
        round_number=round_number,
        cycle=cycle,
        candidate_sha256=candidate_sha256,
        job_id=job_id,
    )
    expected = source.get("evidence_digest")
    if expected is not None and expected != indexed["evidence_digest"]:
        _fail("Provider source evidence digest does not match the ingested record")
    return indexed


def validate_discussion_launch(
    descriptor: dict[str, Any], identity: dict[str, Any]
) -> None:
    """Validate a managed discussion launch against the current protected slot."""
    if descriptor.get("kind") != "discussion":
        _fail("Expected a managed discussion descriptor")
    plan_id = descriptor.get("plan_id")
    step_id = descriptor.get("step_id")
    job_id = descriptor.get("job_id")
    _require_id(plan_id, "managed plan_id")
    _require_id(job_id, "managed job_id")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        if identity.get("root") != static.get("canonical_workspace"):
            _fail("Managed discussion launch is in another canonical workspace")
        journal = _replay_journal(plan_id)
        assignment = _assignment_for_job(journal, job_id)
        if assignment["digest"] != descriptor.get("assignment_digest"):
            _fail("Managed discussion launch does not match its protected assignment")
        _require_b1_slot(
            b1_state,
            step_id,
            descriptor.get("role"),
            descriptor.get("round"),
            descriptor.get("cycle"),
            descriptor.get("candidate_sha256"),
        )
        if (_jobs_dir() / job_id).exists():
            _fail(f"Managed discussion job already exists: {job_id}")
        _require_assignment_binding(
            assignment,
            plan_id=plan_id,
            step_id=step_id,
            role=descriptor.get("role"),
            round_number=descriptor.get("round"),
            cycle=descriptor.get("cycle"),
            candidate_sha256=descriptor.get("candidate_sha256"),
            job_id=job_id,
        )


# ---------------------------------------------------------------------------
# Frozen post-consensus execution contract
# ---------------------------------------------------------------------------

# D2 freezes its voted validation policy inside a new explicit contract
# version. Version 1 contracts remain byte-identical and never acquire D2
# authority; D2 operations refuse a version 1 contract.
CONTRACT_VERSION_D2 = 2
D2_VALIDATION_POLICY_VERSION = 1
MAX_VALIDATION_ENTRIES = 32
MAX_VALIDATION_CAPTURE = 8 * 1024 * 1024
MIN_VALIDATION_CAPTURE = 1_024
MAX_VALIDATION_TIMEOUT = 3_600

CONTRACT_KEYS = {
    "version",
    "plan_id",
    "step_id",
    "cycle",
    "candidate_sha256",
    "plan_sha256",
    "manifest_digest",
    "objective",
    "why",
    "relevant_modules",
    "allowed_paths",
    "denied_paths",
    "required_behavior",
    "required_interfaces",
    "tests",
    "acceptance_criteria",
    "required_validation",
    "max_changed_files",
    "target_branch",
    "protected_branches",
    "reporting",
}


def _contract_pattern(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty repository-relative pattern")
    if len(value.encode("utf-8")) > 4_096:
        _fail(f"{label} exceeds 4096 bytes")
    if "\x00" in value or value.startswith("/"):
        _fail(f"{label} must be repository-relative without NUL bytes")
    parts = Path(value).parts
    if any(part == ".." for part in parts):
        _fail(f"{label} must not escape the repository")
    if parts and parts[0] == ".git":
        _fail(f"{label} must not target Git metadata")
    return value


def _contract_patterns(
    value: Any, label: str, *, minimum_items: int = 0
) -> list[str]:
    patterns = _text_list(
        value,
        label,
        minimum_items=minimum_items,
        maximum_items=MAX_PATH_LIST,
    )
    normalized = [
        _contract_pattern(item, f"{label}[{index}]")
        for index, item in enumerate(patterns)
    ]
    if len(set(normalized)) != len(normalized):
        _fail(f"{label} must not repeat a pattern")
    return normalized


def _contract_validation_commands(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail("contract.required_validation must be a non-empty JSON array")
    if len(value) > 32:
        _fail("contract.required_validation has too many commands")
    commands: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for index, entry in enumerate(value):
        label = f"contract.required_validation[{index}]"
        item = _optional_keys(entry, {"argv"}, {"label"}, label)
        argv = item.get("argv")
        if not isinstance(argv, list) or not argv:
            _fail(f"{label}.argv must be a non-empty literal argument array")
        if len(argv) > 64:
            _fail(f"{label}.argv has too many arguments")
        normalized: list[str] = []
        for arg_index, argument in enumerate(argv):
            if not isinstance(argument, str) or not argument:
                _fail(f"{label}.argv[{arg_index}] must be a non-empty string")
            if "\x00" in argument or "\n" in argument or "\r" in argument:
                _fail(f"{label}.argv[{arg_index}] must be one literal argument")
            if len(argument.encode("utf-8")) > 4_096:
                _fail(f"{label}.argv[{arg_index}] is too long")
            normalized.append(argument)
        key = tuple(normalized)
        if key in seen:
            _fail("contract.required_validation repeats a literal command")
        seen.add(key)
        command: dict[str, Any] = {"argv": normalized}
        if item.get("label") is not None:
            command["label"] = _text(
                item.get("label"), f"{label}.label", minimum=2
            )
        commands.append(command)
    return commands


def _mechanically_restrict_contract(
    contract: dict[str, Any],
    constraints: dict[str, Any],
    *,
    cycle: int,
    candidate_sha256: str,
    plan_sha256: str,
    manifest_digest: str,
    static: dict[str, Any],
    snapshot: dict[str, Any],
) -> None:
    """Prove the frozen contract cannot widen the approved design.

    Allowed patterns must be an exact subset of the approved pattern set (a
    provable restriction). Denied patterns must retain every approval (a
    superset). Dropping a criterion or required literal command, or raising the
    file bound, fails. Glob strings are compared as the exact approved globs,
    never resolved as one concrete path.
    """
    if contract["cycle"] != cycle:
        _fail("contract cycle does not match the active B1 cycle")
    if contract["candidate_sha256"] != candidate_sha256:
        _fail("contract does not bind the frozen candidate digest")
    if contract["plan_sha256"] != plan_sha256:
        _fail("contract does not bind the enrolled plan digest")
    if contract["manifest_digest"] != manifest_digest:
        _fail("contract does not bind the enrolled manifest digest")
    if contract["plan_id"] != static["plan_id"] or contract["step_id"] not in {
        step["id"] for step in static["manifest"]["steps"]
    }:
        _fail("contract names another plan or step")
    approved_allowed = set(constraints["allowed_paths"])
    for pattern in contract["allowed_paths"]:
        if pattern not in approved_allowed:
            _fail(
                "contract allowed pattern is not an exact approved pattern: "
                f"{pattern!r}"
            )
    approved_denied = set(constraints["denied_paths"])
    missing_denied = sorted(approved_denied - set(contract["denied_paths"]))
    if missing_denied:
        _fail(
            "contract drops approved denials: " + ", ".join(missing_denied)
        )
    approved_maximum = constraints.get("max_changed_files")
    contract_maximum = contract.get("max_changed_files")
    if approved_maximum is not None:
        if contract_maximum is None:
            _fail("contract drops the approved max_changed_files bound")
        if contract_maximum > approved_maximum:
            _fail("contract widens the approved max_changed_files bound")
    elif contract_maximum is not None and contract_maximum <= 0:
        _fail("contract max_changed_files must be positive")
    approved_criteria = {
        item["id"]: item["text_sha256"] for item in constraints["criteria"]
    }
    contract_criteria = {
        item["id"]: _sha256_bytes(item["text"].encode("utf-8"))
        for item in contract["acceptance_criteria"]
    }
    if contract_criteria != approved_criteria:
        _fail(
            "contract must bind every approved criterion ID to its exact text "
            "digest and may not substitute criteria"
        )
    approved_commands = {
        tuple(item["argv"]) for item in constraints["required_validation"]
    }
    contract_commands = {
        tuple(item["argv"]) for item in contract["required_validation"]
    }
    missing_commands = sorted(approved_commands - contract_commands)
    if missing_commands:
        _fail(
            "contract drops approved required validation argv: "
            + json.dumps(missing_commands[0])
        )
    if contract["version"] == CONTRACT_VERSION_D2:
        if constraints.get("version") != CONTRACT_VERSION_D2:
            _fail(
                "A version 2 contract requires an approved version 2 candidate "
                "validation policy"
            )
        approved_policy = constraints.get("validation_policy")
        if approved_policy != contract.get("validation_policy"):
            _fail(
                "contract validation_policy must exactly equal the approved "
                "candidate policy; it cannot add, drop or widen an invocation"
            )
        if contract["required_validation"] != constraints["required_validation"]:
            _fail(
                "contract required_validation must exactly mirror the approved "
                "mandatory validation invocations"
            )
    elif contract["version"] != EXECUTION_VERSION:
        _fail("contract version is not supported")
    protected = contract["protected_branches"]
    if not protected:
        _fail("contract requires at least one protected branch")
    if not any(item in protected for item in ("main", "master")):
        _fail("contract protected_branches must include main or master")
    target = contract["target_branch"]
    if target in protected or target in {"main", "master"}:
        _fail("contract target branch is main, master, or protected")
    if snapshot.get("branch") != target:
        _fail(
            f"Contract target branch {target!r} is not the current HEAD branch "
            f"{snapshot.get('branch')!r}"
        )
    if snapshot.get("head") is None:
        _fail("Contract freeze requires a repository HEAD commit")


def _normalize_contract_validation_policy(raw: Any) -> dict[str, Any]:
    """Validate the frozen validation-policy bytes without inventing values.

    The contract may repeat the approved policy exactly or mechanically drop an
    optional entry; it can never add, alter or widen one. Full restriction proof
    runs in ``_mechanically_restrict_contract`` against the approved candidate.
    """
    value = _exact_keys(
        raw, {"version", "entries"}, "contract.validation_policy"
    )
    if value.get("version") != D2_VALIDATION_POLICY_VERSION:
        _fail("contract.validation_policy version is not supported")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        _fail("contract.validation_policy.entries must be non-empty")
    if len(entries) > MAX_VALIDATION_ENTRIES:
        _fail("contract.validation_policy has too many entries")
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        label = f"contract.validation_policy.entries[{index}]"
        item = _exact_keys(
            entry,
            {
                "invocation_id",
                "label",
                "argv",
                "cwd",
                "context",
                "purpose",
                "mandatory",
                "expected_exit",
                "timeout_seconds",
                "capture_limit_bytes",
                "environment_policy",
                "ro_enforcement",
                "evidence",
            },
            label,
        )
        invocation_id = item.get("invocation_id")
        if not isinstance(invocation_id, str) or not re.fullmatch(
            r"^V[0-9]{3}$", invocation_id
        ):
            _fail(f"{label}.invocation_id is invalid")
        argv = item.get("argv")
        if not isinstance(argv, list) or not argv:
            _fail(f"{label}.argv must be a non-empty literal argument array")
        if len(argv) > 64:
            _fail(f"{label}.argv has too many arguments")
        clean_argv: list[str] = []
        for arg_index, argument in enumerate(argv):
            if not isinstance(argument, str) or not argument:
                _fail(f"{label}.argv[{arg_index}] must be a non-empty string")
            if len(argument.encode("utf-8")) > 4_096:
                _fail(f"{label}.argv[{arg_index}] is too long")
            if "\x00" in argument or "\n" in argument or "\r" in argument:
                _fail(f"{label}.argv[{arg_index}] must be one literal argument")
            clean_argv.append(argument)
        cwd = item.get("cwd")
        if not isinstance(cwd, str) or not cwd or cwd.startswith("/"):
            _fail(f"{label}.cwd must be repository-relative")
        if any(part == ".." for part in Path(cwd).parts):
            _fail(f"{label}.cwd must not escape the repository")
        if item.get("context") not in {"ordinary_ro", "systems_trusted"}:
            _fail(f"{label}.context is invalid")
        if not isinstance(item.get("mandatory"), bool):
            _fail(f"{label}.mandatory must be a boolean")
        expected_exit = item.get("expected_exit")
        if (
            not isinstance(expected_exit, int)
            or isinstance(expected_exit, bool)
            or not 0 <= expected_exit <= 255
        ):
            _fail(f"{label}.expected_exit is invalid")
        timeout = item.get("timeout_seconds")
        if (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or not 1 <= timeout <= MAX_VALIDATION_TIMEOUT
        ):
            _fail(f"{label}.timeout_seconds is invalid")
        capture = item.get("capture_limit_bytes")
        if (
            not isinstance(capture, int)
            or isinstance(capture, bool)
            or not MIN_VALIDATION_CAPTURE <= capture <= MAX_VALIDATION_CAPTURE
        ):
            _fail(f"{label}.capture_limit_bytes is invalid")
        if item.get("environment_policy") != "minimal_private":
            _fail(f"{label}.environment_policy is not supported")
        if item.get("ro_enforcement") != "required":
            _fail(
                f"{label}.ro_enforcement must be required; observed or "
                "unconfined read-only execution is not an eligible D2 context"
            )
        evidence = item.get("evidence")
        if not isinstance(evidence, dict):
            _fail(f"{label}.evidence must be a JSON object")
        evidence_kind = evidence.get("kind")
        if evidence_kind == "command_check":
            _exact_keys(evidence, {"kind"}, f"{label}.evidence")
            clean_evidence: dict[str, Any] = {"kind": "command_check"}
        elif evidence_kind == "structured_unittest":
            evidence_value = _exact_keys(
                evidence,
                {"kind", "adapter", "report_env", "min_collected", "min_run"},
                f"{label}.evidence",
            )
            adapter = _exact_keys(
                evidence_value.get("adapter"),
                {"id", "version", "path", "sha256"},
                f"{label}.evidence.adapter",
            )
            if adapter.get("id") != "coordinator-stdlib-unittest":
                _fail(f"{label}.evidence.adapter.id is not the pinned adapter")
            if adapter.get("version") != 1:
                _fail(f"{label}.evidence.adapter.version is not supported")
            adapter_path = adapter.get("path")
            if not isinstance(adapter_path, str) or not adapter_path.startswith("/"):
                _fail(f"{label}.evidence.adapter.path must be absolute")
            adapter_sha = adapter.get("sha256")
            if not isinstance(adapter_sha, str) or not DIGEST_RE.fullmatch(
                adapter_sha
            ):
                _fail(f"{label}.evidence.adapter.sha256 is invalid")
            report_env = evidence_value.get("report_env")
            if not isinstance(report_env, str) or not re.fullmatch(
                r"^[A-Z_][A-Z0-9_]{0,63}$", report_env
            ):
                _fail(f"{label}.evidence.report_env is invalid")
            for key in ("min_collected", "min_run"):
                floor = evidence_value.get(key)
                if (
                    not isinstance(floor, int)
                    or isinstance(floor, bool)
                    or not 1 <= floor <= 1_000_000
                ):
                    _fail(f"{label}.evidence.{key} is invalid")
            clean_evidence = {
                "kind": "structured_unittest",
                "adapter": {
                    "id": "coordinator-stdlib-unittest",
                    "version": 1,
                    "path": adapter_path,
                    "sha256": adapter_sha,
                },
                "report_env": report_env,
                "min_collected": evidence_value["min_collected"],
                "min_run": evidence_value["min_run"],
            }
        else:
            _fail(f"{label}.evidence.kind is invalid")
        normalized.append(
            {
                "invocation_id": invocation_id,
                "label": _text(item.get("label"), f"{label}.label", minimum=2),
                "argv": clean_argv,
                "cwd": cwd,
                "context": item["context"],
                "purpose": _text(
                    item.get("purpose"), f"{label}.purpose", minimum=10
                ),
                "mandatory": item["mandatory"],
                "expected_exit": expected_exit,
                "timeout_seconds": timeout,
                "capture_limit_bytes": capture,
                "environment_policy": "minimal_private",
                "ro_enforcement": item["ro_enforcement"],
                "evidence": clean_evidence,
            }
        )
    ids = [entry["invocation_id"] for entry in normalized]
    if len(set(ids)) != len(ids):
        _fail("contract.validation_policy repeats an invocation ID")
    return {"version": D2_VALIDATION_POLICY_VERSION, "entries": normalized}


def _normalize_contract(
    raw: Any,
    *,
    static: dict[str, Any],
    step: dict[str, Any],
    current: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    if len(_canonical_bytes(raw)) > MAX_CONTRACT_BYTES:
        _fail(f"Execution contract exceeds {MAX_CONTRACT_BYTES} bytes")
    if not isinstance(raw, dict):
        _fail("contract must be a JSON object")
    contract_version = raw.get("version")
    keys = set(CONTRACT_KEYS)
    if contract_version == CONTRACT_VERSION_D2:
        keys.add("validation_policy")
    elif contract_version != EXECUTION_VERSION:
        _fail("contract version is not supported")
    value = _exact_keys(raw, keys, "contract")
    contract = {
        "version": value.get("version"),
        "plan_id": value.get("plan_id"),
        "step_id": value.get("step_id"),
        "cycle": value.get("cycle"),
        "candidate_sha256": value.get("candidate_sha256"),
        "plan_sha256": value.get("plan_sha256"),
        "manifest_digest": value.get("manifest_digest"),
        "objective": _text(value.get("objective"), "contract.objective", minimum=20),
        "why": _text(value.get("why"), "contract.why", minimum=20),
        "relevant_modules": _text_list(
            value.get("relevant_modules"), "contract.relevant_modules", minimum_chars=2
        ),
        "allowed_paths": _contract_patterns(
            value.get("allowed_paths"),
            "contract.allowed_paths",
            minimum_items=1,
        ),
        "denied_paths": _contract_patterns(
            value.get("denied_paths"), "contract.denied_paths"
        ),
        "required_behavior": _text_list(
            value.get("required_behavior"),
            "contract.required_behavior",
            minimum_chars=3,
        ),
        "required_interfaces": _text_list(
            value.get("required_interfaces"),
            "contract.required_interfaces",
            minimum_chars=3,
        ),
        "tests": _text_list(value.get("tests"), "contract.tests", minimum_chars=3),
        "acceptance_criteria": [],
        "required_validation": _contract_validation_commands(
            value.get("required_validation")
        ),
        "max_changed_files": value.get("max_changed_files"),
        "target_branch": value.get("target_branch"),
        "protected_branches": value.get("protected_branches"),
        "reporting": _text_list(
            value.get("reporting"), "contract.reporting", minimum_chars=3
        ),
    }
    if contract_version == CONTRACT_VERSION_D2:
        contract["validation_policy"] = _normalize_contract_validation_policy(
            value.get("validation_policy")
        )
    criteria = value.get("acceptance_criteria")
    if not isinstance(criteria, list) or not criteria:
        _fail("contract.acceptance_criteria must be a non-empty JSON array")
    seen_ids: set[str] = set()
    for index, entry in enumerate(criteria):
        label = f"contract.acceptance_criteria[{index}]"
        item = _exact_keys(entry, {"id", "text"}, label)
        criterion_id = item.get("id")
        if not isinstance(criterion_id, str) or not criterion_id:
            _fail(f"{label}.id must be a non-empty string")
        if criterion_id in seen_ids:
            _fail(f"{label}.id {criterion_id!r} is repeated")
        seen_ids.add(criterion_id)
        contract["acceptance_criteria"].append(
            {
                "id": criterion_id,
                "text": _text(item.get("text"), f"{label}.text", minimum=3),
            }
        )
    if not isinstance(contract["target_branch"], str) or not contract["target_branch"]:
        _fail("contract.target_branch must be a non-empty branch name")
    protected = contract["protected_branches"]
    if not isinstance(protected, list) or not protected or not all(
        isinstance(item, str) and item for item in protected
    ):
        _fail("contract.protected_branches must be a non-empty string array")
    if len(set(protected)) != len(protected):
        _fail("contract.protected_branches must not repeat a branch")
    if contract["max_changed_files"] is not None and (
        not isinstance(contract["max_changed_files"], int)
        or isinstance(contract["max_changed_files"], bool)
        or contract["max_changed_files"] <= 0
    ):
        _fail("contract.max_changed_files must be a positive integer or null")
    constraints = (current["candidate"]["candidate"]).get("execution_constraints")
    if not isinstance(constraints, dict):
        _fail("Frozen candidate has no execution constraints")
    _mechanically_restrict_contract(
        contract,
        constraints,
        cycle=current["cycle"],
        candidate_sha256=current["candidate"]["digest"],
        plan_sha256=static["plan_sha256"],
        manifest_digest=static["manifest_digest"],
        static=static,
        snapshot=snapshot,
    )
    return contract


def freeze_contract(
    *,
    plan_id: str,
    step_id: str,
    contract_raw: Any,
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Freeze the detailed post-consensus contract as immutable evidence."""
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        current = _require_consensus(b1_state, step_id)
        identity = _repo_identity(static)
        snapshot = _observe_workspace(
            Path(static["canonical_workspace"]), None, extra_paths=[]
        )
        step = next(
            (
                item
                for item in static["manifest"]["steps"]
                if item["id"] == step_id
            ),
            None,
        )
        if step is None:
            _fail(f"Unknown manifest step {step_id!r}")
        contract = _normalize_contract(
            contract_raw,
            static=static,
            step=step,
            current=current,
            snapshot=snapshot,
        )
        if identity.get("root") != static["canonical_workspace"]:
            _fail("Contract freeze is in another canonical workspace")
        contract_digest = _digest(contract)
        contract_blob_sha, _contract_bytes_sha = _publish_json_blob(
            plan_id, contract, "execution contract"
        )
        journal = _replay_journal(plan_id)
        existing_contracts = [
            event
            for event in journal["contracts"]
            if event["step_id"] == step_id
            and event["payload"].get("candidate_sha256")
            == current["candidate"]["digest"]
        ]
        if existing_contracts:
            if existing_contracts[-1]["payload"]["contract_digest"] == contract_digest:
                return {
                    "plan_id": plan_id,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "candidate_sha256": current["candidate"]["digest"],
                    "contract_digest": contract_digest,
                    "contract": contract,
                    "event_id": existing_contracts[-1]["event_id"],
                    "idempotent": True,
                }
            _fail(
                "A different execution contract is already frozen for this "
                "candidate; it is immutable"
            )
        index = snapshot.get("index") or {}
        payload = {
            "version": EXECUTION_VERSION,
            "candidate_sha256": current["candidate"]["digest"],
            "cycle": current["cycle"],
            "plan_sha256": static["plan_sha256"],
            "manifest_digest": static["manifest_digest"],
            "base_head": snapshot.get("head"),
            "base_branch": snapshot.get("branch"),
            "base_index_sha256": index.get("sha256"),
            "contract_digest": contract_digest,
            "contract_blob_sha256": contract_blob_sha,
            "target_branch": contract["target_branch"],
            "protected_branches": list(contract["protected_branches"]),
        }
        request_digest = _request_digest(
            "execution-contract",
            plan_id=plan_id,
            step_id=step_id,
            contract_digest=contract_digest,
            candidate_sha256=current["candidate"]["digest"],
        )
        selected_operation = operation_id or _next_operation(
            "dcontract", request_digest
        )
        events = _append_journal(
            plan_id,
            [
                {
                    "type": TYPE_CONTRACT,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "payload": payload,
                }
            ],
            selected_operation,
            request_digest,
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "cycle": current["cycle"],
            "candidate_sha256": current["candidate"]["digest"],
            "contract_digest": contract_digest,
            "contract": contract,
            "event_id": events[0]["event_id"],
            "idempotent": False,
        }


def _contract_event_for(
    journal: dict[str, Any], step_id: str, cycle: int, candidate_sha256: str
) -> dict[str, Any] | None:
    matches = [
        event
        for event in journal["contracts"]
        if event["step_id"] == step_id
        and event["cycle"] == cycle
        and event["payload"].get("candidate_sha256") == candidate_sha256
    ]
    if len(matches) > 1:
        _fail("Execution journal contains multiple contracts for one candidate")
    return matches[0] if matches else None


def _load_contract(
    plan_id: str, journal: dict[str, Any], event: dict[str, Any]
) -> dict[str, Any]:
    payload = event["payload"]
    data = _read_blob(
        plan_id, payload["contract_blob_sha256"], "execution contract"
    )
    try:
        contract = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Frozen execution contract is not valid JSON: {exc}")
    if not isinstance(contract, dict) or _digest(contract) != payload["contract_digest"]:
        _fail("Frozen execution contract bytes do not match their recorded digest")
    # The base commit and branch are frozen by the contract event, not invented
    # by the contract author. Attach them after verifying the stored bytes.
    contract = dict(contract)
    contract["base_head"] = payload["base_head"]
    contract["base_branch"] = payload["base_branch"]
    return contract


def _contract_prompt(contract: dict[str, Any], constraints: dict[str, Any]) -> str:
    lines = [
        "# D1 managed execution contract",
        "",
        "This contract is immutable and mechanically restricted from the "
        "unanimously approved candidate constraints.",
        "",
        f"- Plan: `{contract['plan_id']}`",
        f"- Step: `{contract['step_id']}`",
        f"- Cycle: {contract['cycle']}",
        f"- Candidate: `{contract['candidate_sha256']}`",
        f"- Target branch: `{contract['target_branch']}`",
        f"- Protected branches: {', '.join(contract['protected_branches'])}",
        f"- Allowed paths: {', '.join(contract['allowed_paths']) or '(none)'}",
        f"- Denied paths: {', '.join(contract['denied_paths']) or '(none)'}",
        f"- Max changed files: {contract.get('max_changed_files')}",
        "",
        "## Objective",
        "",
        contract["objective"],
        "",
        "## Why",
        "",
        contract["why"],
        "",
        "## Relevant modules",
        "",
        *[f"- {item}" for item in contract["relevant_modules"]],
        "",
        "## Required behavior",
        "",
        *[f"- {item}" for item in contract["required_behavior"]],
        "",
        "## Required interfaces",
        "",
        *[f"- {item}" for item in contract["required_interfaces"]],
        "",
        "## Tests",
        "",
        *[f"- {item}" for item in contract["tests"]],
        "",
        "## Acceptance criteria (stable IDs)",
        "",
        *[
            f"- `{item['id']}`: {item['text']}"
            for item in contract["acceptance_criteria"]
        ],
        "",
        "## Required literal validation argv",
        "",
        *[
            "- `" + json.dumps(item["argv"], ensure_ascii=False) + "`"
            for item in contract["required_validation"]
        ],
        "",
        "## Reporting",
        "",
        *[f"- {item}" for item in contract["reporting"]],
        "",
        "Return only the C implementation payload. `changed_paths` must list "
        "the complete cumulative task delta from the original base exactly; "
        "validation outcomes are reports, not independent acceptance.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Writer intent, claim and worker revalidation
# ---------------------------------------------------------------------------

ATTEMPT_STATES = {
    TYPE_INTENT: "pending",
    TYPE_CLAIM: "claimed",
    TYPE_RESULT: "result",
    TYPE_COMPLETE: "complete",
    TYPE_BLOCKED: "blocked",
    TYPE_ABORTED: "aborted",
}


def _attempt_state(journal: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    events = [
        event
        for event in journal["events"]
        if event["payload"].get("attempt_id") == attempt_id
    ]
    if not events:
        return {"state": "absent", "events": []}
    # A continuation authorization is a recovery fact, not a new execution
    # state. The attempt remains in its drained-failure/aborted state until a
    # fresh intent is published, so replay never misclassifies the attempt.
    state_events = [event for event in events if event["type"] != TYPE_CONTINUATION]
    latest = (state_events or events)[-1]
    state = ATTEMPT_STATES[latest["type"]]
    result = (
        latest["payload"] if latest["type"] == TYPE_RESULT else None
    )
    if result is not None:
        state = result["classification"]
    return {
        "state": state,
        "events": events,
        "latest": latest,
        "result": result,
        "blocked": (
            latest["payload"]
            if latest["type"] == TYPE_BLOCKED
            else next(
                (
                    event["payload"]
                    for event in reversed(events)
                    if event["type"] == TYPE_BLOCKED
                ),
                None,
            )
        ),
    }


def _all_attempt_states(journal: dict[str, Any]) -> list[dict[str, Any]]:
    attempts = sorted(
        {
            event["payload"]["attempt_id"]
            for event in journal["events"]
            if "attempt_id" in event["payload"]
        }
    )
    return [
        {"attempt_id": attempt_id, **_attempt_state(journal, attempt_id)}
        for attempt_id in attempts
    ]


def _attempt_binding(attempt: dict[str, Any]) -> tuple[str | None, int | None, str | None]:
    intents = [event for event in attempt["events"] if event["type"] == TYPE_INTENT]
    if not intents:
        return (None, None, None)
    intent = intents[-1]
    return (
        intent.get("step_id"),
        intent.get("cycle"),
        intent["payload"].get("candidate_sha256"),
    )


def _active_or_blocking_ownership(
    journal: dict[str, Any],
    *,
    step_id: str | None = None,
    cycle: int | None = None,
    candidate_sha256: str | None = None,
    exclude_attempt: str | None = None,
    exclude_attempts: Any = None,
) -> list[str]:
    excluded = set(exclude_attempts or ())
    if exclude_attempt is not None:
        excluded.add(exclude_attempt)
    problems: list[str] = []
    for attempt in _all_attempt_states(journal):
        if attempt["attempt_id"] in excluded:
            continue
        state = attempt["state"]
        if state in {"pending", "claimed", "uncertain", "blocked"}:
            problems.append(f"{attempt['attempt_id']} is {state}")
        elif state in {"drained_failure", "drained_success"}:
            # Residue belongs to one exact design binding. It requires
            # same-attempt continuation only while that binding is current; a
            # new cycle makes the old grant ineligible without erasing its
            # history, and the workspace still has to pass the new design's
            # protected-admission and dirty-overlap checks.
            attempt_step, attempt_cycle, attempt_candidate = _attempt_binding(
                attempt
            )
            same_binding = (
                (step_id is None or attempt_step == step_id)
                and (cycle is None or attempt_cycle == cycle)
                and (
                    candidate_sha256 is None
                    or attempt_candidate == candidate_sha256
                )
            )
            if same_binding:
                problems.append(f"{attempt['attempt_id']} has {state} residue")
    return problems


def _latest_intent_for(
    journal: dict[str, Any], step_id: str, cycle: int, candidate_sha256: str
) -> dict[str, Any] | None:
    matches = [
        event
        for event in journal["intents"]
        if event["step_id"] == step_id
        and event["cycle"] == cycle
        and event["payload"].get("candidate_sha256") == candidate_sha256
    ]
    return matches[-1] if matches else None


def _intents_for_candidate(
    journal: dict[str, Any], step_id: str, cycle: int, candidate_sha256: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in journal["intents"]
        if event["step_id"] == step_id
        and event["cycle"] == cycle
        and event["payload"].get("candidate_sha256") == candidate_sha256
    ]


def _claim_for_job(
    journal: dict[str, Any], job_id: str
) -> dict[str, Any] | None:
    matches = [
        event for event in journal["claims"] if event["payload"].get("job_id") == job_id
    ]
    if len(matches) > 1:
        _fail(f"Execution journal contains duplicate claims for job {job_id}")
    return matches[0] if matches else None


def _result_for_job(
    journal: dict[str, Any], job_id: str
) -> dict[str, Any] | None:
    matches = [
        event for event in journal["results"] if event["payload"].get("job_id") == job_id
    ]
    if len(matches) > 1:
        _fail(f"Execution journal contains duplicate results for job {job_id}")
    return matches[0] if matches else None


def _intent_for_job(
    journal: dict[str, Any], job_id: str
) -> dict[str, Any] | None:
    matches = [
        event for event in journal["intents"] if event["payload"].get("job_id") == job_id
    ]
    if len(matches) > 1:
        _fail(f"Execution journal contains duplicate intents for job {job_id}")
    return matches[0] if matches else None


def _invocation_limit(static: dict[str, Any]) -> int:
    policy = static.get("executor_policy")
    configured: int | None = None
    if isinstance(policy, dict):
        value = policy.get("max_attempts_per_item")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            configured = value
    if configured is None:
        return DEFAULT_INVOCATION_LIMIT
    return min(DEFAULT_INVOCATION_LIMIT, configured)


def _lease_preflight(identity: dict[str, Any]) -> None:
    try:
        assessment = _b2().assess_lease(identity)
    except Exception as exc:
        _fail(f"Repository writer lease state is unavailable; failing closed: {exc}")
    if assessment.get("blocked"):
        _fail(str(assessment.get("message")))


def _protection_manifest_from_intent(
    plan_id: str, intent_payload: dict[str, Any], label: str
) -> dict[str, Any]:
    """Load and verify the versioned protection manifest of a new attempt.

    An attempt that predates the protection evidence is never silently
    upgraded: old partials remain readable, but they cannot authorize a new
    writer or continuation.
    """
    if intent_payload.get("protection_version") != PROTECTION_VERSION:
        _fail(
            f"{label} has no supported protection-manifest version; a new "
            "protected attempt is required"
        )
    digest = intent_payload.get("protection_manifest_digest")
    blob = intent_payload.get("protection_manifest_blob_sha256")
    _require_digest(digest, f"{label} protection manifest digest")
    _require_digest(blob, f"{label} protection manifest blob")
    data = _read_blob(plan_id, blob, f"{label} protection manifest")
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} protection manifest is not valid JSON: {exc}")
    if not isinstance(manifest, dict):
        _fail(f"{label} protection manifest is malformed")
    if manifest.get("version") != PROTECTION_VERSION:
        _fail(f"{label} protection manifest version is unsupported")
    if manifest.get("manifest_sha256") != digest:
        _fail(f"{label} protection manifest digest does not match the intent")
    computed = _digest(
        {
            key: value
            for key, value in manifest.items()
            if key != "manifest_sha256"
        }
    )
    if computed != digest:
        _fail(f"{label} protection manifest content digest does not match")
    return manifest


def _require_manifest_binding(
    manifest: dict[str, Any],
    *,
    plan_id: str,
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract_digest: str,
    plan_sha256: str,
    b1_manifest_digest: str,
    label: str,
) -> None:
    expected = {
        "plan_id": plan_id,
        "step_id": step_id,
        "cycle": cycle,
        "candidate_sha256": candidate_sha256,
        "contract_digest": contract_digest,
        "plan_sha256": plan_sha256,
        "b1_manifest_digest": b1_manifest_digest,
    }
    mismatched = [
        key for key, value in expected.items() if manifest.get(key) != value
    ]
    if mismatched:
        _fail(
            f"{label} protection manifest is not bound to the current execution "
            "identity: " + ", ".join(sorted(mismatched))
        )


def _protected_owned_paths(state: dict[str, Any]) -> list[str]:
    result = state.get("result") or {}
    residue = result.get("residue") if isinstance(result, dict) else None
    if not isinstance(residue, dict):
        return []
    paths = residue.get("cumulative_changed_paths")
    if not isinstance(paths, list):
        return []
    return [path for path in paths if isinstance(path, str) and path]


def _require_owned_outside_protection(
    manifest: dict[str, Any], owned: list[str], label: str
) -> None:
    root_files = {
        entry["path"] for entry in manifest.get("roots") or [] if entry["kind"] == "file"
    }
    root_directories = [
        entry["path"]
        for entry in manifest.get("roots") or []
        if entry["kind"] == "directory"
    ]
    overlap = [
        path
        for path in owned
        if path in root_files
        or any(path == root or path.startswith(root + "/") for root in root_directories)
    ]
    if overlap:
        _fail(
            f"{label}: the declared own-attempt delta overlaps the original "
            "protected-user set at: " + ", ".join(sorted(overlap)[:20])
        )


def _descriptor_from_intent(
    plan_id: str,
    intent: dict[str, Any],
    contract: dict[str, Any],
    constraints: dict[str, Any],
) -> dict[str, Any]:
    payload = intent["payload"]
    return {
        "version": EXECUTION_VERSION,
        "kind": "implementation",
        "plan_id": plan_id,
        "step_id": intent["step_id"],
        "cycle": intent["cycle"],
        "round": None,
        "role": "deepseek",
        "provider": "deepseek",
        "operation": "implementation",
        "job_id": payload["job_id"],
        "attempt_id": payload["attempt_id"],
        "invocation": payload["invocation"],
        "candidate_sha256": payload["candidate_sha256"],
        "contract_digest": payload["contract_digest"],
        "intent_digest": intent["digest"],
        "intent_event_id": intent["event_id"],
        "assignment_digest": intent["digest"],
        "assignment_event_id": intent["event_id"],
        "task_source_sha256": payload["task_source_sha256"],
        "base_snapshot_digest": payload["base_snapshot_digest"],
        "continuation": payload.get("continuation_of") is not None,
        "constraints": constraints,
        "contract": contract,
        "contract_prompt": _contract_prompt(contract, constraints),
        "target_branch": contract["target_branch"],
        "protected_branches": list(contract["protected_branches"]),
        "allowed_paths": list(contract["allowed_paths"]),
        "denied_paths": list(contract["denied_paths"]),
        "max_changed_files": contract.get("max_changed_files"),
    }


def prepare_implementation(
    *,
    plan_id: str,
    step_id: str,
    task_file: Path,
) -> dict[str, Any]:
    """Publish a brief deterministic implementation intent, then release the lock.

    The intent is a fence and immutable input binding, not source-write
    authority. The B2 lease is acquired only after this function returns, in the
    existing nonblocking launch admission path.
    """
    source = Path(task_file).expanduser().resolve()
    if not source.is_file():
        _fail(f"Implementation task file does not exist: {source}")
    if source.stat().st_size > MAX_TASK_BYTES:
        _fail(f"Implementation task file exceeds {MAX_TASK_BYTES} bytes")
    task_sha = _sha256_bytes(source.read_bytes())
    start = _b2().process_start_identity(os.getpid())
    if not isinstance(start, str) or not start:
        _fail("Cannot record a deterministic issuer process-start identity")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        current = _require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = _candidate_constraints(b1_state, step_id)
        journal = _replay_journal(plan_id)
        contract_event = _contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if contract_event is None:
            _fail(
                "No execution contract is frozen for this candidate; run "
                "execution-contract after unanimous consensus"
            )
        contract = _load_contract(plan_id, journal, contract_event)
        _require_no_d2_initial_writer(journal, step_id)
        identity = _repo_identity(static)
        workspace = Path(static["canonical_workspace"])
        latest_intent = _latest_intent_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        continuation: dict[str, Any] | None = None
        attempt_id: str
        invocation = 1
        original_base_digest: str
        original_base_blob: str
        user_baseline_digest: str
        if latest_intent is not None:
            attempt_id = latest_intent["payload"]["attempt_id"]
            state = _attempt_state(journal, attempt_id)
            if state["state"] == "pending":
                job_dir = _jobs_dir() / state["latest"]["payload"]["job_id"]
                if job_dir.exists():
                    _fail(
                        "A D1 implementation intent is pending with an existing job "
                        "directory; finalize or abort it before another writer"
                    )
                issuer = state["latest"]["payload"]["issuer"]
                issuer_probe = _process_probe(issuer)
                same_issuer = (
                    issuer.get("pid") == os.getpid()
                    and issuer.get("start")
                    == _b2().process_start_identity(os.getpid())
                )
                if issuer_probe != "dead" and not same_issuer:
                    _fail(
                        "The pending D1 implementation intent is still owned by a "
                        "live issuer process; only a dead issuer's exact pending "
                        "intent can be safely reissued"
                    )
                snapshot = _observe_workspace(
                    workspace, contract, extra_paths=[]
                )
                _require_branch_and_head(
                    snapshot, contract, "implementation intent"
                )
                if state["latest"]["payload"].get("continuation_of") is None:
                    _require_no_protected_scope_overlap(
                        snapshot, contract, "implementation intent"
                    )
                if (
                    state["latest"]["payload"]["task_source_sha256"] != task_sha
                    or state["latest"]["payload"]["base_snapshot_digest"]
                    != _snapshot_digest(snapshot)
                ):
                    _fail(
                        "A different D1 implementation intent is already pending; "
                        "abort it before preparing another writer"
                    )
                descriptor = _descriptor_from_intent(
                    plan_id, state["latest"], contract, constraints
                )
                pending_manifest = _protection_manifest_from_intent(
                    plan_id,
                    state["latest"]["payload"],
                    "pending implementation intent",
                )
                _require_manifest_binding(
                    pending_manifest,
                    plan_id=plan_id,
                    step_id=step_id,
                    cycle=current["cycle"],
                    candidate_sha256=candidate_sha256,
                    contract_digest=contract_event["payload"]["contract_digest"],
                    plan_sha256=static["plan_sha256"],
                    b1_manifest_digest=static["manifest_digest"],
                    label="pending implementation intent",
                )
                _validate_protection_identity(
                    workspace, pending_manifest, "pending implementation intent"
                )
                _writable_alias_guard(
                    workspace, pending_manifest["roots"]
                )
                descriptor["protection"] = _protection_inputs(pending_manifest)
                descriptor["protection_manifest_digest"] = pending_manifest[
                    "manifest_sha256"
                ]
                descriptor["protection_manifest_blob_sha256"] = state["latest"][
                    "payload"
                ]["protection_manifest_blob_sha256"]
                descriptor["workspace"] = static["canonical_workspace"]
                descriptor["task_file"] = str(source)
                return descriptor
            if state["state"] in {"claimed", "uncertain", "blocked"}:
                _fail(
                    f"D1 implementation attempt {attempt_id} is {state['state']}; "
                    "no second writer can start until its evidence is reconciled"
                )
            if state["state"] in {"complete", "drained_success"}:
                if state["state"] == "drained_success" and _latest(
                    journal["events"], TYPE_COMPLETE, attempt_id=attempt_id
                ) is None:
                    _fail(
                        "The successful result is recorded but its completion "
                        "event is missing; retry execution-finalize before any "
                        "other writer"
                    )
                _fail("This candidate already reached IMPLEMENTATION_COMPLETE")
            if state["state"] == "drained_failure":
                previous = state["result"]
                continuation = next(
                    (
                        event
                        for event in reversed(journal["continuations"])
                        if event["payload"].get("attempt_id") == attempt_id
                        and event["payload"].get("previous_job_id")
                        == previous.get("job_id")
                        and event["payload"].get("evidence_digest")
                        == previous.get("evidence_digest")
                    ),
                    None,
                )
                if continuation is None:
                    _fail(
                        "The previous implementation invocation failed after it "
                        "started; record an evidence-backed same-attempt continuation "
                        "before another provider job"
                    )
                invocation = int(continuation["payload"]["invocation"])
            elif state["state"] in {"aborted", "pre_invocation_abort"}:
                aborted_intents = [
                    event
                    for event in state["events"]
                    if event["type"] == TYPE_INTENT
                ]
                latest_aborted_intent = aborted_intents[-1] if aborted_intents else None
                invocation = max(
                    1,
                    max(
                        (
                            event["payload"]["invocation"]
                            for event in aborted_intents
                        ),
                        default=0,
                    ),
                )
                if (
                    latest_aborted_intent is not None
                    and latest_aborted_intent["payload"].get("continuation_of")
                ):
                    # A provable pre-invocation abort of a continuation keeps
                    # the same-attempt authorization. Reissue must still match
                    # the exact residue snapshot the continuation was bound to.
                    continuation = next(
                        (
                            event
                            for event in journal["continuations"]
                            if event["digest"]
                            == latest_aborted_intent["payload"]["continuation_of"]
                        ),
                        None,
                    )
                    if continuation is None:
                        _fail(
                            "The aborted continuation authorization is missing "
                            "from the execution journal"
                        )
            else:
                _fail(
                    f"D1 implementation attempt {attempt_id} is in an unsupported "
                    f"state {state['state']!r}"
                )
            original_intent = next(
                event
                for event in state["events"]
                if event["type"] == TYPE_INTENT
            )
            original_base_digest = original_intent["payload"][
                "original_base_snapshot_digest"
            ]
            original_base_blob = original_intent["payload"][
                "original_base_blob_sha256"
            ]
            user_baseline_digest = original_intent["payload"][
                "user_baseline_digest"
            ]
        else:
            blocking = _active_or_blocking_ownership(
                journal,
                step_id=step_id,
                cycle=current["cycle"],
                candidate_sha256=candidate_sha256,
            )
            if blocking:
                _fail(
                    "Another D1 implementation attempt still owns execution state: "
                    + "; ".join(blocking)
                )
            attempt_id = _digest(
                {
                    "plan_id": plan_id,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "candidate_sha256": candidate_sha256,
                    "contract_digest": contract_event["payload"]["contract_digest"],
                }
            )
            original_base_digest = ""
            original_base_blob = ""
            user_baseline_digest = ""
        blocking_other = _active_or_blocking_ownership(
            journal,
            step_id=step_id,
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            exclude_attempt=attempt_id,
        )
        if blocking_other:
            _fail(
                "Another D1 implementation attempt still owns execution state: "
                + "; ".join(blocking_other)
            )
        claims = [
            event
            for event in journal["claims"]
            if event["payload"].get("attempt_id") == attempt_id
        ]
        invocation = max(invocation, len(claims) + 1)
        limit = _invocation_limit(static)
        if invocation > limit:
            _fail(
                f"D1 implementation attempt {attempt_id} exhausted its "
                f"{limit}-invocation budget; guidance is required"
            )
        _lease_preflight(identity)
        live = _live_reservations(identity)
        if live:
            _fail(
                "A repository job is still active or draining: "
                + ", ".join(
                    sorted(str(record.get("job_id")) for record in live)
                )
                + ". No second writer can prepare."
            )
        snapshot = _observe_workspace(workspace, contract, extra_paths=[])
        _require_branch_and_head(snapshot, contract, "implementation intent")
        if continuation is None:
            # Fresh writer admission: protected bytes inside the approved
            # scope (including ignored and hidden-index entries) are rejected
            # before any intent, claim, job record or provider process.
            _require_no_protected_scope_overlap(
                snapshot, contract, "implementation intent"
            )
            try:
                _b2().validate_protected_workspace(
                    workspace,
                    target_branch=contract["target_branch"],
                    protected_branches=contract["protected_branches"],
                    allowed_paths=contract["allowed_paths"],
                    denied_paths=contract["denied_paths"],
                    snapshot=snapshot,
                )
            except Exception as exc:
                _fail(f"Protected workspace admission failed: {exc}")
            original_base_digest = _snapshot_digest(snapshot)
            original_base_blob, _ = _publish_json_blob(
                plan_id, snapshot, "original implementation base snapshot"
            )
            user_baseline_digest = _user_baseline_digest(snapshot)
            protection_manifest = derive_protection_manifest(
                workspace,
                snapshot,
                contract,
                plan_id=plan_id,
                step_id=step_id,
                cycle=current["cycle"],
                candidate_sha256=candidate_sha256,
                contract_digest=contract_event["payload"]["contract_digest"],
                plan_sha256=static["plan_sha256"],
                b1_manifest_digest=static["manifest_digest"],
            )
            protection_blob, _ = _publish_json_blob(
                plan_id,
                protection_manifest,
                "original protected-user manifest",
            )
            protection_digest = protection_manifest["manifest_sha256"]
        else:
            # Same-attempt continuation: the current workspace may contain only
            # the exact authorized prior residue. The continuation event is bound
            # to this exact snapshot digest.
            if continuation["payload"]["new_base_snapshot_digest"] != _snapshot_digest(
                snapshot
            ):
                _fail(
                    "Workspace content changed after the continuation was authorized; "
                    "unknown or user-edited residue blocks a new invocation"
                )
            original_base = json.loads(
                _read_blob(
                    plan_id, original_base_blob, "original implementation base"
                ).decode("utf-8")
            )
            if _snapshot_digest(original_base) != original_base_digest:
                _fail("Original implementation base evidence is inconsistent")
            if _user_baseline_digest(original_base) != user_baseline_digest:
                _fail("Original implementation user baseline evidence is inconsistent")
            _require_unchanged_user_baseline(
                original_base, snapshot, "implementation continuation"
            )
            _require_branch_and_head(snapshot, contract, "implementation continuation")
            protection_manifest = _protection_manifest_from_intent(
                plan_id,
                original_intent["payload"],
                "implementation continuation",
            )
            _require_manifest_binding(
                protection_manifest,
                plan_id=plan_id,
                step_id=step_id,
                cycle=current["cycle"],
                candidate_sha256=candidate_sha256,
                contract_digest=contract_event["payload"]["contract_digest"],
                plan_sha256=static["plan_sha256"],
                b1_manifest_digest=static["manifest_digest"],
                label="implementation continuation",
            )
            owned = _protected_owned_paths(state)
            _require_owned_outside_protection(
                protection_manifest, owned, "implementation continuation"
            )
            _validate_protection_identity(
                workspace, protection_manifest, "implementation continuation"
            )
            _writable_alias_guard(
                workspace, protection_manifest["roots"], known_owned=owned
            )
            protection_blob = original_intent["payload"][
                "protection_manifest_blob_sha256"
            ]
            protection_digest = protection_manifest["manifest_sha256"]
        base_digest = _snapshot_digest(snapshot)
        base_blob, _ = _publish_json_blob(
            plan_id, snapshot, "implementation invocation base snapshot"
        )
        index = snapshot.get("index") or {}
        next_sequence = len(journal["events"]) + 1
        job_id = "impl-" + _digest(
            {
                "attempt_id": attempt_id,
                "invocation": invocation,
                "base_snapshot_digest": base_digest,
                "sequence": next_sequence,
            }
        )[:48]
        payload = {
            "version": EXECUTION_VERSION,
            "attempt_id": attempt_id,
            "job_id": job_id,
            "invocation": invocation,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "plan_sha256": static["plan_sha256"],
            "manifest_digest": static["manifest_digest"],
            "provider": "deepseek",
            "operation": "implementation",
            "capability": "workspace_write",
            "issuer": {"pid": os.getpid(), "start": start},
            "base_snapshot_digest": base_digest,
            "base_snapshot_blob_sha256": base_blob,
            "original_base_snapshot_digest": original_base_digest,
            "original_base_blob_sha256": original_base_blob,
            "head": snapshot.get("head"),
            "branch": snapshot.get("branch"),
            "index_sha256": index.get("sha256"),
            "user_baseline_digest": user_baseline_digest,
            "task_source_sha256": task_sha,
            "protection_version": PROTECTION_VERSION,
            "protection_manifest_digest": protection_digest,
            "protection_manifest_blob_sha256": protection_blob,
            "continuation_of": (
                continuation["digest"] if continuation is not None else None
            ),
        }
        request_digest = _request_digest(
            "implementation-intent",
            plan_id=plan_id,
            step_id=step_id,
            payload=payload,
        )
        events = _append_journal(
            plan_id,
            [
                {
                    "type": TYPE_INTENT,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "payload": payload,
                }
            ],
            _next_operation("dintent", request_digest),
            request_digest,
        )
        return {
            "version": EXECUTION_VERSION,
            "kind": "implementation",
            "plan_id": plan_id,
            "step_id": step_id,
            "cycle": current["cycle"],
            "round": None,
            "role": "deepseek",
            "provider": "deepseek",
            "operation": "implementation",
            "job_id": job_id,
            "attempt_id": attempt_id,
            "invocation": invocation,
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "intent_digest": events[0]["digest"],
            "intent_event_id": events[0]["event_id"],
            "assignment_digest": events[0]["digest"],
            "assignment_event_id": events[0]["event_id"],
            "task_source_sha256": task_sha,
            "base_snapshot_digest": base_digest,
            "continuation": continuation is not None,
            "protection": _protection_inputs(protection_manifest),
            "protection_manifest_digest": protection_digest,
            "protection_manifest_blob_sha256": protection_blob,
            "constraints": constraints,
            "contract": contract,
            "contract_prompt": _contract_prompt(contract, constraints),
            "target_branch": contract["target_branch"],
            "protected_branches": list(contract["protected_branches"]),
            "allowed_paths": list(contract["allowed_paths"]),
            "denied_paths": list(contract["denied_paths"]),
            "max_changed_files": contract.get("max_changed_files"),
            "task_file": str(source),
            "workspace": static["canonical_workspace"],
        }


def _repair_binding() -> Any:
    module = _HOOKS.get("review_module")
    if module is None:
        _fail("D2 repair admission is unavailable; failing closed")
    return module()


def _require_no_d2_initial_writer(journal: dict[str, Any], step_id: str) -> None:
    """No second initial writer may escape an allocated/rejected D2 path."""
    allocations = [
        event
        for event in journal.get("repair_allocations", [])
        if event["step_id"] == step_id
    ]
    reviews = [
        event for event in journal.get("reviews", []) if event["step_id"] == step_id
    ]
    if allocations or reviews:
        _fail(
            "This step already entered D2 review/repair ownership; the initial "
            "implementation path is closed. Use the formal repair path."
        )


def prepare_repair_implementation(
    *, plan_id: str, step_id: str, allocation_id: str
) -> dict[str, Any]:
    """Prepare a new versioned repair intent bound to one durable allocation."""
    start = _b2().process_start_identity(os.getpid())
    if not isinstance(start, str) or not start:
        _fail("Cannot record a deterministic repair issuer process identity")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        current = _require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = _candidate_constraints(b1_state, step_id)
        if constraints.get("version") != CONTRACT_VERSION_D2:
            _fail("Formal repair requires an approved version 2 candidate policy")
        journal = _replay_journal(plan_id)
        contract_event = _contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if contract_event is None:
            _fail("No execution contract is frozen for the repair")
        contract = _load_contract(plan_id, journal, contract_event)
        if contract.get("version") != CONTRACT_VERSION_D2:
            _fail("Formal repair requires a frozen version 2 contract")
        identity = _repo_identity(static)
        if identity.get("root") != static["canonical_workspace"]:
            _fail("Repair preparation is in another canonical workspace")
        workspace = Path(static["canonical_workspace"])
        _lease_preflight(identity)
        live = _live_reservations(identity)
        if live:
            _fail(
                "A repository job is still active or draining: "
                + ", ".join(sorted(str(record.get("job_id")) for record in live))
            )
        snapshot = _observe_workspace(workspace, contract, extra_paths=[])
        binding = _repair_binding().repair_admission_locked(
            plan_id=plan_id,
            step_id=step_id,
            allocation_id=allocation_id,
            journal=journal,
            b1_state=b1_state,
            contract=contract,
            contract_event=contract_event,
            snapshot=snapshot,
            static=static,
            constraints=constraints,
            current=current,
            candidate_sha256=candidate_sha256,
        )
        attempt_id = binding["attempt_id"]
        generation = int(binding["generation"])
        existing_intents = [
            event
            for event in journal["intents"]
            if event["payload"].get("repair_allocation_id") == allocation_id
        ]
        if existing_intents:
            latest = existing_intents[-1]
            payload = latest["payload"]
            state = _attempt_state(journal, payload["attempt_id"])
            if state["state"] != "pending":
                _fail(
                    f"The repair attempt is {state['state']}; no second setup can "
                    "reuse this formal slot"
                )
            job_dir = _jobs_dir() / payload["job_id"]
            issuer = payload["issuer"]
            same_issuer = (
                issuer.get("pid") == os.getpid()
                and issuer.get("start") == start
            )
            if job_dir.exists() and not same_issuer:
                _fail(
                    "The pending repair intent has an existing job directory; "
                    "ambiguity blocks setup"
                )
            if _process_probe(issuer) != "dead" and not same_issuer:
                _fail("The pending repair intent is owned by a live issuer process")
            if (
                payload["base_snapshot_digest"]
                != _snapshot_digest(snapshot)
                or payload["repair_contract_digest"]
                != binding["repair_contract_digest"]
            ):
                _fail(
                    "A different pending repair intent exists for this allocation"
                )
            descriptor = _repair_descriptor(
                plan_id,
                step_id,
                current["cycle"],
                candidate_sha256,
                contract,
                contract_event,
                binding,
                latest,
                snapshot,
                static,
                workspace,
            )
            return descriptor
        blocking = _active_or_blocking_ownership(
            journal,
            step_id=step_id,
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            # repair_admission_locked proved the exact settled source/rejection
            # lineage of this allocation, including every accumulated failed
            # ancestor. Only those proven attempts may transfer ownership to the
            # new formal repair; every other residue remains blocking.
            exclude_attempts=binding.get("superseded_attempt_ids") or (),
        )
        if blocking:
            _fail(
                "Another execution attempt still owns state for this step: "
                + "; ".join(blocking)
            )
        protected_contract = dict(contract)
        protected_contract["allowed_paths"] = list(
            binding["repair_contract"]["allowed_paths"]
        )
        protected_contract["denied_paths"] = list(
            binding["repair_contract"]["denied_paths"]
        )
        protection_manifest = derive_protection_manifest(
            workspace,
            snapshot,
            protected_contract,
            plan_id=plan_id,
            step_id=step_id,
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            contract_digest=contract_event["payload"]["contract_digest"],
            plan_sha256=static["plan_sha256"],
            b1_manifest_digest=static["manifest_digest"],
            known_owned=list(binding["owned_paths"]),
        )
        _require_owned_outside_protection(
            protection_manifest,
            list(binding["owned_paths"]),
            "formal repair",
        )
        _writable_alias_guard(
            workspace,
            protection_manifest["roots"],
            known_owned=list(binding["owned_paths"]),
        )
        protection_blob, _ = _publish_json_blob(
            plan_id, protection_manifest, "repair protected-user manifest"
        )
        base_digest = _snapshot_digest(snapshot)
        base_blob, _ = _publish_json_blob(
            plan_id, snapshot, "repair invocation base snapshot"
        )
        task_text = binding["task_text"]
        task_file = Path(binding["task_file"])
        task_sha = _sha256_bytes(task_file.read_bytes())
        next_sequence = len(journal["events"]) + 1
        job_id = "rep-" + _digest(
            {
                "attempt_id": attempt_id,
                "base_snapshot_digest": base_digest,
                "sequence": next_sequence,
            }
        )[:48]
        index = snapshot.get("index") or {}
        payload = {
            "version": EXECUTION_VERSION,
            "attempt_id": attempt_id,
            "job_id": job_id,
            "invocation": 1,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "plan_sha256": static["plan_sha256"],
            "manifest_digest": static["manifest_digest"],
            "provider": "deepseek",
            "operation": "repair",
            "capability": "workspace_write",
            "issuer": {"pid": os.getpid(), "start": start},
            "base_snapshot_digest": base_digest,
            "base_snapshot_blob_sha256": base_blob,
            "original_base_snapshot_digest": binding[
                "original_base_snapshot_digest"
            ],
            "original_base_blob_sha256": binding["original_base_blob_sha256"],
            "head": snapshot.get("head"),
            "branch": snapshot.get("branch"),
            "index_sha256": index.get("sha256"),
            "user_baseline_digest": binding["user_baseline_digest"],
            "task_source_sha256": task_sha,
            "protection_version": PROTECTION_VERSION,
            "protection_manifest_digest": protection_manifest["manifest_sha256"],
            "protection_manifest_blob_sha256": protection_blob,
            "continuation_of": None,
            "repair_allocation_id": allocation_id,
            "repair_contract_digest": binding["repair_contract_digest"],
            "parent_attempt_id": binding["parent_attempt_id"],
            "parent_job_id": binding["parent_job_id"],
            "repair_generation": generation,
        }
        request_digest = _request_digest(
            "repair-intent",
            plan_id=plan_id,
            step_id=step_id,
            payload=payload,
        )
        events = _append_journal(
            plan_id,
            [
                {
                    "type": TYPE_INTENT,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "payload": payload,
                }
            ],
            _next_operation("drepair", request_digest),
            request_digest,
        )
        return _repair_descriptor(
            plan_id,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract,
            contract_event,
            binding,
            events[0],
            snapshot,
            static,
            workspace,
        )


def _repair_descriptor(
    plan_id: str,
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract: dict[str, Any],
    contract_event: dict[str, Any],
    binding: dict[str, Any],
    intent_event: dict[str, Any],
    snapshot: dict[str, Any],
    static: dict[str, Any],
    workspace: Path,
) -> dict[str, Any]:
    payload = intent_event["payload"]
    repair_contract = binding["repair_contract"]
    return {
        "version": EXECUTION_VERSION,
        "kind": "implementation",
        "plan_id": plan_id,
        "step_id": step_id,
        "cycle": cycle,
        "round": None,
        "role": "deepseek",
        "provider": "deepseek",
        "operation": "repair",
        "job_id": payload["job_id"],
        "attempt_id": payload["attempt_id"],
        "invocation": payload["invocation"],
        "candidate_sha256": candidate_sha256,
        "contract_digest": contract_event["payload"]["contract_digest"],
        "intent_digest": intent_event["digest"],
        "intent_event_id": intent_event["event_id"],
        "assignment_digest": intent_event["digest"],
        "assignment_event_id": intent_event["event_id"],
        "task_source_sha256": payload["task_source_sha256"],
        "base_snapshot_digest": payload["base_snapshot_digest"],
        "continuation": False,
        "repair": True,
        "repair_allocation_id": binding["allocation_id"],
        "repair_contract_digest": binding["repair_contract_digest"],
        "repair_generation": binding["generation"],
        "protected_contract_allowed_paths": list(repair_contract["allowed_paths"]),
        "protection": _protection_inputs(
            _protection_manifest_from_intent(
                plan_id, payload, "repair descriptor"
            )
        ),
        "protection_manifest_digest": payload["protection_manifest_digest"],
        "protection_manifest_blob_sha256": payload[
            "protection_manifest_blob_sha256"
        ],
        "constraints": None,
        "contract": contract,
        "contract_prompt": binding["task_text"],
        "target_branch": contract["target_branch"],
        "protected_branches": list(contract["protected_branches"]),
        "allowed_paths": list(repair_contract["allowed_paths"]),
        "denied_paths": list(repair_contract["denied_paths"]),
        "max_changed_files": contract.get("max_changed_files"),
        "task_file": str(binding["task_file"]),
        "workspace": static["canonical_workspace"],
    }


def validate_implementation_launch(
    descriptor: dict[str, Any], identity: dict[str, Any]
) -> None:
    """Validate an implementation launch against its protected intent."""
    plan_id = descriptor.get("plan_id")
    step_id = descriptor.get("step_id")
    job_id = descriptor.get("job_id")
    _require_id(plan_id, "managed plan_id")
    _require_id(job_id, "managed job_id")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        if identity.get("root") != static.get("canonical_workspace"):
            _fail("Managed implementation launch is in another canonical workspace")
        current = _require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = _candidate_constraints(b1_state, step_id)
        journal = _replay_journal(plan_id)
        intent = _intent_for_job(journal, job_id)
        if intent is None:
            _fail(f"Managed implementation job {job_id} has no protected intent")
        if intent["digest"] != descriptor.get("intent_digest"):
            _fail("Managed implementation launch does not match its protected intent")
        payload = intent["payload"]
        superseded_attempts: list[str] = []
        if descriptor.get("operation") != payload.get("operation"):
            _fail("Managed implementation launch operation does not match its intent")
        if bool(descriptor.get("repair")) != bool(
            payload.get("repair_allocation_id")
        ):
            _fail("Managed implementation repair flag does not match its intent")
        if payload.get("repair_allocation_id") is not None:
            repair_snapshot = _observe_workspace(
                Path(identity["root"]), _load_contract(
                    plan_id,
                    journal,
                    _contract_event_for(
                        journal, step_id, current["cycle"], candidate_sha256
                    ),
                ), extra_paths=[]
            )
            repair_admission = _repair_binding().repair_admission_locked(
                plan_id=plan_id,
                step_id=step_id,
                allocation_id=payload["repair_allocation_id"],
                journal=journal,
                b1_state=b1_state,
                contract=_load_contract(
                    plan_id,
                    journal,
                    _contract_event_for(
                        journal, step_id, current["cycle"], candidate_sha256
                    ),
                ),
                contract_event=_contract_event_for(
                    journal, step_id, current["cycle"], candidate_sha256
                ),
                snapshot=repair_snapshot,
                static=static,
                constraints=constraints,
                current=current,
                candidate_sha256=candidate_sha256,
            )
            superseded_attempts = list(
                repair_admission.get("superseded_attempt_ids") or ()
            )
        if payload.get("job_id") != job_id:
            _fail("Managed implementation intent names another job")
        if payload["invocation"] > _invocation_limit(static):
            _fail("Managed implementation intent exceeds the invocation budget")
        if payload["candidate_sha256"] != candidate_sha256:
            _fail("Managed implementation intent is stale against the frozen candidate")
        if payload["cycle"] != current["cycle"]:
            _fail("Managed implementation intent belongs to another cycle")
        if intent["step_id"] != step_id:
            _fail("Managed implementation intent belongs to another step")
        if bool(descriptor.get("continuation")) != (
            payload.get("continuation_of") is not None
        ):
            _fail("Managed implementation continuation flag does not match its intent")
        if _claim_for_job(journal, job_id) is not None:
            _fail("Managed implementation job already has a claim")
        if _result_for_job(journal, job_id) is not None:
            _fail("Managed implementation job already has an invocation result")
        state = _attempt_state(journal, payload["attempt_id"])
        if state["state"] != "pending" or state["latest"]["digest"] != intent["digest"]:
            _fail(
                f"Managed implementation attempt is {state['state']}; another "
                "writer cannot start"
            )
        blocking = _active_or_blocking_ownership(
            journal,
            step_id=step_id,
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            exclude_attempt=payload["attempt_id"],
            exclude_attempts=superseded_attempts,
        )
        if blocking:
            _fail(
                "Another D1 implementation attempt owns execution state: "
                + "; ".join(blocking)
            )
        contract_event = _contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if contract_event is None or (
            contract_event["payload"]["contract_digest"] != payload["contract_digest"]
        ):
            _fail("Managed implementation intent does not match the frozen contract")
        if (_jobs_dir() / job_id).exists():
            _fail(f"Managed implementation job already exists: {job_id}")
        _lease_preflight(identity)
        live = _live_reservations(identity)
        if live:
            _fail(
                "A repository job is still active or draining: "
                + ", ".join(sorted(str(record.get("job_id")) for record in live))
            )


def claim_implementation(
    descriptor: dict[str, Any],
    identity: dict[str, Any],
    lease: Any,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Publish the post-lease claim bound to the exact B2 epoch and ctx."""
    plan_id = descriptor.get("plan_id")
    step_id = descriptor.get("step_id")
    job_id = descriptor.get("job_id")
    _require_id(plan_id, "managed plan_id")
    _require_id(job_id, "managed job_id")
    if not isinstance(getattr(lease, "epoch", None), str):
        _fail("Managed implementation claim requires the actual B2 lease")
    if lease.owner.get("job_id") != job_id:
        _fail("Repository writer lease belongs to another job")
    if lease.owner.get("epoch") != lease.epoch:
        _fail("Repository writer lease epoch is inconsistent")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        if identity.get("root") != static.get("canonical_workspace"):
            _fail("Managed implementation claim is in another canonical workspace")
        current = _require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = _candidate_constraints(b1_state, step_id)
        journal = _replay_journal(plan_id)
        intent = _intent_for_job(journal, job_id)
        if intent is None:
            _fail(f"Managed implementation job {job_id} has no protected intent")
        if intent["digest"] != descriptor.get("intent_digest"):
            _fail("Managed implementation claim does not match its protected intent")
        payload = intent["payload"]
        existing = _claim_for_job(journal, job_id)
        if existing is not None:
            if existing["payload"]["lease"]["epoch"] != lease.epoch:
                _fail("Managed implementation job already claimed another lease")
            return existing["payload"]
        if payload["candidate_sha256"] != candidate_sha256:
            _fail("Managed implementation intent is stale against the frozen candidate")
        if payload["cycle"] != current["cycle"] or intent["step_id"] != step_id:
            _fail("Managed implementation intent moved out of its current binding")
        state = _attempt_state(journal, payload["attempt_id"])
        if state["state"] != "pending" or state["latest"]["digest"] != intent["digest"]:
            _fail(
                f"Managed implementation attempt is {state['state']}; refusing a "
                "second claim"
            )
        if _snapshot_digest(snapshot) != payload["base_snapshot_digest"]:
            _fail(
                "Workspace content changed between the implementation intent and "
                "the authoritative post-lease claim; refusing to start"
            )
        claim_contract_event = _contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        claim_contract = _load_contract(
            plan_id, journal, claim_contract_event
        )
        _require_branch_and_head(snapshot, claim_contract, "implementation claim")
        if payload.get("continuation_of") is None and payload.get(
            "repair_allocation_id"
        ) is None:
            # Re-establish protected pre-existing content at the post-lease
            # admission point using the authoritative snapshot, independently
            # of status-only tracked membership, before publishing the claim.
            # A formal repair is exempt only for its exact attributable parent
            # delta, proven by repair_admission_locked below.
            _require_no_protected_scope_overlap(
                _annotated_snapshot(snapshot, Path(identity["root"])),
                claim_contract,
                "implementation claim",
            )
        claim_workspace = Path(identity["root"])
        claim_manifest = _protection_manifest_from_intent(
            plan_id, payload, "implementation claim"
        )
        _require_manifest_binding(
            claim_manifest,
            plan_id=plan_id,
            step_id=step_id,
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            contract_digest=claim_contract_event["payload"]["contract_digest"],
            plan_sha256=static["plan_sha256"],
            b1_manifest_digest=static["manifest_digest"],
            label="implementation claim",
        )
        _validate_protection_identity(
            claim_workspace, claim_manifest, "implementation claim"
        )
        claim_state = _attempt_state(journal, payload["attempt_id"])
        claim_owned = (
            _protected_owned_paths(claim_state)
            if payload.get("continuation_of") is not None
            else []
        )
        _require_owned_outside_protection(
            claim_manifest, claim_owned, "implementation claim"
        )
        _writable_alias_guard(
            claim_workspace,
            claim_manifest["roots"],
            known_owned=claim_owned,
        )
        superseded_attempts: list[str] = []
        if payload.get("repair_allocation_id") is not None:
            repair_admission = _repair_binding().repair_admission_locked(
                plan_id=plan_id,
                step_id=step_id,
                allocation_id=payload["repair_allocation_id"],
                journal=journal,
                b1_state=b1_state,
                contract=claim_contract,
                contract_event=claim_contract_event,
                snapshot=snapshot,
                static=static,
                constraints=constraints,
                current=current,
                candidate_sha256=candidate_sha256,
            )
            superseded_attempts = list(
                repair_admission.get("superseded_attempt_ids") or ()
            )
        blocking = _active_or_blocking_ownership(
            journal,
            step_id=step_id,
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            exclude_attempt=payload["attempt_id"],
            exclude_attempts=superseded_attempts,
        )
        if blocking:
            _fail(
                "Another execution attempt still owns state for this claim: "
                + "; ".join(blocking)
            )
        lease_meta = {
            "epoch": lease.epoch,
            "owner_path": str(lease.paths["owner"]),
            "lock_path": str(lease.paths["lock"]),
            "lock_dev": lease.owner.get("lock_dev"),
            "lock_ino": lease.owner.get("lock_ino"),
            "job_dir": str(Path(lease.job_dir).resolve()),
            "receipt_path": str(
                _b2().completion_receipt_path(Path(lease.job_dir))
            ),
        }
        claim_facts = {
            "attempt_id": payload["attempt_id"],
            "job_id": job_id,
            "invocation": payload["invocation"],
            "cycle": payload["cycle"],
            "candidate_sha256": payload["candidate_sha256"],
            "contract_digest": payload["contract_digest"],
            "lease": lease_meta,
            "base_snapshot_digest": payload["base_snapshot_digest"],
            "protection_manifest_digest": claim_manifest["manifest_sha256"],
            "head": snapshot.get("head"),
            "branch": snapshot.get("branch"),
            "index_sha256": (snapshot.get("index") or {}).get("sha256"),
            **(
                {
                    "repair_allocation_id": payload["repair_allocation_id"],
                    "repair_contract_digest": payload["repair_contract_digest"],
                }
                if payload.get("repair_allocation_id") is not None
                else {}
            ),
        }
        claim_digest = _digest(claim_facts)
        claim_payload = {
            "version": EXECUTION_VERSION,
            **claim_facts,
            "claim_digest": claim_digest,
        }
        request_digest = _request_digest(
            "implementation-claim",
            plan_id=plan_id,
            step_id=step_id,
            claim_digest=claim_digest,
        )
        events = _append_journal(
            plan_id,
            [
                {
                    "type": TYPE_CLAIM,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "payload": claim_payload,
                }
            ],
            _next_operation("dclaim", request_digest),
            request_digest,
        )
        return events[0]["payload"]


def validate_managed_worker(meta: dict[str, Any]) -> str | None:
    """Worker-side revalidation before any provider invocation.

    Returns a fail-closed reason, or ``None`` when the protected assignment or
    claim still matches the current B1 cycle, candidate and contract, the C
    capability, and the actual B2 lease ownership.
    """
    descriptor = meta.get("managed_execution")
    if not isinstance(descriptor, dict):
        return "Managed execution metadata is malformed; failing closed"
    if descriptor.get("version") != EXECUTION_VERSION:
        return "Managed execution metadata has an unsupported version"
    plan_id = descriptor.get("plan_id")
    job_id = descriptor.get("job_id")
    if not isinstance(plan_id, str) or not isinstance(job_id, str):
        return "Managed execution metadata has no plan or job identity"
    try:
        with _b1().plan_lock(plan_id):
            b1_state = _b1().replay_plan_state_locked(plan_id)
            static = _require_strict_plan(b1_state)
            journal = _replay_journal(plan_id)
            if descriptor.get("kind") == "discussion":
                assignment = _assignment_for_job(journal, job_id)
                if assignment["digest"] != descriptor.get("assignment_digest"):
                    return "Managed discussion assignment no longer matches the job"
                role = descriptor.get("role")
                round_number = descriptor.get("round")
                expected_operation = SLOT_ROUNDS.get(round_number)
                if (
                    role not in {"deepseek", "glm"}
                    or expected_operation is None
                    or descriptor.get("operation") != expected_operation
                ):
                    return "Managed discussion operation is not a reserved readonly slot"
                binding = _c().binding_from_meta(meta)
                if (
                    binding.get("provider") != role
                    or binding.get("operation") != expected_operation
                    or binding.get("capability") != "readonly"
                ):
                    return (
                        "Managed discussion binding is not the reserved readonly "
                        "operation for its assigned role"
                    )
                _require_b1_slot(
                    b1_state,
                    descriptor.get("step_id"),
                    role,
                    round_number,
                    descriptor.get("cycle"),
                    descriptor.get("candidate_sha256"),
                )
                baseline = meta.get("git_baseline")
                workspace = Path(str(meta.get("workspace") or ""))
                if not isinstance(baseline, dict) or not workspace.is_absolute():
                    return "Managed discussion job has no Git baseline evidence"
                identity = _repo_identity(static)
                if (
                    _hook("canonical_workspace")(workspace).get("root")
                    != identity.get("root")
                ):
                    return "Managed discussion job is not in the canonical workspace"
                _lease_preflight(identity)
                current = _observe_workspace(
                    workspace,
                    None,
                    extra_paths=sorted(set((baseline.get("entries") or {}).keys())),
                )
                report = _workspace_changes(baseline, current)
                if (
                    report.get("count")
                    or report.get("head_changed")
                    or report.get("branch_changed")
                    or report.get("index_changed")
                ):
                    return (
                        "Workspace source changed between the discussion assignment "
                        "and provider invocation"
                    )
                return None
            if descriptor.get("kind") != "implementation":
                return "Managed execution kind is unsupported"
            if meta.get("agent") != "deepseek" or meta.get("cli") != "deepseek":
                return "Managed implementation must run as the reserved deepseek writer"
            binding = _c().binding_from_meta(meta)
            if (
                binding.get("operation")
                not in {"implementation", "repair"}
                or binding.get("capability") != "workspace_write"
            ):
                return "Managed implementation binding is not the authorized writer"
            workspace = Path(str(meta.get("workspace") or ""))
            if not workspace.is_absolute():
                return "Managed implementation workspace is not absolute"
            identity = _repo_identity(static)
            if (
                _hook("canonical_workspace")(workspace).get("root")
                != identity.get("root")
            ):
                return "Managed implementation job is not in the canonical workspace"
            lease = meta.get("workspace_lease")
            if not isinstance(lease, dict):
                return "Managed implementation job has no workspace lease record"
            owner = _b2().read_owner(identity)
            if not isinstance(owner, dict):
                return "Managed implementation has no durable B2 owner record"
            if (
                owner.get("job_id") != job_id
                or owner.get("epoch") != lease.get("epoch")
                or owner.get("state") not in {"admission", "supervising"}
            ):
                return "Managed implementation does not own the actual B2 writer lease"
            if (
                owner.get("lock_dev") != lease.get("lock_dev")
                or owner.get("lock_ino") != lease.get("lock_ino")
            ):
                return "Managed implementation lease lock identity changed"
            current = _require_consensus(b1_state, descriptor.get("step_id"))
            constraints, candidate_sha256 = _candidate_constraints(
                b1_state, descriptor.get("step_id")
            )
            intent = _intent_for_job(journal, job_id)
            if intent is None or intent["digest"] != descriptor.get("intent_digest"):
                return "Managed implementation intent does not match the job"
            if binding.get("operation") != intent["payload"].get("operation"):
                return "Managed implementation binding operation changed"
            if bool(descriptor.get("repair_allocation_id")) != bool(
                intent["payload"].get("repair_allocation_id")
            ):
                return "Managed implementation repair binding changed"
            claim = _claim_for_job(journal, job_id)
            if claim is None:
                return "Managed implementation job has no protected claim"
            if claim["payload"]["lease"]["epoch"] != lease.get("epoch"):
                return "Managed implementation claim names another lease epoch"
            if claim["payload"]["claim_digest"] != descriptor.get("claim_digest"):
                return "Managed implementation claim digest changed"
            if intent["payload"]["candidate_sha256"] != candidate_sha256:
                return "Managed implementation intent is stale against the candidate"
            if intent["cycle"] != current["cycle"]:
                return "Managed implementation intent belongs to another cycle"
            contract_event = _contract_event_for(
                journal,
                descriptor.get("step_id"),
                current["cycle"],
                candidate_sha256,
            )
            if contract_event is None:
                return "Managed implementation contract is missing"
            if (
                contract_event["payload"]["contract_digest"]
                != intent["payload"]["contract_digest"]
            ):
                return "Managed implementation contract changed"
            contract = _load_contract(plan_id, journal, contract_event)
            workspace = Path(str(meta.get("workspace") or ""))
            if not workspace.is_absolute():
                return "Managed implementation workspace is not absolute"
            try:
                worker_manifest = _protection_manifest_from_intent(
                    plan_id, intent["payload"], "implementation worker"
                )
                _require_manifest_binding(
                    worker_manifest,
                    plan_id=plan_id,
                    step_id=descriptor.get("step_id"),
                    cycle=current["cycle"],
                    candidate_sha256=candidate_sha256,
                    contract_digest=contract_event["payload"]["contract_digest"],
                    plan_sha256=static["plan_sha256"],
                    b1_manifest_digest=static["manifest_digest"],
                    label="implementation worker",
                )
                if descriptor.get("protection_manifest_digest") != worker_manifest[
                    "manifest_sha256"
                ]:
                    return (
                        "Managed implementation job does not carry the manifest "
                        "bound to its protected intent"
                    )
                _validate_protection_identity(
                    workspace, worker_manifest, "implementation worker"
                )
                worker_owned = (
                    _protected_owned_paths(
                        _attempt_state(
                            journal, intent["payload"]["attempt_id"]
                        )
                    )
                    if intent["payload"].get("continuation_of") is not None
                    else []
                )
                _require_owned_outside_protection(
                    worker_manifest, worker_owned, "implementation worker"
                )
                _writable_alias_guard(
                    workspace,
                    worker_manifest["roots"],
                    known_owned=worker_owned,
                )
            except Exception as exc:
                return (
                    "Managed implementation protection revalidation failed; "
                    f"failing closed: {exc}"
                )
            snapshot = _observe_workspace(workspace, contract, extra_paths=[])
            if _snapshot_digest(snapshot) != claim["payload"]["base_snapshot_digest"]:
                return (
                    "Workspace content changed between the claim and provider "
                    "invocation; refusing to start a writer"
                )
            if (
                snapshot.get("head") != claim["payload"]["head"]
                or snapshot.get("branch") != claim["payload"]["branch"]
            ):
                return "Repository HEAD changed between the claim and provider invocation"
            if intent["payload"].get("continuation_of") is None:
                # Worker-side fresh-writer admission: re-establish protected
                # pre-existing content from raw workspace observation, never
                # from the earlier status-only view, before any provider call.
                # A formal repair is exempt only for its exact parent delta,
                # which repair_admission_locked proves separately below.
                if intent["payload"].get("repair_allocation_id") is None:
                    _require_no_protected_scope_overlap(
                        snapshot, contract, "implementation worker"
                    )
            superseded_attempts: list[str] = []
            if intent["payload"].get("repair_allocation_id") is not None:
                repair_admission = _repair_binding().repair_admission_locked(
                    plan_id=plan_id,
                    step_id=descriptor.get("step_id"),
                    allocation_id=intent["payload"]["repair_allocation_id"],
                    journal=journal,
                    b1_state=b1_state,
                    contract=contract,
                    contract_event=contract_event,
                    snapshot=snapshot,
                    static=static,
                    constraints=constraints,
                    current=current,
                    candidate_sha256=candidate_sha256,
                )
                superseded_attempts = list(
                    repair_admission.get("superseded_attempt_ids") or ()
                )
            blocking = _active_or_blocking_ownership(
                journal,
                step_id=descriptor.get("step_id"),
                cycle=current["cycle"],
                candidate_sha256=candidate_sha256,
                exclude_attempt=intent["payload"]["attempt_id"],
                exclude_attempts=superseded_attempts,
            )
            if blocking:
                return (
                    "Another execution attempt still owns state for this job; "
                    "failing closed: " + "; ".join(blocking)
                )
            return None
    except Exception as exc:
        return f"Managed execution worker validation failed; failing closed: {exc}"


def protection_for_worker(meta: dict[str, Any]) -> dict[str, Any]:
    """Return the typed C protection inputs immediately before provider spawn.

    This repeats the fail-closed manifest, identity and writable-alias checks
    under the plan lock; it is the authoritative pre-effect revalidation and
    never derives authority from the job's own reports.
    """
    descriptor = meta.get("managed_execution")
    if not isinstance(descriptor, dict) or descriptor.get("kind") != "implementation":
        _fail("Worker protection inputs require a managed implementation job")
    plan_id = descriptor.get("plan_id")
    job_id = descriptor.get("job_id")
    _require_id(plan_id, "managed plan_id")
    _require_id(job_id, "managed job_id")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        current = _require_consensus(b1_state, descriptor.get("step_id"))
        constraints, candidate_sha256 = _candidate_constraints(
            b1_state, descriptor.get("step_id")
        )
        journal = _replay_journal(plan_id)
        intent = _intent_for_job(journal, job_id)
        if intent is None or intent["digest"] != descriptor.get("intent_digest"):
            _fail("Managed implementation intent does not match the job")
        contract_event = _contract_event_for(
            journal,
            descriptor.get("step_id"),
            current["cycle"],
            candidate_sha256,
        )
        if contract_event is None:
            _fail("Managed implementation contract is missing")
        workspace = Path(str(meta.get("workspace") or ""))
        if not workspace.is_absolute():
            _fail("Managed implementation workspace is not absolute")
        manifest = _protection_manifest_from_intent(
            plan_id, intent["payload"], "implementation worker"
        )
        _require_manifest_binding(
            manifest,
            plan_id=plan_id,
            step_id=descriptor.get("step_id"),
            cycle=current["cycle"],
            candidate_sha256=candidate_sha256,
            contract_digest=contract_event["payload"]["contract_digest"],
            plan_sha256=static["plan_sha256"],
            b1_manifest_digest=static["manifest_digest"],
            label="implementation worker",
        )
        _validate_protection_identity(workspace, manifest, "implementation worker")
        owned = (
            _protected_owned_paths(
                _attempt_state(journal, intent["payload"]["attempt_id"])
            )
            if intent["payload"].get("continuation_of") is not None
            else []
        )
        _require_owned_outside_protection(
            manifest, owned, "implementation worker"
        )
        _writable_alias_guard(workspace, manifest["roots"], known_owned=owned)
        return _protection_inputs(manifest)


# ---------------------------------------------------------------------------
# Completion evidence and recovery
# ---------------------------------------------------------------------------


def _git_capture(
    workspace: Path,
    args: list[str],
    label: str,
    *,
    maximum: int = MAX_BLOB_BYTES,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> bytes:
    environment = dict(os.environ)
    environment.update(
        {
            "LC_ALL": "C",
            "LANGUAGE": "C",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(workspace), *args],
            capture_output=True,
            timeout=120,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        _fail(f"Timed out capturing {label}")
    except OSError as exc:
        _fail(f"Cannot capture {label}: {exc}")
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        _fail(f"{label} exceeds the {maximum}-byte evidence bound")
    if result.returncode not in accepted_returncodes:
        _fail(
            f"Cannot capture {label}: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    return result.stdout


def _read_worktree_bytes(workspace: Path, path: str) -> bytes | None:
    if not isinstance(path, str) or not path or path.startswith("/"):
        _fail("Workspace evidence path is not a safe relative path")
    parts = Path(path).parts
    if any(part == ".." for part in parts):
        _fail("Workspace evidence path escapes the work tree")
    target = workspace / path
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return None
    except OSError as exc:
        _fail(f"Cannot inspect workspace evidence path {path}: {exc}")
    if stat.S_ISLNK(info.st_mode):
        return os.fsencode(os.readlink(target))
    if not stat.S_ISREG(info.st_mode):
        _fail(f"Unsupported workspace evidence structure at {path}")
    if info.st_size > MAX_BLOB_BYTES:
        _fail(f"Workspace evidence path {path} exceeds the blob bound")
    try:
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        _fail(f"Cannot read workspace evidence path {path}: {exc}")
    try:
        return os.read(descriptor, MAX_BLOB_BYTES + 1)
    finally:
        os.close(descriptor)


def _is_binary(data: bytes | None) -> bool:
    return bool(data) and b"\x00" in data[:8192]


def _base64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _capture_delta_content(
    plan_id: str,
    workspace: Path,
    path: str,
    *,
    current_entry: dict[str, Any] | None,
    deleted: bool,
) -> dict[str, Any]:
    """Capture raw content for one task-delta path inside immutable blobs."""
    if deleted:
        data = _git_capture(
            workspace,
            ["cat-file", "blob", f"HEAD:{path}"],
            f"deleted file content for {path}",
        )
        kind = "deleted"
    else:
        data = _read_worktree_bytes(workspace, path)
        kind = "current"
    if data is None:
        return {
            "kind": kind,
            "content_available": False,
            "sha256": None,
            "size": None,
            "binary": False,
        }
    sha = _sha256_bytes(data)
    blob_sha = _publish_blob(
        plan_id, data, f"raw workspace content for {path}"
    )
    return {
        "kind": kind,
        "content_available": True,
        "sha256": sha,
        "size": len(data),
        "binary": _is_binary(data),
        "content_blob_sha256": blob_sha,
        "content_base64": (
            _base64(data) if len(data) <= 8192 and _is_binary(data) else None
        ),
    }


def _delta_evidence(
    plan_id: str,
    workspace: Path,
    report: dict[str, Any],
) -> dict[str, Any]:
    if report.get("changed_truncated"):
        _fail(
            "Workspace change attribution exceeded the detailed bound; a complete "
            "task delta cannot be frozen"
        )
    paths = list(report.get("paths") or [])
    if len(paths) > MAX_REPORT_PATHS:
        _fail(
            f"Task delta has more than {MAX_REPORT_PATHS} paths; a complete evidence "
            "bundle cannot be frozen"
        )
    # The completion journal event carries the path list. Refuse a delta whose
    # path names alone cannot fit the bounded event before capturing content.
    path_bytes = sum(len(str(path).encode("utf-8")) + 3 for path in paths)
    if path_bytes > 48_000:
        _fail(
            "Task delta path names exceed the bounded execution journal event size"
        )
    details = {
        item.get("path"): item
        for item in report.get("changed") or []
        if isinstance(item, dict)
    }
    entries: list[dict[str, Any]] = []
    deleted_paths: list[str] = []
    new_paths: list[str] = []
    binary_paths: list[str] = []
    current_entries = report.get("_current_entries") or {}
    for path in paths:
        detail = details.get(path) or {}
        current_entry = current_entries.get(path)
        baseline_entry = report.get("_baseline_entries", {}).get(path)
        baseline_status = detail.get("baseline_status")
        current_status = detail.get("current_status")
        deleted = (
            (isinstance(current_entry, dict) and current_entry.get("kind") == "missing")
            or (isinstance(current_status, str) and "D" in current_status)
        )
        new = bool(
            not deleted
            and (
                (
                    isinstance(current_status, str)
                    and (current_status.startswith("?") or current_status.startswith("A"))
                )
                or baseline_entry is None
                or (
                    isinstance(baseline_entry, dict)
                    and baseline_entry.get("kind") == "missing"
                )
            )
        )
        content = _capture_delta_content(
            plan_id,
            workspace,
            path,
            current_entry=current_entry,
            deleted=deleted,
        )
        if deleted:
            deleted_paths.append(path)
        if new:
            new_paths.append(path)
        if content.get("binary"):
            binary_paths.append(path)
        entries.append(
            {
                "path": path,
                "reasons": list(detail.get("reasons") or []),
                "baseline_sha256": detail.get("baseline_sha256"),
                "current_sha256": detail.get("current_sha256"),
                "baseline_status": baseline_status,
                "current_status": current_status,
                "deleted": deleted,
                "new": new,
                **content,
            }
        )
    diff_paths = [path for path in paths if isinstance(path, str)]
    if diff_paths:
        diff = _git_capture(
            workspace,
            [
                "--literal-pathspecs",
                "diff",
                "--binary",
                "--no-color",
                "--no-ext-diff",
                "-M",
                "HEAD",
                "--",
                *diff_paths,
            ],
            "original-base task diff",
        )
    else:
        diff = b""
    # `git diff HEAD` omits untracked additions. Freeze their complete raw
    # content as explicit new-file diffs so the original-base diff evidence
    # includes every task-created path, including binary files.
    diff_parts = [diff] if diff else []
    for path in sorted(new_paths):
        new_diff = _git_capture(
            workspace,
            [
                "diff",
                "--no-index",
                "--binary",
                "--no-color",
                "--no-ext-diff",
                "--",
                "/dev/null",
                path,
            ],
            f"new-file task diff for {path}",
            accepted_returncodes=(0, 1),
        )
        if new_diff:
            diff_parts.append(new_diff)
    diff = b"\n".join(diff_parts)
    diff_sha = _publish_blob(plan_id, diff, "original-base task diff")
    return {
        "paths": paths,
        "entries": entries,
        "new_paths": sorted(new_paths),
        "deleted_paths": sorted(deleted_paths),
        "binary_paths": sorted(binary_paths),
        "diff_sha256": _sha256_bytes(diff),
        "diff_blob_sha256": diff_sha,
        "diff_bytes": len(diff),
        "changed_count": len(paths),
    }


def _proof_file(
    plan_id: str, path: Path, label: str
) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    data = _bounded_file_bytes(path, label)
    return {
        "path": str(path),
        "sha256": _sha256_bytes(data),
        "size": len(data),
        "blob_sha256": _publish_blob(plan_id, data, label),
    }


def _b2_completion(meta: dict[str, Any], job_dir: Path) -> dict[str, Any]:
    try:
        return _b2().completion_evidence(meta, job_dir)
    except Exception as exc:
        _fail(f"Repository lease completion evidence is unavailable: {exc}")


def _job_spawned(meta: dict[str, Any], completion: dict[str, Any]) -> bool:
    if completion.get("kind") == "finalized" and completion.get("final_check"):
        return True
    if completion.get("kind") == "failed_admission":
        return False
    for key in ("worker_pid", "provider_pid", "child_pid", "supervisor_pid"):
        if isinstance(meta.get(key), int) and not isinstance(meta.get(key), bool):
            return True
    return False


def _completion_workspace(
    *,
    plan_id: str,
    static: dict[str, Any],
    contract: dict[str, Any],
    intent: dict[str, Any],
    claim: dict[str, Any],
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Validate current workspace integrity against the original attempt base."""
    workspace = Path(static["canonical_workspace"])
    original_base = json.loads(
        _read_blob(
            plan_id,
            intent["payload"]["original_base_blob_sha256"],
            "original implementation base",
        ).decode("utf-8")
    )
    invocation_base = json.loads(
        _read_blob(
            plan_id,
            intent["payload"]["base_snapshot_blob_sha256"],
            "implementation invocation base",
        ).decode("utf-8")
    )
    if _snapshot_digest(invocation_base) != claim["payload"]["base_snapshot_digest"]:
        _fail("Claim base snapshot does not match the protected intent snapshot")
    if _snapshot_digest(meta.get("git_baseline") or {}) != claim["payload"][
        "base_snapshot_digest"
    ]:
        _fail("The job's B2 baseline does not match the protected claim snapshot")
    completion_manifest = _protection_manifest_from_intent(
        plan_id, intent["payload"], "implementation completion"
    )
    _require_manifest_binding(
        completion_manifest,
        plan_id=plan_id,
        step_id=intent["step_id"],
        cycle=intent["cycle"],
        candidate_sha256=intent["payload"]["candidate_sha256"],
        contract_digest=intent["payload"]["contract_digest"],
        plan_sha256=static["plan_sha256"],
        b1_manifest_digest=static["manifest_digest"],
        label="implementation completion",
    )
    if claim["payload"].get("protection_manifest_digest") != completion_manifest[
        "manifest_sha256"
    ]:
        _fail(
            "The claim protection digest does not match the bound manifest"
        )
    _validate_protection_identity(
        workspace, completion_manifest, "implementation completion"
    )
    extra = sorted(
        set(
            list((original_base.get("entries") or {}).keys())
            + list((invocation_base.get("entries") or {}).keys())
        )
    )
    current = _observe_workspace(workspace, contract, extra_paths=extra)
    _require_branch_and_head(current, contract, "implementation completion")
    _require_unchanged_user_baseline(
        original_base, current, "implementation completion"
    )
    scope = _scope_for_contract(contract)
    try:
        scope_violations = _b2().scope_violations(workspace, original_base, scope)
    except Exception as exc:
        _fail(f"Cannot verify cumulative workspace scope: {exc}")
    if scope_violations:
        _fail(
            "Cumulative workspace scope violations: "
            + "; ".join(scope_violations[:20])
        )
    final_report = _b2().final_integrity_report(
        workspace, meta.get("git_baseline") or {}, scope
    )
    if not final_report.get("supported"):
        _fail(
            "The final workspace integrity observation is unsupported: "
            + str(final_report.get("reason"))
        )
    if final_report.get("scope_violations"):
        _fail(
            "The supervisor final check records scope violations: "
            + "; ".join(final_report["scope_violations"][:20])
        )
    if (
        final_report.get("head_changed")
        or final_report.get("branch_changed")
        or final_report.get("index_changed")
    ):
        _fail(
            "Workspace HEAD, branch, or Git index changed during the implementation"
        )
    report = _workspace_changes(original_base, current)
    report["_current_entries"] = current.get("entries") or {}
    report["_baseline_entries"] = original_base.get("entries") or {}
    delta = _delta_evidence(plan_id, workspace, report)
    _require_owned_outside_protection(
        completion_manifest, delta["paths"], "implementation completion"
    )
    if contract.get("max_changed_files") is not None and delta["changed_count"] > int(
        contract["max_changed_files"]
    ):
        _fail(
            f"Task delta changed {delta['changed_count']} files, above the approved "
            f"limit {contract['max_changed_files']}"
        )
    return {
        "original_base": original_base,
        "invocation_base": invocation_base,
        "current": current,
        "report": report,
        "delta": delta,
    }


def _validate_provider_completion(
    evidence: dict[str, Any],
    meta: dict[str, Any],
    intent_payload: dict[str, Any] | None = None,
) -> list[str]:
    reasons: list[str] = []
    result = evidence["result"]
    provider_result = evidence["provider_result"]
    binding = evidence["binding"]
    expected_operation = str(
        (intent_payload or {}).get("operation") or "implementation"
    )
    if meta.get("agent") != "deepseek" or meta.get("cli") != "deepseek":
        reasons.append("the job did not run as the reserved deepseek provider")
    if binding.get("provider") != "deepseek":
        reasons.append("the provider binding is not deepseek")
    if binding.get("operation") != expected_operation:
        reasons.append(
            f"the provider binding is not the expected {expected_operation} operation"
        )
    if binding.get("capability") != "workspace_write":
        reasons.append("the provider binding is not a workspace-write capability")
    if result.get("state") != "succeeded":
        reasons.append(f"job result state is {result.get('state')!r}")
    if result.get("scope_violations"):
        reasons.append("the worker recorded scope violations")
    if result.get("timed_out") or result.get("cancelled"):
        reasons.append("the worker timed out or was cancelled")
    if result.get("exit_code") not in {0, None}:
        reasons.append(f"the worker exited {result.get('exit_code')!r}")
    if provider_result.get("validated") is not True:
        reasons.append("the C provider result was not validated")
    if provider_result.get("error") is not None:
        reasons.append("the C provider result records an error")
    if provider_result.get("operation") != expected_operation:
        reasons.append(
            f"the C provider result is not an {expected_operation} report"
        )
    if provider_result.get("capability") != "workspace_write":
        reasons.append("the C provider result is not a workspace-write report")
    protection_digest = (intent_payload or {}).get(
        "protection_manifest_digest"
    )
    if not isinstance(protection_digest, str):
        reasons.append(
            "the protected attempt has no versioned protection-manifest evidence"
        )
    else:
        confinement = provider_result.get("confinement")
        if not isinstance(confinement, dict):
            reasons.append(
                "the C provider result has no protected-confinement evidence"
            )
        else:
            if confinement.get("version") != 1:
                reasons.append(
                    "the C protected-confinement evidence version is unsupported"
                )
            if confinement.get("manifest_sha256") != protection_digest:
                reasons.append(
                    "the C confinement evidence does not match the bound "
                    "protection manifest"
                )
            if confinement.get("capability") != "workspace_write":
                reasons.append(
                    "the C confinement evidence is not a workspace-write report"
                )
            if not isinstance(confinement.get("plan_sha256"), str):
                reasons.append(
                    "the C confinement evidence has no applied mount-plan digest"
                )
            if not isinstance(confinement.get("bwrap_argv_sha256"), str):
                reasons.append(
                    "the C confinement evidence has no actual argv digest"
                )
            application = confinement.get("application")
            if not isinstance(application, dict):
                reasons.append(
                    "the C confinement evidence has no application record"
                )
            elif application.get("verified") is not True:
                reasons.append(
                    "the C confinement evidence does not prove the declared "
                    "mounts were applied"
                )
    payload = evidence.get("normalized_payload")
    if not isinstance(payload, dict):
        reasons.append("the C provider result has no valid implementation payload")
    return reasons


def _matches_final_check(
    report: dict[str, Any], current: dict[str, Any], final_check: dict[str, Any]
) -> bool:
    final_report = final_check.get("report")
    if not isinstance(final_report, dict):
        return False
    current_index = (current.get("index") or {}).get("sha256")
    if current_index != final_report.get("index_current_sha256"):
        return False
    if sorted(current.get("status") or []) != sorted(
        final_report.get("current_status") or []
    ):
        return False
    if (current.get("staged") or {}) != (final_report.get("current_staged") or {}):
        return False
    changed = {
        item.get("path"): item.get("current_sha256")
        for item in final_report.get("changed") or []
        if isinstance(item, dict)
    }
    current_entries = current.get("entries") or {}
    for path, expected in changed.items():
        entry = current_entries.get(path)
        actual = entry.get("sha256") if isinstance(entry, dict) else None
        if expected != actual:
            return False
    return True


def _build_attempt_evidence(
    *,
    plan_id: str,
    static: dict[str, Any],
    contract: dict[str, Any],
    intent: dict[str, Any],
    claim: dict[str, Any] | None,
    meta: dict[str, Any] | None,
    job_evidence: dict[str, Any] | None,
    completion: dict[str, Any],
    classification: str,
    reasons: list[str],
    workspace: dict[str, Any] | None,
) -> tuple[dict[str, Any], str, str]:
    """Freeze complete proof references and raw evidence in content-addressed blobs."""
    job_dir = (
        job_evidence["path"]
        if job_evidence is not None
        else _jobs_dir() / intent["payload"]["job_id"]
    )
    proofs: dict[str, Any] = {}
    for name, label in (
        ("meta.json", "job meta"),
        ("result.json", "job result"),
        ("provider-result.json", "provider result"),
        ("final-check.json", "supervisor final check"),
        ("lease-completion.json", "lease completion receipt"),
        ("task.md", "job prompt"),
        ("task-original.md", "job original task"),
    ):
        proof = _proof_file(plan_id, job_dir / name, f"{label} for job {job_dir.name}")
        if proof is not None:
            proofs[name] = proof
    final_snapshot = None
    final_snapshot_blob = None
    delta = None
    change_report = None
    original_base = None
    if workspace is not None:
        original_base = workspace["original_base"]
        final_snapshot = workspace["current"]
        final_snapshot_blob, _ = _publish_json_blob(
            plan_id, final_snapshot, "final implementation snapshot"
        )
        delta = workspace["delta"]
        change_report = {
            key: value
            for key, value in workspace["report"].items()
            if not key.startswith("_")
        }
    evidence = {
        "version": EXECUTION_VERSION,
        "kind": "implementation",
        "plan_id": plan_id,
        "step_id": intent["step_id"],
        "cycle": intent["cycle"],
        "candidate_sha256": intent["payload"]["candidate_sha256"],
        "contract_digest": intent["payload"]["contract_digest"],
        "attempt_id": intent["payload"]["attempt_id"],
        "job_id": intent["payload"]["job_id"],
        "invocation": intent["payload"]["invocation"],
        "classification": classification,
        "reasons": reasons,
        "workspace": static["canonical_workspace"],
        "target_branch": contract["target_branch"],
        "protected_branches": contract["protected_branches"],
        "contract": contract,
        "intent": intent["payload"],
        "claim": claim["payload"] if claim is not None else None,
        "job_result_state": (
            job_evidence["result"].get("state")
            if job_evidence is not None
            else (meta or {}).get("state")
        ),
        "b2": {
            "kind": completion.get("kind"),
            "finalized": bool(completion.get("finalized")),
            "final_check": completion.get("final_check"),
            "reason": completion.get("reason"),
        },
        "proofs": proofs,
        "protection": None,
        "original_base_snapshot_digest": intent["payload"][
            "original_base_snapshot_digest"
        ],
        "original_base_blob_sha256": intent["payload"][
            "original_base_blob_sha256"
        ],
        "invocation_base_snapshot_digest": intent["payload"]["base_snapshot_digest"],
        "final_snapshot_digest": (
            _snapshot_digest(final_snapshot) if final_snapshot is not None else None
        ),
        "final_snapshot_blob_sha256": final_snapshot_blob,
        "user_baseline_digest": intent["payload"]["user_baseline_digest"],
        "cumulative_change_report": change_report,
        "delta": delta,
        "provider_report": (
            job_evidence.get("normalized_payload")
            if job_evidence is not None
            else None
        ),
    }
    if intent["payload"].get("protection_manifest_digest"):
        manifest = _protection_manifest_from_intent(
            plan_id, intent["payload"], "attempt evidence"
        )
        provider_result = (
            job_evidence.get("provider_result") if job_evidence is not None else {}
        )
        evidence["protection"] = {
            "version": PROTECTION_VERSION,
            "manifest_digest": manifest["manifest_sha256"],
            "manifest_blob_sha256": intent["payload"][
                "protection_manifest_blob_sha256"
            ],
            "manifest": manifest,
            "confinement": (
                provider_result.get("confinement")
                if isinstance(provider_result, dict)
                else None
            ),
        }
    evidence["evidence_digest"] = _digest(evidence)
    blob_sha, _bytes_sha = _publish_json_blob(
        plan_id, evidence, f"attempt evidence for job {intent['payload']['job_id']}"
    )
    return evidence, evidence["evidence_digest"], blob_sha


def _completion_payload(
    intent_payload: dict[str, Any],
    evidence: dict[str, Any],
    evidence_digest: str,
    evidence_blob: str,
) -> dict[str, Any]:
    delta = evidence["delta"]
    provider_report = evidence.get("provider_report") or {}
    protection = evidence.get("protection") or {}
    confinement = (
        protection.get("confinement") if isinstance(protection, dict) else None
    )
    repair_fields = {
        key: intent_payload[key]
        for key in ("repair_allocation_id", "parent_attempt_id")
        if intent_payload.get(key) is not None
    }
    return {
        "version": EXECUTION_VERSION,
        "attempt_id": intent_payload["attempt_id"],
        "job_id": intent_payload["job_id"],
        "invocation": intent_payload["invocation"],
        "candidate_sha256": intent_payload["candidate_sha256"],
        "contract_digest": intent_payload["contract_digest"],
        **repair_fields,
        "protection_manifest_digest": protection.get("manifest_digest"),
        "confinement_digest": (
            _digest(confinement) if isinstance(confinement, dict) else None
        ),
        "original_base_snapshot_digest": intent_payload[
            "original_base_snapshot_digest"
        ],
        "final_snapshot_digest": evidence["final_snapshot_digest"],
        "cumulative_changed_paths": list(delta["paths"]),
        "cumulative_changed_digest": _digest(delta["entries"]),
        "evidence_digest": evidence_digest,
        "evidence_blob_sha256": evidence_blob,
        "diff_blob_sha256": delta["diff_blob_sha256"],
        "changed_count": delta["changed_count"],
        "report": {
            "new_paths": delta["new_paths"],
            "deleted_paths": delta["deleted_paths"],
            "binary_paths": delta["binary_paths"],
            "diff_sha256": delta["diff_sha256"],
            "validation_commands": list(
                provider_report.get("validation_commands") or []
            ),
            "validation_outcomes": list(
                provider_report.get("validation_outcomes") or []
            ),
            "remaining_issues": list(
                provider_report.get("remaining_issues") or []
            ),
            "independent_acceptance": "D2_CLOSED",
        },
    }


def _record_result(
    *,
    plan_id: str,
    static: dict[str, Any],
    contract: dict[str, Any],
    intent: dict[str, Any],
    claim: dict[str, Any] | None,
    meta: dict[str, Any] | None,
    job_evidence: dict[str, Any] | None,
    completion: dict[str, Any],
    classification: str,
    reasons: list[str],
    workspace: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence, evidence_digest, evidence_blob = _build_attempt_evidence(
        plan_id=plan_id,
        static=static,
        contract=contract,
        intent=intent,
        claim=claim,
        meta=meta,
        job_evidence=job_evidence,
        completion=completion,
        classification=classification,
        reasons=reasons,
        workspace=workspace,
    )
    payload = intent["payload"]
    proofs = evidence["proofs"]
    delta = evidence.get("delta")
    residue = (
        {
            "final_snapshot_digest": evidence["final_snapshot_digest"],
            "final_snapshot_blob_sha256": evidence["final_snapshot_blob_sha256"],
            "cumulative_changed_paths": (
                delta.get("paths") if isinstance(delta, dict) else []
            ),
            "cumulative_changed_digest": (
                _digest(delta.get("entries")) if isinstance(delta, dict) else None
            ),
            "user_baseline_digest": evidence["user_baseline_digest"],
            "head": (
                workspace["current"].get("head") if workspace is not None else None
            ),
            "index_sha256": (
                (workspace["current"].get("index") or {}).get("sha256")
                if workspace is not None
                else None
            ),
            "branch": (
                workspace["current"].get("branch") if workspace is not None else None
            ),
        }
        if classification in {"drained_failure"}
        else None
    )
    result_payload = {
        "version": EXECUTION_VERSION,
        "attempt_id": payload["attempt_id"],
        "job_id": payload["job_id"],
        "invocation": payload["invocation"],
        "classification": classification,
        **(
            {"repair_allocation_id": payload["repair_allocation_id"]}
            if payload.get("repair_allocation_id") is not None
            else {}
        ),
        "state": evidence.get("job_result_state"),
        "protection_manifest_digest": (
            (evidence.get("protection") or {}).get("manifest_digest")
        ),
        "confinement_digest": (
            _digest(
                (evidence.get("protection") or {}).get("confinement")
            )
            if isinstance(
                (evidence.get("protection") or {}).get("confinement"), dict
            )
            else None
        ),
        "job_meta_sha256": (
            proofs.get("meta.json", {}).get("sha256")
        ),
        "job_result_sha256": (
            proofs.get("result.json", {}).get("sha256")
        ),
        "provider_result_sha256": (
            proofs.get("provider-result.json", {}).get("sha256")
        ),
        "final_check_sha256": (
            proofs.get("final-check.json", {}).get("sha256")
        ),
        "receipt_sha256": (
            proofs.get("lease-completion.json", {}).get("sha256")
        ),
        "evidence_digest": evidence_digest,
        "evidence_blob_sha256": evidence_blob,
        "reasons": list(reasons),
        "residue": residue,
    }
    specs: list[dict[str, Any]] = [
        {
            "type": TYPE_RESULT,
            "step_id": intent["step_id"],
            "cycle": intent["cycle"],
            "payload": result_payload,
        }
    ]
    completed = False
    if classification == "drained_success":
        complete_payload = _completion_payload(
            payload, evidence, evidence_digest, evidence_blob
        )
        if len(_canonical_bytes(complete_payload)) > MAX_EVENT_BYTES - 2_048:
            # The full provider report remains in the immutable evidence blob.
            # A report too large for the bounded journal event is a recorded
            # failure, never a half-published completion or a stuck append.
            completed = False
            classification = "drained_failure"
            reasons = list(reasons) + [
                "the provider completion report exceeds the bounded execution "
                "journal event size; the immutable evidence blob retains it"
            ]
            result_payload["classification"] = classification
            result_payload["reasons"] = list(reasons)
        else:
            specs.append(
                {
                    "type": TYPE_COMPLETE,
                    "step_id": intent["step_id"],
                    "cycle": intent["cycle"],
                    "payload": complete_payload,
                }
            )
            completed = True
    elif classification == "uncertain":
        specs.append(
            {
                "type": TYPE_BLOCKED,
                "step_id": intent["step_id"],
                "cycle": intent["cycle"],
                "payload": {
                    "version": EXECUTION_VERSION,
                    "attempt_id": payload["attempt_id"],
                    "job_id": payload["job_id"],
                    "invocation": payload["invocation"],
                    "state": "SUSPECT",
                    "reasons": list(reasons),
                    "evidence_digest": evidence_digest,
                },
            }
        )
    request_digest = _request_digest(
        "implementation-finalize",
        plan_id=plan_id,
        step_id=intent["step_id"],
        job_id=payload["job_id"],
        classification=classification,
        evidence_digest=evidence_digest,
    )
    events = _append_journal(
        plan_id,
        specs,
        _next_operation("dfinal", request_digest),
        request_digest,
    )
    return {
        "plan_id": plan_id,
        "step_id": intent["step_id"],
        "attempt_id": payload["attempt_id"],
        "job_id": payload["job_id"],
        "invocation": payload["invocation"],
        "classification": classification,
        "completed": completed,
        "state": (
            "REPAIR_APPLIED"
            if completed and payload.get("repair_allocation_id")
            else "IMPLEMENTATION_COMPLETE"
            if completed
            else classification
        ),
        "reasons": list(reasons),
        "evidence_digest": evidence_digest,
        "evidence_blob_sha256": evidence_blob,
        "changed_paths": (
            list(evidence["delta"]["paths"]) if completed else []
        ),
        "event_ids": [event["event_id"] for event in events],
        "closed_gates": CLOSED_GATES,
    }


def _recover_missing_completion(
    plan_id: str,
    journal: dict[str, Any],
    intent: dict[str, Any],
    result_event: dict[str, Any],
) -> dict[str, Any] | None:
    """Complete a torn result/completion append without duplicating evidence.

    ``_record_result`` publishes the result and completion events under one
    operation. A crash between the two files leaves a valid journal prefix with
    a successful result and no completion. Retrying finalize must finish that
    exact immutable completion, not fabricate a second invocation.
    """
    job_id = intent["payload"]["job_id"]
    completion = _latest(journal["events"], TYPE_COMPLETE, job_id=job_id)
    if completion is not None:
        return completion
    if result_event["payload"].get("classification") != "drained_success":
        return None
    evidence = _load_evidence_blob(
        plan_id,
        result_event["payload"]["evidence_blob_sha256"],
        result_event["payload"]["evidence_digest"],
        f"attempt evidence for job {job_id}",
    )
    if not isinstance(evidence.get("delta"), dict):
        _fail("Successful attempt evidence has no complete delta")
    complete_payload = _completion_payload(
        intent["payload"],
        evidence,
        result_event["payload"]["evidence_digest"],
        result_event["payload"]["evidence_blob_sha256"],
    )
    if len(_canonical_bytes(complete_payload)) > MAX_EVENT_BYTES - 2_048:
        _fail("Recovered completion report exceeds the bounded journal event size")
    request_digest = _request_digest(
        "implementation-finalize-recovery",
        plan_id=plan_id,
        step_id=intent["step_id"],
        job_id=job_id,
        evidence_digest=result_event["payload"]["evidence_digest"],
    )
    events = _append_journal(
        plan_id,
        [
            {
                "type": TYPE_COMPLETE,
                "step_id": intent["step_id"],
                "cycle": intent["cycle"],
                "payload": complete_payload,
            }
        ],
        _next_operation("dfinal", request_digest),
        request_digest,
    )
    return events[0]


def _abort_locked(
    *,
    plan_id: str,
    intent: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    payload = intent["payload"]
    request_digest = _request_digest(
        "implementation-abort",
        plan_id=plan_id,
        step_id=intent["step_id"],
        job_id=payload["job_id"],
        reason=reason,
    )
    events = _append_journal(
        plan_id,
        [
            {
                "type": TYPE_ABORTED,
                "step_id": intent["step_id"],
                "cycle": intent["cycle"],
                "payload": {
                    "version": EXECUTION_VERSION,
                    "attempt_id": payload["attempt_id"],
                    "job_id": payload["job_id"],
                    "invocation": payload["invocation"],
                    "reason": reason,
                    "evidence_digest": None,
                },
            }
        ],
        _next_operation("dabort", request_digest),
        request_digest,
    )
    return {
        "plan_id": plan_id,
        "step_id": intent["step_id"],
        "job_id": payload["job_id"],
        "aborted": True,
        "classification": "pre_invocation_abort",
        "reason": reason,
        "event_id": events[0]["event_id"],
    }


def abort_unstarted(
    *,
    plan_id: str,
    step_id: str,
    job_id: str,
    reason: str,
) -> dict[str, Any]:
    """Close an intent as a provable pre-invocation no-start.

    Nothing is inferred from elapsed time or exit codes: a job directory with
    recorded worker/provider/supervisor identities or any durable receipt is
    never relabeled as never-started.
    """
    reason = _text(reason, "abort reason", minimum=3)[:2_000]
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        journal = _replay_journal(plan_id)
        intent = _intent_for_job(journal, job_id)
        if intent is None:
            _fail(f"Unknown D1 implementation intent for job {job_id}")
        if intent["step_id"] != step_id:
            _fail("D1 implementation intent belongs to another step")
        if (
            _result_for_job(journal, job_id) is not None
            or _claim_for_job(journal, job_id) is not None
        ):
            return {
                "plan_id": plan_id,
                "step_id": step_id,
                "job_id": job_id,
                "aborted": False,
                "reason": "the invocation already claimed or produced evidence",
            }
        state = _attempt_state(journal, intent["payload"]["attempt_id"])
        if state["state"] != "pending" or state["latest"]["digest"] != intent["digest"]:
            return {
                "plan_id": plan_id,
                "step_id": step_id,
                "job_id": job_id,
                "aborted": False,
                "reason": (
                    f"the implementation attempt is {state['state']}; only the "
                    "current pending intent can be closed as never started"
                ),
            }
        identity = _repo_identity(static)
        for record in _live_reservations(identity):
            if record.get("job_id") == job_id:
                return {
                    "aborted": False,
                    "reason": "a live repository reservation still names this job",
                }
        job_dir = _jobs_dir() / job_id
        if job_dir.exists():
            meta_path = job_dir / "meta.json"
            if meta_path.is_file():
                meta = _read_json(meta_path)
                for key in (
                    "worker_pid",
                    "provider_pid",
                    "child_pid",
                    "supervisor_pid",
                ):
                    if meta.get(key) is not None:
                        return {
                            "aborted": False,
                            "reason": (
                                f"job {job_id} recorded {key}; a started invocation "
                                "cannot be relabeled as never-started"
                            ),
                        }
                if (job_dir / "result.json").is_file():
                    return {
                        "aborted": False,
                        "reason": (
                            f"job {job_id} published a result; post-invocation "
                            "evidence must be finalized instead"
                        ),
                    }
                if (job_dir / "lease-completion.json").is_file():
                    return {
                        "aborted": False,
                        "reason": f"job {job_id} published a completion receipt",
                    }
            owner = None
            try:
                owner = _b2().read_owner(identity)
            except Exception:
                owner = None
            if owner is not None and owner.get("job_id") == job_id:
                state = owner.get("state")
                if state not in {"failed_admission", "reconciled"}:
                    return {
                        "aborted": False,
                        "reason": (
                            f"repository lease owner for job {job_id} is {state!r}; "
                            "no-start is not provable"
                        ),
                    }
        return _abort_locked(plan_id=plan_id, intent=intent, reason=reason)


def authorize_continuation(
    *,
    plan_id: str,
    step_id: str,
    operator: str,
    authorization: str,
) -> dict[str, Any]:
    """Classify exact own-attempt residue and authorize one same-attempt retry."""
    operator = _text(operator, "continuation operator", minimum=2)
    authorization = _text(authorization, "continuation authorization", minimum=10)
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        current = _require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = _candidate_constraints(b1_state, step_id)
        journal = _replay_journal(plan_id)
        intent = _latest_intent_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if intent is None:
            _fail("No D1 implementation attempt exists for this candidate")
        payload = intent["payload"]
        if payload.get("repair_allocation_id") is not None:
            _fail(
                "A formal repair invocation has no same-attempt continuation. A "
                "claimed failure needs a fresh actual Codex rejection and a new "
                "durable allocation; no retry or refund exists."
            )
        state = _attempt_state(journal, payload["attempt_id"])
        if state["state"] != "drained_failure":
            _fail(
                "Continuation requires a fully drained prior invocation with exact "
                f"own-attempt evidence; current state is {state['state']}"
            )
        result = state["result"]
        residue = result.get("residue")
        if not isinstance(residue, dict):
            _fail("The prior invocation has no attributable residue evidence")
        existing = next(
            (
                event
                for event in reversed(journal["continuations"])
                if event["payload"].get("attempt_id") == payload["attempt_id"]
                and event["payload"].get("previous_job_id") == payload["job_id"]
            ),
            None,
        )
        if existing is not None:
            return {
                "plan_id": plan_id,
                "step_id": step_id,
                "continuation_event_id": existing["event_id"],
                "continuation_digest": existing["digest"],
                "idempotent": True,
            }
        contract_event = _contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if contract_event is None:
            _fail("The execution contract is missing")
        contract = _load_contract(plan_id, journal, contract_event)
        if payload["invocation"] + 1 > _invocation_limit(static):
            _fail(
                "The implementation attempt exhausted its invocation budget; "
                "operator guidance is required before any continuation"
            )
        workspace = Path(static["canonical_workspace"])
        original_base = json.loads(
            _read_blob(
                plan_id,
                intent["payload"]["original_base_blob_sha256"],
                "original implementation base",
            ).decode("utf-8")
        )
        if (
            _snapshot_digest(original_base)
            != intent["payload"]["original_base_snapshot_digest"]
        ):
            _fail("Original implementation base evidence is inconsistent")
        if (
            _user_baseline_digest(original_base)
            != intent["payload"]["user_baseline_digest"]
        ):
            _fail("Original implementation user baseline evidence is inconsistent")
        current_snapshot = _observe_workspace(
            workspace,
            contract,
            extra_paths=sorted(set((original_base.get("entries") or {}).keys())),
        )
        _require_branch_and_head(
            current_snapshot, contract, "implementation continuation"
        )
        _require_unchanged_user_baseline(
            original_base, current_snapshot, "implementation continuation"
        )
        if _snapshot_digest(current_snapshot) != residue.get(
            "final_snapshot_digest"
        ):
            _fail(
                "Workspace bytes changed after the drained invocation; unknown or "
                "user-edited residue blocks continuation"
            )
        continuation_payload = {
            "version": EXECUTION_VERSION,
            "attempt_id": payload["attempt_id"],
            "previous_job_id": payload["job_id"],
            "previous_invocation": payload["invocation"],
            "evidence_digest": result["evidence_digest"],
            "authorization": {
                "operator": operator,
                "text": authorization,
            },
            "new_base_snapshot_digest": _snapshot_digest(current_snapshot),
            "invocation": payload["invocation"] + 1,
        }
        request_digest = _request_digest(
            "implementation-continuation",
            plan_id=plan_id,
            step_id=step_id,
            payload=continuation_payload,
        )
        events = _append_journal(
            plan_id,
            [
                {
                    "type": TYPE_CONTINUATION,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "payload": continuation_payload,
                }
            ],
            _next_operation("dcont", request_digest),
            request_digest,
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "continuation_event_id": events[0]["event_id"],
            "continuation_digest": events[0]["digest"],
            "new_base_snapshot_digest": continuation_payload[
                "new_base_snapshot_digest"
            ],
            "invocation": continuation_payload["invocation"],
            "idempotent": False,
            "closed_gates": CLOSED_GATES,
        }


def finalize_implementation(
    *, plan_id: str, step_id: str, job_id: str | None = None
) -> dict[str, Any]:
    """Reconcile a settled invocation and freeze immutable attempt evidence."""
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = _require_strict_plan(b1_state)
        current = _require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = _candidate_constraints(b1_state, step_id)
        journal = _replay_journal(plan_id)
        selected_job = job_id
        if selected_job is None:
            intent = _latest_intent_for(
                journal, step_id, current["cycle"], candidate_sha256
            )
            if intent is None:
                _fail("No D1 implementation invocation exists to finalize")
            selected_job = intent["payload"]["job_id"]
        intent = _intent_for_job(journal, selected_job)
        if intent is None:
            _fail(f"No D1 implementation intent exists for job {selected_job}")
        if intent["step_id"] != step_id:
            _fail("D1 implementation intent belongs to another step")
        payload = intent["payload"]
        if payload["candidate_sha256"] != candidate_sha256:
            _fail("D1 implementation intent is stale against the current candidate")
        existing_result = _result_for_job(journal, selected_job)
        if existing_result is not None:
            _verify_attempt_artifacts(
                plan_id, journal, payload["attempt_id"]
            )
            completion = _recover_missing_completion(
                plan_id, journal, intent, existing_result
            )
            return {
                "plan_id": plan_id,
                "step_id": step_id,
                "attempt_id": payload["attempt_id"],
                "job_id": selected_job,
                "invocation": payload["invocation"],
                "classification": existing_result["payload"]["classification"],
                "completed": completion is not None,
                "state": (
                    "REPAIR_APPLIED"
                    if completion is not None
                    and payload.get("repair_allocation_id")
                    else "IMPLEMENTATION_COMPLETE"
                    if completion is not None
                    else existing_result["payload"]["classification"]
                ),
                "reasons": existing_result["payload"]["reasons"],
                "evidence_digest": existing_result["payload"]["evidence_digest"],
                "changed_paths": (
                    list(completion["payload"]["cumulative_changed_paths"])
                    if completion is not None
                    else []
                ),
                "idempotent": True,
                "closed_gates": CLOSED_GATES,
            }
        claim = _claim_for_job(journal, selected_job)
        job_dir = _jobs_dir() / selected_job
        contract_event = _contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if contract_event is None:
            _fail("The execution contract is missing")
        contract = _load_contract(plan_id, journal, contract_event)
        if not job_dir.is_dir():
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=None,
                job_evidence=None,
                completion={"kind": "missing", "finalized": False},
                classification=(
                    "pre_invocation_abort" if claim is None else "uncertain"
                ),
                reasons=(
                    ["the job directory is absent; no provider started"]
                    if claim is None
                    else [
                        "the protected claim exists but the job directory is absent; "
                        "ownership cannot be proven"
                    ]
                ),
                workspace=None,
            )
        meta = (
            _read_json(job_dir / "meta.json")
            if (job_dir / "meta.json").is_file()
            else {}
        )
        if not meta:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=None,
                job_evidence=None,
                completion={"kind": "missing", "finalized": False},
                classification="uncertain",
                reasons=["the managed job record is absent or unreadable"],
                workspace=None,
            )
        try:
            completion = _b2_completion(meta, job_dir)
        except Exception as exc:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=None,
                completion={"kind": "unreadable", "finalized": False},
                classification="uncertain",
                reasons=[
                    "durable B2 completion evidence is unreadable and fails closed: "
                    + str(exc)
                ],
                workspace=None,
            )
        if completion.get("kind") == "pending":
            _fail(
                "The implementation job is still running or draining; finalize only "
                "after the immutable B2 receipt is published"
            )
        if completion.get("kind") == "failed_admission":
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=None,
                completion=completion,
                classification="pre_invocation_abort",
                reasons=[
                    "B2 recorded a failed admission with no worker or descendant"
                ],
                workspace=None,
            )
        if claim is None:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=None,
                meta=meta,
                job_evidence=None,
                completion=completion,
                classification="uncertain",
                reasons=[
                    "the job exists but has no protected D1 claim; ownership and "
                    "descent cannot be proven"
                ],
                workspace=None,
            )
        if completion.get("kind") != "finalized":
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=None,
                completion=completion,
                classification="uncertain",
                reasons=[
                    "durable B2 completion evidence is not finalized: "
                    + str(completion.get("reason"))
                ],
                workspace=None,
            )
        try:
            job_evidence = _job_evidence(
                selected_job,
                str(payload.get("operation") or "implementation"),
                "deepseek",
                require_validated=False,
            )
        except Exception as exc:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=None,
                completion=completion,
                classification="uncertain",
                reasons=[
                    "provider job evidence cannot be reconciled and fails closed: "
                    + str(exc)
                ],
                workspace=None,
            )
        lease = meta.get("workspace_lease")
        if not isinstance(lease, dict):
            _fail("The managed implementation job has no B2 lease metadata")
        if claim["payload"]["lease"]["epoch"] != lease.get("epoch"):
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=job_evidence,
                completion=completion,
                classification="uncertain",
                reasons=["the protected claim does not match the job lease epoch"],
                workspace=None,
            )
        managed = meta.get("managed_execution")
        if not isinstance(managed, dict) or (
            managed.get("intent_digest") != intent["digest"]
            or managed.get("claim_digest") != claim["payload"]["claim_digest"]
        ):
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=job_evidence,
                completion=completion,
                classification="uncertain",
                reasons=[
                    "the job's protected intent or claim descriptor was altered"
                ],
                workspace=None,
            )
        if _snapshot_digest(meta.get("git_baseline") or {}) != claim["payload"][
            "base_snapshot_digest"
        ]:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=job_evidence,
                completion=completion,
                classification="uncertain",
                reasons=[
                    "the job baseline does not match the protected claim snapshot"
                ],
                workspace=None,
            )
        reasons = _validate_provider_completion(
            job_evidence, meta, intent["payload"]
        )
        final_check = completion.get("final_check")
        if not isinstance(final_check, dict):
            reasons.append("no supervisor final check is available")
        elif final_check.get("state") != "clean":
            reasons.append(
                f"supervisor final check state is {final_check.get('state')!r}"
            )
        workspace: dict[str, Any] | None = None
        workspace_problem: str | None = None
        try:
            workspace = _completion_workspace(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
            )
        except Exception as exc:
            workspace_problem = str(exc)
        if workspace_problem is not None:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=job_evidence,
                completion=completion,
                classification="uncertain",
                reasons=[*reasons, f"workspace integrity failed: {workspace_problem}"],
                workspace=None,
            )
        if (
            isinstance(final_check, dict)
            and not _matches_final_check(
                workspace["report"], workspace["current"], final_check
            )
        ):
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=job_evidence,
                completion=completion,
                classification="uncertain",
                reasons=[
                    *reasons,
                    "current workspace bytes changed after the supervisor final check",
                ],
                workspace=workspace,
            )
        reported = (
            job_evidence.get("normalized_payload") or {}
        ).get("changed_paths")
        actual = sorted(workspace["delta"]["paths"])
        if not isinstance(reported, list) or len(reported) != len(set(reported)):
            reasons.append("the provider report has no unique changed_paths list")
        elif sorted(reported) != actual:
            reasons.append(
                "provider changed_paths do not reconcile with the cumulative actual "
                "task delta"
            )
        if reasons:
            return _record_result(
                plan_id=plan_id,
                static=static,
                contract=contract,
                intent=intent,
                claim=claim,
                meta=meta,
                job_evidence=job_evidence,
                completion=completion,
                classification="drained_failure",
                reasons=reasons,
                workspace=workspace,
            )
        return _record_result(
            plan_id=plan_id,
            static=static,
            contract=contract,
            intent=intent,
            claim=claim,
            meta=meta,
            job_evidence=job_evidence,
            completion=completion,
            classification="drained_success",
            reasons=[],
            workspace=workspace,
        )


def _verify_attempt_artifacts(
    plan_id: str, journal: dict[str, Any], attempt_id: str
) -> None:
    """Fail closed when any immutable artifact an attempt references is gone.

    Derived views and idempotent recovery must not present completion from a
    journal whose referenced evidence, diff, snapshot or contract blobs were
    deleted or altered. Historical facts are re-validated from content hashes;
    no live process or network is consulted.
    """
    events = [
        event
        for event in journal["events"]
        if event["payload"].get("attempt_id") == attempt_id
    ]
    results = [event for event in events if event["type"] == TYPE_RESULT]
    if not results:
        return
    intents = {
        event["payload"]["job_id"]: event
        for event in events
        if event["type"] == TYPE_INTENT
    }
    if not intents:
        _fail("Attempt evidence has no protected intent")
    for result_event in results:
        result = result_event["payload"]
        intent = intents.get(result.get("job_id"))
        if intent is None:
            _fail("Attempt result has no matching protected intent")
        payload = intent["payload"]
        evidence = _load_evidence_blob(
            plan_id,
            result["evidence_blob_sha256"],
            result["evidence_digest"],
            f"attempt {attempt_id} evidence",
        )
        if evidence.get("evidence_digest") != result["evidence_digest"]:
            _fail("Attempt evidence digest does not match its result event")
        for key, label in (
            ("base_snapshot_blob_sha256", "attempt invocation base snapshot"),
            ("original_base_blob_sha256", "attempt original base snapshot"),
        ):
            _read_blob(plan_id, payload[key], label)
        if payload.get("protection_manifest_digest"):
            manifest = _protection_manifest_from_intent(
                plan_id, payload, f"attempt {attempt_id}"
            )
            protection = evidence.get("protection")
            if not isinstance(protection, dict):
                _fail("Attempt evidence has no protection evidence")
            if protection.get("manifest_digest") != manifest["manifest_sha256"]:
                _fail(
                    "Attempt protection evidence does not match its manifest"
                )
            if protection.get("manifest_blob_sha256") != payload.get(
                "protection_manifest_blob_sha256"
            ):
                _fail(
                    "Attempt protection manifest blob reference does not match "
                    "its protected intent"
                )
        if evidence.get("final_snapshot_blob_sha256") is not None:
            final_bytes = _read_blob(
                plan_id,
                evidence["final_snapshot_blob_sha256"],
                "attempt final snapshot",
            )
            final_snapshot = json.loads(final_bytes.decode("utf-8"))
            if _snapshot_digest(final_snapshot) != evidence.get(
                "final_snapshot_digest"
            ):
                _fail("Attempt final snapshot does not match its recorded digest")
        delta = evidence.get("delta")
        if isinstance(delta, dict):
            diff = _read_blob(
                plan_id, delta.get("diff_blob_sha256"), "attempt diff"
            )
            if _sha256_bytes(diff) != delta.get("diff_sha256"):
                _fail("Attempt diff does not match its recorded digest")
            entries = delta.get("entries")
            if not isinstance(entries, list):
                _fail("Attempt delta entries are malformed")
            for entry in entries:
                if not isinstance(entry, dict):
                    _fail("Attempt delta entry is malformed")
                content_sha = entry.get("content_blob_sha256")
                if content_sha is None:
                    if entry.get("content_available"):
                        _fail("Attempt delta entry has no raw content reference")
                    continue
                _read_blob(
                    plan_id, content_sha, "attempt changed-path raw content"
                )
                if entry.get("sha256") != content_sha:
                    _fail(
                        "Attempt changed-path raw content hash does not match "
                        "its recorded digest"
                    )
        proofs = evidence.get("proofs")
        if not isinstance(proofs, dict):
            _fail("Attempt evidence has no immutable proof references")
        for name, proof in sorted(proofs.items()):
            if not isinstance(proof, dict):
                _fail(f"Attempt proof reference {name!r} is malformed")
            _read_blob(
                plan_id, proof.get("blob_sha256"), f"attempt proof {name}"
            )
    last_intent = intents.get(results[-1]["payload"].get("job_id"))
    if last_intent is None:
        _fail("Attempt evidence has no protected intent for its last result")
    contract_event = _contract_event_for(
        journal,
        last_intent["step_id"],
        last_intent["cycle"],
        last_intent["payload"]["candidate_sha256"],
    )
    if contract_event is None:
        _fail("Attempt evidence has no frozen contract event")
    _load_contract(plan_id, journal, contract_event)


def refuse_closed_gate(action: str) -> None:
    """Structurally refuse every D2/E acceptance or completion operation."""
    _fail(
        f"{action} is closed in D1. Review acceptance, formal repair dispatch, "
        "independent validation execution, PR/CI/MERGED completion and dependency "
        "opening are implemented only by later slices; D1 stops at "
        "IMPLEMENTATION_COMPLETE and never marks a plan item done."
    )


# ---------------------------------------------------------------------------
# Derived views and cycle fencing
# ---------------------------------------------------------------------------


def _completion_source_drift(
    plan_id: str,
    journal: dict[str, Any],
    attempt_id: str,
    contract: dict[str, Any],
) -> bool:
    """Return whether current source bytes differ from the completed attempt."""
    results = [
        event
        for event in journal["events"]
        if event["type"] == TYPE_RESULT
        and event["payload"].get("attempt_id") == attempt_id
    ]
    intents = [
        event
        for event in journal["events"]
        if event["type"] == TYPE_INTENT
        and event["payload"].get("attempt_id") == attempt_id
    ]
    if not results or not intents:
        _fail("Completed attempt is missing its result or intent evidence")
    result = results[-1]["payload"]
    intent = intents[-1]["payload"]
    evidence = _load_evidence_blob(
        plan_id,
        result["evidence_blob_sha256"],
        result["evidence_digest"],
        f"attempt {attempt_id} evidence",
    )
    workspace_value = evidence.get("workspace")
    if not isinstance(workspace_value, str) or not Path(workspace_value).is_absolute():
        _fail("Completed attempt evidence has no absolute workspace")
    original_base = json.loads(
        _read_blob(
            plan_id,
            intent["original_base_blob_sha256"],
            "original implementation base",
        ).decode("utf-8")
    )
    invocation_base = json.loads(
        _read_blob(
            plan_id,
            intent["base_snapshot_blob_sha256"],
            "implementation invocation base",
        ).decode("utf-8")
    )
    extra = sorted(
        set(
            list((original_base.get("entries") or {}).keys())
            + list((invocation_base.get("entries") or {}).keys())
        )
    )
    current = _observe_workspace(
        Path(workspace_value), contract, extra_paths=extra
    )
    return _snapshot_digest(current) != evidence.get("final_snapshot_digest")


def _step_execution_view(
    plan_id: str,
    state: dict[str, Any],
    journal: dict[str, Any],
    step: dict[str, Any],
) -> dict[str, Any]:
    b1 = _b1()
    current = state["steps"][step["id"]]
    stage = b1.stage_of(current)
    budget = {
        "limit": FORMAL_REPAIR_LIMIT,
        "used": 0,
        "remaining": FORMAL_REPAIR_LIMIT,
        "lineage": "per-step across designs and restarts",
        "consumption": "CLOSED_UNTIL_D2",
    }
    view: dict[str, Any] = {
        "stage": "DISCUSSION_PENDING",
        "next_action": None,
        "missing_actions": [],
        "blocked_reasons": [],
        "attempt": None,
        "formal_repair_budget": budget,
    }
    blockers = b1.dependency_blockers(step)
    if blockers:
        view["stage"] = "DEPENDENCY_BLOCKED"
        view["blocked_reasons"] = list(blockers)
        view["next_action"] = (
            "this step remains DEPENDENCY_BLOCKED until later independently "
            "verified MERGED evidence exists; D1 opens no dependency"
        )
        return view
    if current.get("outcome") != b1.STAGE_CONSENSUS:
        view["missing_actions"] = [
            action
            for action in b1._step_missing_actions(step, current)
        ]
        view["next_action"] = (
            view["missing_actions"][0] if view["missing_actions"] else None
        )
        return view
    candidate = current.get("candidate") or {}
    candidate_sha = candidate.get("digest")
    contract_event = (
        _contract_event_for(journal, step["id"], current["cycle"], candidate_sha)
        if candidate_sha
        else None
    )
    if contract_event is None:
        view["stage"] = "AWAITING_CONTRACT"
        view["next_action"] = (
            "freeze the detailed post-consensus execution contract with "
            "execution-contract --contract-file"
        )
        view["missing_actions"] = [view["next_action"]]
        return view
    contract_document = _load_contract(plan_id, journal, contract_event)
    contract_digest = contract_event["payload"]["contract_digest"]
    intents = _intents_for_candidate(
        journal, step["id"], current["cycle"], candidate_sha
    )
    attempt_ids = []
    for intent in intents:
        attempt_id = intent["payload"]["attempt_id"]
        if attempt_id not in attempt_ids:
            attempt_ids.append(attempt_id)
    attempt_id = attempt_ids[-1] if attempt_ids else None
    attempt_view = None
    if attempt_id is not None:
        attempt_state = _attempt_state(journal, attempt_id)
        _verify_attempt_artifacts(plan_id, journal, attempt_id)
        attempt_intents = [
            event
            for event in attempt_state["events"]
            if event["type"] == TYPE_INTENT
        ]
        attempt_results = [
            event
            for event in attempt_state["events"]
            if event["type"] == TYPE_RESULT
        ]
        latest_result = (
            attempt_results[-1]["payload"] if attempt_results else None
        )
        attempt_view = {
            "attempt_id": attempt_id,
            "candidate_sha256": candidate_sha,
            "contract_digest": contract_digest,
            "state": attempt_state["state"],
            "invocations": len(
                [
                    event
                    for event in attempt_state["events"]
                    if event["type"] == TYPE_CLAIM
                ]
            ),
            "job_id": (
                attempt_intents[-1]["payload"]["job_id"]
                if attempt_intents
                else None
            ),
            "invocation": (
                attempt_intents[-1]["payload"]["invocation"]
                if attempt_intents
                else None
            ),
            "classification": (
                latest_result.get("classification")
                if isinstance(latest_result, dict)
                else None
            ),
            "evidence_digest": (
                latest_result.get("evidence_digest")
                if isinstance(latest_result, dict)
                else None
            ),
            "changed_paths": [],
            "protection_manifest_digest": (
                attempt_intents[-1]["payload"].get("protection_manifest_digest")
                if attempt_intents
                else None
            ),
            "confinement_digest": (
                latest_result.get("confinement_digest")
                if isinstance(latest_result, dict)
                else None
            ),
            "reasons": (
                list(latest_result.get("reasons") or [])
                if isinstance(latest_result, dict)
                else []
            ),
        }
    view["attempt"] = attempt_view
    if (
        attempt_id is not None
        and attempt_intents
        and attempt_intents[-1]["payload"].get("protection_manifest_digest")
    ):
        try:
            protection_manifest = _protection_manifest_from_intent(
                plan_id,
                attempt_intents[-1]["payload"],
                "execution view",
            )
        except Exception as exc:
            view["stage"] = "BLOCKED"
            view["blocked_reasons"] = [
                f"protection manifest evidence is unavailable: {exc}"
            ]
            view["next_action"] = (
                "restore the immutable protection manifest evidence; no "
                "completion or continuation can be derived without it"
            )
            return view
        attempt_view["protection"] = {
            "manifest_digest": protection_manifest["manifest_sha256"],
            "protected_roots": protection_manifest["counts"][
                "protected_roots"
            ],
            "ancestor_anchors": protection_manifest["counts"][
                "ancestor_anchors"
            ],
            "extra_mount_argv_bytes": protection_manifest["counts"][
                "extra_mount_argv_bytes"
            ],
            "mutable_stat_paths": protection_manifest["counts"].get(
                "mutable_stat_paths"
            ),
            "coverage": protection_manifest["coverage"]["mode"],
            "recursive_ignored_content_hashes": protection_manifest[
                "coverage"
            ]["recursive_ignored_content_hashes"],
        }
    if attempt_id is None:
        view["stage"] = "READY_TO_IMPLEMENT"
        view["next_action"] = (
            "start the managed deepseek implementation with the frozen contract "
            "and approved constraints"
        )
        view["missing_actions"] = [view["next_action"]]
        return view
    completion = _latest(
        journal["events"], TYPE_COMPLETE, attempt_id=attempt_id
    )
    block = _latest(journal["events"], TYPE_BLOCKED, attempt_id=attempt_id)
    if completion is not None:
        view["stage"] = "IMPLEMENTATION_COMPLETE"
        view["next_action"] = (
            "D1 is complete at IMPLEMENTATION_COMPLETE. Independent review, "
            "validation, repairs, PR/CI/merge and dependency opening are closed "
            "until D2/E; the plan item is not done."
        )
        view["missing_actions"] = []
        drift = _completion_source_drift(
            plan_id, journal, attempt_id, contract_document
        )
        view["source_drift"] = drift
        if drift:
            view["blocked_reasons"] = [
                "the workspace no longer matches the immutable completed "
                "snapshot; later source drift makes the attempt ineligible for "
                "acceptance or continuation"
            ]
            view["next_action"] = (
                "IMPLEMENTATION_COMPLETE evidence is now ineligible because the "
                "workspace drifted after completion; preserve the current bytes "
                "and request explicit reconciliation. D1 never auto-reverts them."
            )
        if attempt_view is not None:
            attempt_view["changed_paths"] = list(
                completion["payload"]["cumulative_changed_paths"]
            )
            attempt_view["state"] = "complete"
            attempt_view["source_drift"] = drift
        return view
    if attempt_state := _attempt_state(journal, attempt_id):
        classification = (
            attempt_state["result"].get("classification")
            if isinstance(attempt_state.get("result"), dict)
            else None
        )
        if classification == "drained_success" and completion is None:
            view["stage"] = "COMPLETION_INTERRUPTED"
            view["blocked_reasons"] = [
                "the successful result is recorded but its immutable completion "
                "event was not published"
            ]
            view["next_action"] = (
                "retry execution-finalize to finish the interrupted completion "
                "append; no second invocation is admitted"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if classification == "uncertain":
            view["stage"] = "BLOCKED"
            view["blocked_reasons"] = list(
                (attempt_state["result"] or {}).get("reasons") or []
            )
            view["next_action"] = (
                "reconcile the suspect attempt evidence explicitly; D1 never "
                "auto-reverts residue or starts a duplicate writer"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if classification == "drained_failure":
            continuation = next(
                (
                    event
                    for event in reversed(journal["continuations"])
                    if event["payload"].get("attempt_id") == attempt_id
                    and event["payload"].get("previous_job_id")
                    == (attempt_state["result"] or {}).get("job_id")
                ),
                None,
            )
            if continuation is None:
                view["stage"] = "CONTINUATION_REQUIRED"
                view["blocked_reasons"] = list(
                    (attempt_state["result"] or {}).get("reasons") or []
                )
                view["next_action"] = (
                    "review the drained failure and authorize one exact same-attempt "
                    "continuation with execution-continue; otherwise the residue "
                    "stays blocked"
                )
                view["missing_actions"] = [view["next_action"]]
            else:
                view["stage"] = "READY_TO_CONTINUE"
                view["next_action"] = (
                    "prepare the authorized same-attempt continuation invocation"
                )
                view["missing_actions"] = [view["next_action"]]
            return view
        if attempt_state["state"] == "claimed":
            view["stage"] = "CLAIMED"
            view["next_action"] = (
                "wait for the claimed invocation to settle, then finalize its "
                "immutable evidence"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if attempt_state["state"] == "pending":
            view["stage"] = "INTENT_PENDING"
            view["next_action"] = (
                "the protected intent is pending; allow its single nonblocking "
                "lease admission or abort it only when no start is provable"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if attempt_state["state"] in {"aborted", "pre_invocation_abort"}:
            view["stage"] = "READY_TO_IMPLEMENT"
            view["next_action"] = (
                "the previous invocation provably never started; prepare a fresh "
                "bounded invocation"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
    if block is not None:
        view["stage"] = block["payload"]["state"]
        view["blocked_reasons"] = list(block["payload"]["reasons"])
        view["next_action"] = (
            "suspect or blocked residue requires explicit evidence reconciliation"
        )
        view["missing_actions"] = [view["next_action"]]
        return view
    view["stage"] = "READY_TO_IMPLEMENT"
    view["next_action"] = (
        "no invocation evidence is active; prepare the managed implementation"
    )
    view["missing_actions"] = [view["next_action"]]
    return view


def execution_overlay(*, plan_id: str, state: dict[str, Any]) -> dict[str, Any]:
    """Derive D1 execution stage, next action and missing evidence.

    The overlay is computed only from the immutable B1 ledger and the execution
    journal. It never marks an item done or claims review/release completion.
    """
    static = _plan_static(state)
    journal = _replay_journal(plan_id)
    steps: dict[str, Any] = {}
    for step in static["manifest"]["steps"]:
        steps[step["id"]] = _step_execution_view(
            plan_id, state, journal, step
        )
    ordered = [steps[step["id"]] for step in static["manifest"]["steps"]]
    unfinished = [
        view for view in ordered if view["stage"] != "IMPLEMENTATION_COMPLETE"
    ]
    if unfinished:
        plan_stage = unfinished[0]["stage"]
        next_action = unfinished[0]["next_action"]
        missing = [
            f"{step['id']}: {action}"
            for step in static["manifest"]["steps"]
            for action in steps[step["id"]]["missing_actions"]
        ]
        blocked = [
            f"{step['id']}: {reason}"
            for step in static["manifest"]["steps"]
            for reason in steps[step["id"]]["blocked_reasons"]
        ]
    else:
        drifted = [view for view in ordered if view.get("source_drift")]
        if drifted:
            plan_stage = "IMPLEMENTATION_COMPLETE"
            next_action = str(drifted[0]["next_action"])
            missing = [
                f"{step['id']}: {action}"
                for step in static["manifest"]["steps"]
                for action in steps[step["id"]]["missing_actions"]
            ]
            blocked = [
                f"{step['id']}: {reason}"
                for step in static["manifest"]["steps"]
                for reason in steps[step["id"]]["blocked_reasons"]
            ]
        else:
            plan_stage = "IMPLEMENTATION_COMPLETE"
            next_action = (
                "D1 complete at IMPLEMENTATION_COMPLETE. Review acceptance, formal "
                "repair, independent validation, PR/CI/MERGED completion and "
                "dependency opening remain closed until D2/E."
            )
            missing = []
            blocked = []
    budget = {
        "limit": FORMAL_REPAIR_LIMIT,
        "used": 0,
        "remaining": FORMAL_REPAIR_LIMIT,
        "lineage": "per-step across designs and restarts",
        "consumption": "CLOSED_UNTIL_D2",
    }
    d2_view: dict[str, Any] | None = None
    d2_hook = _HOOKS.get("d2_overlay")
    if d2_hook is not None:
        try:
            d2_view = d2_hook(plan_id=plan_id, state=state, journal=journal)
        except Exception as exc:
            d2_view = {
                "version": 1,
                "active": False,
                "stage": "BLOCKED",
                "error": f"D2 overlay failed closed: {exc}",
            }
        if d2_view.get("active"):
            for step_id, d2_step in (d2_view.get("steps") or {}).items():
                if not d2_step.get("active"):
                    continue
                if step_id in steps:
                    steps[step_id]["d2_stage"] = d2_step.get("stage")
                    steps[step_id]["d2_next_action"] = d2_step.get(
                        "next_action"
                    )
            if (
                plan_stage in {"IMPLEMENTATION_COMPLETE", "READY_TO_IMPLEMENT"}
                and d2_view.get("stage") is not None
            ):
                # A version 2 step with an actual D2-derived stage owns the
                # plan stage even when D1's writer view looks "ready" (for
                # example an aborted repair intent, or a linked new design
                # cycle whose carry is not executable). A brand-new version 2
                # step before any implementation emits no D2 stage and keeps
                # the honest D1 ready-to-implement view.
                plan_stage = str(d2_view.get("stage") or plan_stage)
                next_action = str(d2_view.get("next_action") or next_action)
                missing = list(d2_view.get("missing_actions") or missing)
                blocked = list(d2_view.get("blocked_reasons") or blocked)
            budget = (
                d2_view.get("repair_budget")
                or budget
            )
    d2_step_views = (d2_view or {}).get("steps") or {}
    return {
        "version": EXECUTION_VERSION,
        "stage": plan_stage,
        "next_action": next_action,
        "missing_actions": missing,
        "blocked_reasons": blocked,
        "source_drift": any(view.get("source_drift") for view in ordered)
        or any(
            isinstance(d2_step_views.get(step["id"]), dict)
            and d2_step_views[step["id"]].get("source_drift")
            for step in static["manifest"]["steps"]
        ),
        "steps": steps,
        "attempt": next(
            (view["attempt"] for view in ordered if view["attempt"]), None
        ),
        "d2": d2_view,
        "formal_repair_budget": budget,
        "implementation_gate": (
            "D1_IMPLEMENTATION_COMPLETE_SOURCE_DRIFT"
            if any(view.get("source_drift") for view in ordered)
            else "D1_IMPLEMENTATION_COMPLETE_REVIEW_CLOSED"
            if plan_stage == "IMPLEMENTATION_COMPLETE"
            else f"D2_{plan_stage}"
            if d2_view and d2_view.get("active")
            else "D1_MANAGED_EXECUTION"
        ),
        "closed_gates": dict(CLOSED_GATES),
    }


def cycle_mutation_guard(*, plan_id: str, step_id: str) -> str | None:
    """Return a fail-closed reason when D1 ownership fences a B1 reopen.

    Missing journals are quiescent. A corrupt journal raises and is caught by
    B1 as a fail-closed condition.
    """
    if not _journal_exists(plan_id):
        return None
    journal = _replay_journal(plan_id)
    for assignment in journal["assignments"]:
        if assignment["step_id"] != step_id:
            continue
        job_id = assignment["payload"]["job_id"]
        if _evidence_for_job(journal, job_id) is not None:
            continue
        path = _jobs_dir() / job_id
        if not path.is_dir():
            continue
        meta = (
            _read_json(path / "meta.json")
            if (path / "meta.json").is_file()
            else {}
        )
        if meta:
            try:
                _require_processes_dead(
                    meta, f"Discussion job {job_id}"
                )
            except Exception:
                return (
                    f"Refusing to reopen the cycle while D1 discussion job "
                    f"{job_id} is still live for step {step_id}."
                )
        if not (path / "result.json").is_file():
            return (
                f"Refusing to reopen the cycle while D1 discussion job {job_id} "
                f"is unsettled for step {step_id}."
            )
    relevant = [
        event
        for event in journal["events"]
        if event["step_id"] == step_id and "attempt_id" in event["payload"]
    ]
    attempt_ids: list[str] = []
    for event in relevant:
        attempt_id = event["payload"]["attempt_id"]
        if attempt_id not in attempt_ids:
            attempt_ids.append(attempt_id)
    for attempt_id in attempt_ids:
        state = _attempt_state(journal, attempt_id)
        if state["state"] in {"pending", "claimed"}:
            return (
                f"Refusing to reopen the cycle while D1 attempt {attempt_id} is "
                f"{state['state']} for step {step_id}. Finish or reconcile the "
                "owned intent/claim first."
            )
        if state["state"] == "uncertain" or state["state"] == "blocked":
            return (
                f"Refusing to reopen the cycle while D1 attempt {attempt_id} has "
                "uncertain or blocked ownership evidence for step "
                f"{step_id}. Explicit evidence reconciliation is required first."
            )
        if state["state"] == "drained_success" and _latest(
            journal["events"], TYPE_COMPLETE, attempt_id=attempt_id
        ) is None:
            return (
                f"Refusing to reopen the cycle while D1 attempt {attempt_id} has a "
                "successful result whose completion event was not published. "
                "Retry execution-finalize to finish the torn append."
            )
    return None


def latest_implementation_job(plan_id: str, step_id: str) -> str | None:
    """Return the most recent protected implementation job for a step."""
    journal = _replay_journal(plan_id)
    matches = [
        event
        for event in journal["intents"]
        if event["step_id"] == step_id
    ]
    return matches[-1]["payload"]["job_id"] if matches else None


def wait_for_job_evidence_settled(job_id: str, timeout: float = 20.0) -> None:
    """Wait outside the plan lock for all recorded job processes to exit.

    Completion evidence is written by the supervisor before it closes the lease
    descriptor, so the finalize command may observe a still-live supervisor for
    a few milliseconds. This helper never decides success; finalize re-validates
    every hash and process identity afterwards.
    """
    _require_id(job_id, "job_id")
    path = _jobs_dir() / job_id
    deadline = time.monotonic() + timeout
    while True:
        if not (path / "meta.json").is_file():
            _fail(f"Managed job record is missing: {job_id}")
        meta = _read_json(path / "meta.json")
        try:
            _require_processes_dead(meta, f"Managed job {job_id}")
            return
        except Exception:
            if time.monotonic() >= deadline:
                _fail(
                    f"Managed job {job_id} still has a live or unprobeable recorded "
                    "process; completion evidence cannot be finalized"
                )
        time.sleep(0.05)
