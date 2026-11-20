#!/usr/bin/env python3
"""B2 repository writer leases and content-aware workspace integrity.

This module is loaded by ``cli_agent_job.py`` through an absolute-path import,
like ``b1_consensus.py``, and is configured with a small set of runner hooks.

Design summary:

* A stable, never-unlinked ``flock`` inode lives in the canonical Git common
  directory (``<git-common-dir>/agent-orchestrator/lease/writer.lock``).  Every
  launch from any state home, subdirectory, symlinked path or linked worktree
  resolves to that one inode; distinct Git repositories keep distinct inodes.
* Admission acquires the lock non-blocking before a job record is published.
  The launcher then passes the locked descriptor to a small Linux supervisor
  process (``cli_agent_job.py _lease-supervisor``).  The supervisor is a child
  subreaper, so every worker/provider descendant -- including ``setsid`` and
  double-fork daemons -- is reparented to it, and it keeps the lock until the
  kernel reports no children remain.  Providers never keep the descriptor.
* A durable owner record published before the worker starts names the epoch,
  coordinator/supervisor process start identities and lease inode.  Normal
  completion writes an immutable per-job ``lease-completion.json`` receipt
  (bound to the epoch, lock inode and exact final-check digest) and then
  ``state=completed`` before the descriptor is closed.  The receipt keeps every
  historical completion verifiable after later lease epochs replace the mutable
  owner record.  If the supervisor is killed, the released lock, a stale PID or
  an empty process group proves nothing: the non-terminal owner record fails
  admission closed until completion is proven by a valid receipt or an
  evidence-backed ``lease-reconcile`` record is written.
* Admission also rejects discoverable live legacy/unleased writers from local
  canonical job metadata and shared repository reservations; a terminal B2
  owner is a finished hand-off, never a live writer.
* Workspace baselines are taken only after the lease is held and capture
  HEAD/branch, raw index integrity, logical staged state, content hashes of
  dirty paths and bounded explicit allowed/denied scope paths including ignored
  files.  Final scope checks compare content hashes, so edits to already-dirty
  files, renames, deletions and new files are attributed without ever resetting
  the tree or index.  Externally visible success waits for the supervisor final
  check and a terminal owner state.  This is detection, not OS-level prevention
  of arbitrary provider writes (C supplies that).

Limitations (documented, not silently weakened): POSIX/Linux local filesystems
with ``/proc`` and ``flock``; advisory coordination of runner processes; an
externally SIGKILLed supervisor with an unknowable descendant tree requires an
explicit operator reconciliation.  Managed research implementations stay gated
by B1 until C/D.
"""

from __future__ import annotations

import ctypes
import fcntl
import fnmatch
import hashlib
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

LEASE_VERSION = 1
LEASE_DIR_NAME = "lease"
LEASE_LOCK_NAME = "writer.lock"
LEASE_OWNER_NAME = "owner.json"
LEASE_RECEIPT_NAME = "lease-completion.json"
RECEIPT_VERSION = 1
RECONCILIATION_DIR = "reconciliations"
LEASE_ACTIVE_STATES = frozenset({"admission", "supervising"})
LEASE_TERMINAL_STATES = frozenset({"completed", "failed_admission", "reconciled"})
LEASE_STATES = LEASE_ACTIVE_STATES | LEASE_TERMINAL_STATES
EPOCH_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_LEASE_ERROR_BYTES = 4096
MAX_EVIDENCE_BYTES = 8192
MAX_START_IDENTITY_BYTES = 64
CANCEL_GRACE_SECONDS = 5.0

SNAPSHOT_VERSION = 2
MAX_SNAPSHOT_PATHS = 4000
MAX_STAGED_PATHS = 20000
MAX_HASH_FILE_BYTES = 32 * 1024 * 1024
MAX_HASH_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ATTRIBUTION_DETAIL = 4000
# Explicit scope patterns are resolved to concrete paths so ignored files are
# observable without an exhaustive `git status --ignored` scan.  Both the
# pattern list and the pathspec-scoped enumeration are bounded; exceeding a
# bound refuses the observation instead of silently attesting a partial set.
MAX_SCOPE_PATTERNS = 64
MAX_SCOPE_LIST_BYTES = 8 * 1024 * 1024
MAX_SCOPE_LIST_ENTRIES = 100000

PR_SET_CHILD_SUBREAPER = 36
LEASE_HANDOFF_ENV = "AGENT_ORCHESTRATOR_LEASE_HANDOFF_SECONDS"
DEFAULT_LEASE_HANDOFF_SECONDS = 10.0

_HOOKS: dict[str, Any] = {}


def configure(**hooks: Any) -> None:
    """Install runner-provided hooks (same pattern as ``b1_consensus``)."""
    _HOOKS.update(hooks)


def _hook(name: str) -> Any:
    try:
        return _HOOKS[name]
    except KeyError as exc:  # pragma: no cover - configuration bug
        raise RuntimeError(f"b2_workspace hook is not configured: {name}") from exc


def _optional_hook(name: str) -> Any:
    return _HOOKS.get(name)


def _fail(message: str) -> None:
    raise _hook("runner_error")(message)


def _now() -> str:
    return _hook("utc_now")()


def _read_json(path: Path) -> dict[str, Any]:
    return _hook("read_json")(path)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _hook("write_json")(path, value)
    _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    """Persist a directory entry for local POSIX filesystems.

    Lease ownership transitions must survive a crash between journal replay and
    the process exit that releases the flock.  Unsupported directory fsync
    semantics fail closed instead of pretending the marker is durable.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        _fail(f"Cannot open lease directory for durability at {path}: {exc}")
    try:
        os.fsync(descriptor)
    except OSError as exc:
        _fail(f"Cannot fsync lease directory at {path}: {exc}")
    finally:
        os.close(descriptor)


# ---------------------------------------------------------------------------
# Process start identity
# ---------------------------------------------------------------------------


def _proc_state_and_start(pid: int) -> tuple[str, str] | None:
    try:
        data = Path(f"/proc/{pid}/stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError:
        return None
    try:
        tail = data.rsplit(b")", 1)[1].split()
        state = tail[0].decode("ascii")
        start = tail[19].decode("ascii")
    except (IndexError, UnicodeDecodeError):
        return None
    return state[:1], start[:MAX_START_IDENTITY_BYTES]


def process_start_identity(pid: Any) -> str | None:
    """Return the Linux start time token for ``pid`` or ``None`` if gone.

    ``/proc/<pid>/stat`` field 22 changes only when a PID is reused, so pid plus
    start identity names one process instance.  Unreadable state is reported as
    ``None`` and callers must treat it as unprobeable, never as proof of death.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    values = _proc_state_and_start(pid)
    return values[1] if values else None


def process_record(pid: Any) -> dict[str, Any] | None:
    """Return a durable process identity, or ``None`` when the PID is gone.

    A present-but-unreadable ``/proc`` entry returns a record with
    ``start=None``; ``process_probe`` classifies that as ``unknown`` so lease
    admission fails closed.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if not Path(f"/proc/{pid}").exists():
        return None
    values = _proc_state_and_start(pid)
    if values is None:
        return {"pid": pid, "start": None, "zombie": False}
    state, start = values
    return {"pid": pid, "start": start, "zombie": state == "Z"}


def process_probe(record: Any) -> str:
    """Classify a recorded process as ``alive``, ``dead`` or ``unknown``."""
    if not isinstance(record, dict):
        return "dead"
    pid = record.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return "dead"
    current = process_record(pid)
    if current is None:
        return "dead"
    if current.get("zombie"):
        # A zombie has exited; only its unreaped status remains.  It cannot
        # hold the lease or write the repository.
        return "dead"
    expected = record.get("start")
    if not isinstance(expected, str) or not expected:
        return "unknown"
    if current.get("start") is None:
        return "unknown"
    return "alive" if current["start"] == expected else "dead"


def _valid_process_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    pid = record.get("pid")
    start = record.get("start")
    return (
        isinstance(pid, int)
        and not isinstance(pid, bool)
        and pid > 0
        and isinstance(start, (str, type(None)))
        and (start is None or len(start) <= MAX_START_IDENTITY_BYTES)
    )


def _record_or_none(pid: Any) -> dict[str, Any] | None:
    record = process_record(pid)
    return record if _valid_process_record(record) else None


def lease_handoff_timeout() -> float:
    raw = os.environ.get(LEASE_HANDOFF_ENV)
    if raw:
        try:
            value = float(raw)
        except ValueError:
            value = DEFAULT_LEASE_HANDOFF_SECONDS
        if value >= 0:
            return value
    return DEFAULT_LEASE_HANDOFF_SECONDS


# ---------------------------------------------------------------------------
# Git observation
# ---------------------------------------------------------------------------


class _UnsupportedSnapshot(Exception):
    pass


def _git_environment() -> dict[str, str]:
    # ``GIT_OPTIONAL_LOCKS=0`` keeps observation from opportunistically
    # rewriting the index; the C locale keeps diagnostics machine-checkable.
    env = dict(os.environ)
    env.update(
        {
            "LC_ALL": "C",
            "LANGUAGE": "C",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def _run_git(
    workspace: Path,
    args: list[str],
    *,
    timeout: float = 30,
    text: bool = False,
) -> subprocess.CompletedProcess[Any]:
    command = ["git", "-C", str(workspace), *args]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=text,
            timeout=timeout,
            check=False,
            env=_git_environment(),
        )
    except subprocess.TimeoutExpired:
        _fail(f"Timed out observing Git workspace {workspace}: {' '.join(args)}")
    except OSError as exc:
        _fail(f"Cannot observe Git workspace {workspace}: {exc}")


def _unsafe_relative_path(value: str) -> bool:
    if not value or value.startswith("/") or "\x00" in value:
        return True
    parts = Path(value).parts
    return any(part in ("..",) for part in parts)


def _decode_path(raw: bytes) -> str:
    return os.fsdecode(raw)


def _parse_porcelain_z(
    data: bytes,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    fields = data.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    entries: list[dict[str, Any]] = []
    lines: list[str] = []
    paths: set[str] = set()
    index = 0
    while index < len(fields):
        field = fields[index]
        index += 1
        if len(field) < 4:
            raise _UnsupportedSnapshot("malformed NUL-delimited git status record")
        status_text = field[:2].decode("ascii", errors="replace")
        path = _decode_path(field[3:])
        if _unsafe_relative_path(path):
            raise _UnsupportedSnapshot(f"unsafe path in git status: {path!r}")
        original: str | None = None
        if "R" in status_text or "C" in status_text:
            if index >= len(fields):
                raise _UnsupportedSnapshot("truncated git rename record")
            original = _decode_path(fields[index])
            index += 1
            if _unsafe_relative_path(original):
                raise _UnsupportedSnapshot(
                    f"unsafe rename source in git status: {original!r}"
                )
            paths.add(original)
        entry = {"status": status_text, "path": path}
        if original is not None:
            entry["orig_path"] = original
            lines.append(f"{status_text} {original} -> {path}")
        else:
            lines.append(f"{status_text} {path}")
        entries.append(entry)
        paths.add(path)
    return entries, lines, sorted(paths)


def _parse_raw_diff_z(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Parse ``git diff --raw -z`` into logical staged state.

    The raw record is ``:oldmode newmode oldoid newoid status`` followed by one
    NUL-terminated path, or by old and new paths for a rename/copy.
    """
    fields = data.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    entries: dict[str, Any] = {}
    renames: list[dict[str, str]] = []
    index = 0
    while index < len(fields):
        header = fields[index]
        index += 1
        if not header.startswith(b":"):
            raise _UnsupportedSnapshot("malformed staged diff record")
        parts = header[1:].split(b" ")
        if len(parts) != 5:
            raise _UnsupportedSnapshot("malformed staged diff header")
        old_mode, new_mode, old_oid, new_oid, status_raw = parts
        status_text = status_raw.decode("ascii", errors="replace")
        code = status_text[:1]
        if code in ("R", "C"):
            if index + 1 >= len(fields):
                raise _UnsupportedSnapshot("truncated staged rename record")
            old_path = _decode_path(fields[index])
            new_path = _decode_path(fields[index + 1])
            index += 2
            if _unsafe_relative_path(old_path) or _unsafe_relative_path(new_path):
                raise _UnsupportedSnapshot("unsafe staged rename path")
            renames.append({"from": old_path, "to": new_path})
            entries[old_path] = {
                "status": code,
                "renamed_to": new_path,
                "mode": old_mode.decode("ascii", errors="replace"),
                "oid": old_oid.decode("ascii", errors="replace"),
            }
            entries[new_path] = {
                "status": code,
                "renamed_from": old_path,
                "mode": new_mode.decode("ascii", errors="replace"),
                "oid": new_oid.decode("ascii", errors="replace"),
            }
            continue
        if index >= len(fields):
            raise _UnsupportedSnapshot("truncated staged path record")
        path = _decode_path(fields[index])
        index += 1
        if _unsafe_relative_path(path):
            raise _UnsupportedSnapshot("unsafe staged path")
        entries[path] = {
            "status": code,
            "mode": new_mode.decode("ascii", errors="replace"),
            "oid": new_oid.decode("ascii", errors="replace"),
        }
    return entries, renames


def _parse_ls_files_z(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]]]:
    entries: dict[str, Any] = {}
    fields = data.split(b"\0")
    for field in fields:
        if not field:
            continue
        try:
            info, raw_path = field.split(b"\t", 1)
            mode, oid, stage = info.split(b" ")
        except ValueError as exc:
            raise _UnsupportedSnapshot("malformed staged file record") from exc
        path = _decode_path(raw_path)
        if _unsafe_relative_path(path):
            raise _UnsupportedSnapshot("unsafe staged file path")
        if stage != b"0":
            raise _UnsupportedSnapshot("unmerged index entries are not supported")
        entries[path] = {
            "status": "A",
            "mode": mode.decode("ascii", errors="replace"),
            "oid": oid.decode("ascii", errors="replace"),
        }
        if len(entries) > MAX_STAGED_PATHS:
            raise _UnsupportedSnapshot(
                f"staged path count exceeds {MAX_STAGED_PATHS}"
            )
    return entries, []


def _index_evidence(workspace: Path) -> dict[str, Any]:
    resolved = _run_git(
        workspace,
        ["rev-parse", "--path-format=absolute", "--git-path", "index"],
        text=True,
    )
    if resolved.returncode != 0:
        resolved = _run_git(
            workspace, ["rev-parse", "--git-path", "index"], text=True
        )
    if resolved.returncode != 0:
        raise _UnsupportedSnapshot(
            "cannot resolve the Git index path: "
            + (resolved.stderr or "git rev-parse failed").strip()
        )
    raw_path = resolved.stdout.strip().splitlines()
    if len(raw_path) != 1 or not raw_path[0]:
        raise _UnsupportedSnapshot("git reported an ambiguous index path")
    index_path = Path(raw_path[0])
    if not index_path.is_absolute():
        index_path = (workspace / index_path).resolve()
    evidence: dict[str, Any] = {"path": str(index_path), "exists": False}
    try:
        info = os.lstat(index_path)
    except FileNotFoundError:
        return evidence
    except OSError as exc:
        raise _UnsupportedSnapshot(f"cannot stat the Git index: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _UnsupportedSnapshot("the Git index is not a regular file")
    try:
        descriptor = os.open(
            index_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise _UnsupportedSnapshot(f"cannot open the Git index: {exc}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(descriptor)
    evidence.update(
        {
            "exists": True,
            "sha256": digest.hexdigest(),
            "size": size,
            "mtime_ns": opened.st_mtime_ns,
            "dev": opened.st_dev,
            "ino": opened.st_ino,
        }
    )
    return evidence


def _hash_path(top: Path, relative: str, budget: dict[str, int]) -> dict[str, Any]:
    if _unsafe_relative_path(relative):
        raise _UnsupportedSnapshot(f"unsafe workspace path: {relative!r}")
    target = top / relative
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return {"kind": "missing"}
    except OSError as exc:
        raise _UnsupportedSnapshot(f"cannot stat {relative}: {exc}") from exc
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        raw = os.fsencode(os.readlink(target))
        return {
            "kind": "symlink",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "mode": mode,
        }
    if stat.S_ISDIR(info.st_mode):
        return {"kind": "directory", "mode": mode}
    if not stat.S_ISREG(info.st_mode):
        raise _UnsupportedSnapshot(
            f"{relative} is a special file whose content cannot be attested"
        )
    if info.st_size > MAX_HASH_FILE_BYTES:
        raise _UnsupportedSnapshot(
            f"{relative} is {info.st_size} bytes, above the "
            f"{MAX_HASH_FILE_BYTES}-byte content-hash bound"
        )
    budget["remaining"] -= info.st_size
    if budget["remaining"] < 0:
        raise _UnsupportedSnapshot(
            f"dirty workspace content exceeds the {MAX_HASH_TOTAL_BYTES}-byte "
            "content-hash bound"
        )
    try:
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise _UnsupportedSnapshot(f"cannot read {relative}: {exc}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _UnsupportedSnapshot(f"{relative} changed type during observation")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_HASH_FILE_BYTES:
                raise _UnsupportedSnapshot(
                    f"{relative} grew beyond the content-hash bound"
                )
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return {
        "kind": "file",
        "sha256": digest.hexdigest(),
        "size": size,
        "mode": mode,
    }


def _base_snapshot(workspace: Path, supported: bool, reason: str | None) -> dict[str, Any]:
    return {
        "version": SNAPSHOT_VERSION,
        "is_git": True,
        "is_work_tree": False,
        "supported": supported,
        "unsupported_reason": reason,
        "dirty": False,
        "head": None,
        "branch": None,
        "detached": None,
        "status": [],
        "status_entries": [],
        "dirty_paths": [],
        "untracked_paths": [],
        "index": {"exists": False},
        "staged": {"entries": {}, "renames": []},
        "entries": {},
        "workspace": str(workspace),
    }


def snapshot_workspace(
    workspace: Path,
    *,
    strict: bool = True,
    extra_paths: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Capture a bounded, attributable Git baseline or observation.

    ``strict`` refuses rather than returning a snapshot that cannot attest the
    full dirty set.  Non-strict callers (status/dashboard observation) receive
    ``supported=False`` with the precise reason.
    """
    literal = Path(workspace).expanduser()
    inside = _run_git(literal, ["rev-parse", "--is-inside-work-tree"], text=True)
    if inside.returncode != 0:
        stderr = (inside.stderr or "").casefold()
        if "not a git repository" in stderr or "not a git work tree" in stderr:
            return {"is_git": False, "dirty": False}
        message = (inside.stderr or "git rev-parse failed").strip()
        if strict:
            _fail(f"Cannot inspect Git workspace {literal}: {message}")
        return _base_snapshot(literal, False, message)
    if inside.stdout.strip() != "true":
        message = "workspace is a Git administrative directory or bare repository"
        if strict:
            _fail(f"Cannot inspect Git workspace {literal}: {message}")
        return _base_snapshot(literal, False, message)
    try:
        return _snapshot_work_tree(literal, strict=strict, extra_paths=extra_paths)
    except _UnsupportedSnapshot as exc:
        if strict:
            _fail(f"Workspace integrity snapshot refused for {literal}: {exc}")
        result = _base_snapshot(literal, False, str(exc))
        result["is_work_tree"] = True
        return result


def _snapshot_work_tree(
    workspace: Path,
    *,
    strict: bool,
    extra_paths: list[str] | tuple[str, ...] | None,
) -> dict[str, Any]:
    top_result = _run_git(
        workspace, ["rev-parse", "--show-toplevel"], text=True
    )
    if top_result.returncode != 0 or not top_result.stdout.strip():
        raise _UnsupportedSnapshot("cannot resolve the Git work-tree root")
    top = Path(top_result.stdout.strip()).resolve()
    head_result = _run_git(
        workspace, ["rev-parse", "--verify", "-q", "HEAD"], text=True
    )
    head = (
        head_result.stdout.strip()
        if head_result.returncode == 0 and head_result.stdout.strip()
        else None
    )
    branch_result = _run_git(
        workspace, ["symbolic-ref", "--short", "-q", "HEAD"], text=True
    )
    branch = (
        branch_result.stdout.strip()
        if branch_result.returncode == 0 and branch_result.stdout.strip()
        else None
    )
    status_result = _run_git(
        workspace,
        [
            "-c",
            "status.relativePaths=false",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
    )
    if status_result.returncode != 0:
        raise _UnsupportedSnapshot(
            "git status failed: " + (status_result.stderr or "").strip()
        )
    status_entries, status_lines, dirty_paths = _parse_porcelain_z(
        status_result.stdout
    )
    for entry in status_entries:
        if entry["status"] in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"} or (
            "U" in entry["status"]
        ):
            raise _UnsupportedSnapshot(
                "the index has unmerged entries; resolve them before launching"
            )
    if len(dirty_paths) > MAX_SNAPSHOT_PATHS:
        raise _UnsupportedSnapshot(
            f"dirty path count {len(dirty_paths)} exceeds {MAX_SNAPSHOT_PATHS}"
        )
    index = _index_evidence(workspace)
    if head:
        diff_result = _run_git(
            workspace,
            [
                "diff",
                "--cached",
                "--raw",
                "-z",
                "-M",
                "--no-abbrev",
                head,
            ],
        )
        if diff_result.returncode != 0:
            raise _UnsupportedSnapshot(
                "cannot read staged state: "
                + (diff_result.stderr or "git diff --cached failed").strip()
            )
        staged_entries, staged_renames = _parse_raw_diff_z(diff_result.stdout)
    else:
        listed = _run_git(
            workspace, ["ls-files", "--stage", "-z", "--full-name"]
        )
        if listed.returncode != 0:
            raise _UnsupportedSnapshot(
                "cannot read the unborn branch index: "
                + (listed.stderr or "git ls-files failed").strip()
            )
        staged_entries, staged_renames = _parse_ls_files_z(listed.stdout)
    if len(staged_entries) > MAX_STAGED_PATHS:
        raise _UnsupportedSnapshot(
            f"staged path count exceeds {MAX_STAGED_PATHS}"
        )
    hash_paths = set(dirty_paths)
    for entry in status_entries:
        original = entry.get("orig_path")
        if original:
            hash_paths.add(original)
    for extra in extra_paths or ():
        if isinstance(extra, str):
            hash_paths.add(extra)
    if len(hash_paths) > MAX_SNAPSHOT_PATHS:
        raise _UnsupportedSnapshot(
            f"content-hash path count {len(hash_paths)} exceeds {MAX_SNAPSHOT_PATHS}"
        )
    budget = {"remaining": MAX_HASH_TOTAL_BYTES}
    entries: dict[str, Any] = {}
    for path in sorted(hash_paths):
        entries[path] = _hash_path(top, path, budget)
    untracked = sorted(
        entry["path"] for entry in status_entries if entry["status"] == "??"
    )
    return {
        "version": SNAPSHOT_VERSION,
        "is_git": True,
        "is_work_tree": True,
        "supported": True,
        "unsupported_reason": None,
        "dirty": bool(status_entries),
        "head": head,
        "branch": branch,
        "detached": branch is None,
        "status": status_lines,
        "status_entries": status_entries,
        "dirty_paths": dirty_paths,
        "untracked_paths": untracked,
        "index": index,
        "staged": {"entries": staged_entries, "renames": staged_renames},
        "entries": entries,
        "top_level": str(top),
        "workspace": str(workspace),
        "bounded": {
            "dirty_paths": len(dirty_paths),
            "staged_paths": len(staged_entries),
            "hashed_paths": len(entries),
            "hashed_bytes": MAX_HASH_TOTAL_BYTES - budget["remaining"],
            "max_paths": MAX_SNAPSHOT_PATHS,
            "max_hash_bytes": MAX_HASH_TOTAL_BYTES,
        },
    }


# ---------------------------------------------------------------------------
# Content-aware attribution and scope
# ---------------------------------------------------------------------------


def _entry_signature(entry: Any) -> tuple[Any, ...] | None:
    if not isinstance(entry, dict):
        return None
    return (
        entry.get("kind"),
        entry.get("sha256"),
        entry.get("size"),
        entry.get("mode"),
    )


def _status_map(snapshot: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for entry in snapshot.get("status_entries", []):
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if isinstance(path, str):
            mapping[path] = str(entry.get("status", ""))
        original = entry.get("orig_path")
        if isinstance(original, str):
            mapping.setdefault(original, str(entry.get("status", "")))
    return mapping


def changed_paths(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Compare two supported snapshots by content, staging and status.

    Preexisting dirty paths are content-hashed in both snapshots, so an edit
    that leaves the same status code still counts as a change.  Renames,
    deletions and new files are represented explicitly instead of being
    subtracted by path name.
    """
    base_entries = baseline.get("entries", {})
    cur_entries = current.get("entries", {})
    if not isinstance(base_entries, dict):
        base_entries = {}
    if not isinstance(cur_entries, dict):
        cur_entries = {}
    base_status = _status_map(baseline)
    cur_status = _status_map(current)
    reasons: dict[str, set[str]] = {}
    details: dict[str, dict[str, Any]] = {}

    def add(path: str, reason: str) -> None:
        if not isinstance(path, str) or _unsafe_relative_path(path):
            return
        reasons.setdefault(path, set()).add(reason)
        detail = details.setdefault(
            path,
            {
                "path": path,
                "baseline_status": base_status.get(path),
                "current_status": cur_status.get(path),
                "baseline_sha256": None,
                "current_sha256": None,
            },
        )
        base_entry = base_entries.get(path)
        if isinstance(base_entry, dict):
            detail["baseline_sha256"] = base_entry.get("sha256")
        cur_entry = cur_entries.get(path)
        if isinstance(cur_entry, dict):
            detail["current_sha256"] = cur_entry.get("sha256")

    for path in sorted(set(base_entries) | set(cur_entries)):
        base_entry = base_entries.get(path)
        cur_entry = cur_entries.get(path)
        if _entry_signature(base_entry) == _entry_signature(cur_entry):
            continue
        if cur_entry is None:
            add(path, "not observed in final snapshot")
        elif isinstance(cur_entry, dict) and cur_entry.get("kind") == "missing":
            add(path, "deleted")
        elif base_entry is None:
            add(path, "newly observed dirty or scope path")
        elif isinstance(base_entry, dict) and base_entry.get("kind") == "missing":
            add(path, "created")
        else:
            add(path, "content or mode changed")
    for path in sorted(set(base_status) | set(cur_status)):
        base_value = base_status.get(path)
        cur_value = cur_status.get(path)
        if base_value == cur_value:
            continue
        if base_value is None:
            add(path, "newly dirty")
        elif cur_value is None:
            add(path, "cleaned or reverted relative to baseline")
            if isinstance(base_entries.get(path), dict):
                add(path, "content or mode changed")
        else:
            add(path, f"status changed {base_value!r}->{cur_value!r}")
    base_staged = baseline.get("staged", {})
    cur_staged = current.get("staged", {})
    base_staged_entries = (
        base_staged.get("entries", {}) if isinstance(base_staged, dict) else {}
    )
    cur_staged_entries = (
        cur_staged.get("entries", {}) if isinstance(cur_staged, dict) else {}
    )
    if not isinstance(base_staged_entries, dict):
        base_staged_entries = {}
    if not isinstance(cur_staged_entries, dict):
        cur_staged_entries = {}
    for path in sorted(set(base_staged_entries) | set(cur_staged_entries)):
        if base_staged_entries.get(path) != cur_staged_entries.get(path):
            add(path, "staged state changed")
    base_renames = (
        base_staged.get("renames", []) if isinstance(base_staged, dict) else []
    )
    cur_renames = (
        cur_staged.get("renames", []) if isinstance(cur_staged, dict) else []
    )
    if base_renames != cur_renames:
        for rename in cur_renames:
            if isinstance(rename, dict):
                if isinstance(rename.get("from"), str):
                    add(rename["from"], "rename source changed")
                if isinstance(rename.get("to"), str):
                    add(rename["to"], "rename target changed")
    for entry in current.get("status_entries", []):
        if isinstance(entry, dict) and "R" in str(entry.get("status", "")):
            new_path = entry.get("path")
            old_path = entry.get("orig_path")
            if isinstance(old_path, str):
                add(old_path, "renamed from")
            if isinstance(new_path, str):
                add(new_path, "rename target")

    ordered = [
        {
            **details[path],
            "reasons": sorted(reasons[path]),
        }
        for path in sorted(reasons)
    ]
    index_before = baseline.get("index", {})
    index_after = current.get("index", {})
    if not isinstance(index_before, dict):
        index_before = {}
    if not isinstance(index_after, dict):
        index_after = {}
    return {
        "version": SNAPSHOT_VERSION,
        "changed": ordered[:MAX_ATTRIBUTION_DETAIL],
        "changed_truncated": len(ordered) > MAX_ATTRIBUTION_DETAIL,
        "paths": [item["path"] for item in ordered],
        "count": len(ordered),
        "baseline_head": baseline.get("head"),
        "current_head": current.get("head"),
        "head_changed": baseline.get("head") != current.get("head"),
        "baseline_branch": baseline.get("branch"),
        "current_branch": current.get("branch"),
        "branch_changed": baseline.get("branch") != current.get("branch"),
        "baseline_detached": baseline.get("detached"),
        "current_detached": current.get("detached"),
        "index_baseline_sha256": index_before.get("sha256"),
        "index_current_sha256": index_after.get("sha256"),
        "index_changed": index_before.get("sha256") != index_after.get("sha256"),
        "baseline_supported": bool(baseline.get("supported")),
        "current_supported": bool(current.get("supported")),
    }


def _scope_configured(scope: dict[str, Any]) -> bool:
    return bool(
        scope.get("allowed_paths")
        or scope.get("denied_paths")
        or scope.get("max_changed_files") is not None
    )


def _scope_pattern(value: Any) -> str:
    """Validate one explicit allowed/denied pattern for path observation."""
    if not isinstance(value, str) or not value:
        raise _UnsupportedSnapshot("an explicit scope pattern is empty")
    if "\x00" in value or value.startswith("/"):
        raise _UnsupportedSnapshot(
            f"explicit scope pattern is not a relative path: {value!r}"
        )
    if any(part == ".." for part in Path(value).parts):
        raise _UnsupportedSnapshot(
            f"explicit scope pattern escapes the work tree: {value!r}"
        )
    if len(value.encode("utf-8", errors="replace")) > 4096:
        raise _UnsupportedSnapshot("an explicit scope pattern is too long")
    return value


def _scope_static_prefix(pattern: str) -> str:
    """Return the literal directory prefix before the first glob character."""
    indexes = [pattern.find(char) for char in "*?[" if char in pattern]
    head = pattern[: min(indexes)] if indexes else pattern
    return head.rsplit("/", 1)[0] if "/" in head else ""


def _scope_git_candidates(
    workspace: Path, prefix: str, *, ignored: bool
) -> list[str]:
    """List tracked/untracked or ignored files under a literal path prefix."""
    args = ["--literal-pathspecs", "ls-files", "-z"]
    if ignored:
        args.extend(["--others", "--ignored", "--exclude-standard"])
    else:
        args.extend(["--cached", "--others", "--exclude-standard"])
    args.extend(["--", prefix or "."])
    result = _run_git(workspace, args, timeout=30)
    if result.returncode != 0:
        detail = (result.stderr or b"git ls-files failed").decode(
            "utf-8", errors="replace"
        )
        raise _UnsupportedSnapshot(
            "cannot enumerate explicit scope paths: " + detail.strip()
        )
    data = result.stdout
    if len(data) > MAX_SCOPE_LIST_BYTES:
        raise _UnsupportedSnapshot(
            "explicit scope path enumeration exceeds the "
            f"{MAX_SCOPE_LIST_BYTES}-byte bound"
        )
    fields = data.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) > MAX_SCOPE_LIST_ENTRIES:
        raise _UnsupportedSnapshot(
            "explicit scope path enumeration exceeds the "
            f"{MAX_SCOPE_LIST_ENTRIES}-entry bound"
        )
    paths: list[str] = []
    for field in fields:
        if not field:
            continue
        path = _decode_path(field)
        if _unsafe_relative_path(path):
            raise _UnsupportedSnapshot(
                f"unsafe path in explicit scope enumeration: {path!r}"
            )
        paths.append(path)
    return paths


def _scope_observation_paths(
    workspace: Path, scope: dict[str, Any] | None
) -> list[str]:
    """Resolve explicit allowed/denied patterns to bounded concrete paths.

    Literal patterns are observed directly, so a currently missing denied path
    still has an attributable baseline.  Glob patterns are enumerated with a
    pathspec-scoped ``git ls-files`` that includes tracked, untracked and
    ignored matches; this observes ignored files without scanning the whole
    ignored tree and without mutating the index.  Enumeration is filtered with
    the same ``fnmatch`` rules used for scope attribution.
    """
    if not isinstance(scope, dict):
        return []
    patterns: list[str] = []
    for key in ("allowed_paths", "denied_paths"):
        values = scope.get(key)
        if values is None:
            continue
        if not isinstance(values, (list, tuple)):
            raise _UnsupportedSnapshot(f"scope {key} is not a list")
        patterns.extend(_scope_pattern(value) for value in values)
    if not patterns:
        return []
    if len(patterns) > MAX_SCOPE_PATTERNS:
        raise _UnsupportedSnapshot(
            f"explicit scope pattern count exceeds {MAX_SCOPE_PATTERNS}"
        )
    found: set[str] = set()
    for pattern in patterns:
        if not any(char in pattern for char in "*?["):
            found.add(pattern)
            continue
        prefix = _scope_static_prefix(pattern)
        candidates = _scope_git_candidates(workspace, prefix, ignored=False)
        candidates.extend(_scope_git_candidates(workspace, prefix, ignored=True))
        for path in candidates:
            if fnmatch.fnmatch(path, pattern):
                found.add(path)
        if len(found) > MAX_SNAPSHOT_PATHS:
            raise _UnsupportedSnapshot(
                "explicit scope path observation exceeds "
                f"{MAX_SNAPSHOT_PATHS} paths"
            )
    if len(found) > MAX_SNAPSHOT_PATHS:
        raise _UnsupportedSnapshot(
            f"explicit scope path observation exceeds {MAX_SNAPSHOT_PATHS} paths"
        )
    return sorted(found)


def scope_observation_paths(
    workspace: Path, scope: dict[str, Any] | None
) -> list[str]:
    """Public wrapper that fails closed with a runner diagnostic."""
    try:
        return _scope_observation_paths(Path(workspace).expanduser(), scope)
    except _UnsupportedSnapshot as exc:
        _fail(
            f"Workspace scope observation refused for {workspace}: {exc}"
        )


def scope_violations(
    workspace: Path, baseline: dict[str, Any], scope: dict[str, Any]
) -> list[str]:
    """Return content-attributed scope violations for a running/finished job.

    Legacy baselines created before B2 have no content version; they fall back
    to the original status-path subtraction so an in-flight job admitted by an
    older runner is not silently re-interpreted.
    """
    if not _scope_configured(scope):
        return []
    if not isinstance(baseline, dict) or not baseline.get("is_git"):
        return []
    if baseline.get("version") != SNAPSHOT_VERSION or not baseline.get(
        "supported"
    ):
        current = snapshot_workspace(workspace, strict=False)
        if not current.get("is_git"):
            return []
        changed = _status_paths(current.get("status", [])) - _status_paths(
            baseline.get("status", [])
        )
        return _scope_messages(changed, scope)
    base_entries = baseline.get("entries", {})
    base_paths = set(base_entries) if isinstance(base_entries, dict) else set()
    try:
        scope_paths = set(_scope_observation_paths(workspace, scope))
    except _UnsupportedSnapshot as exc:
        _fail(
            "Cannot verify workspace scope; explicit scope path observation is "
            f"unsupported: {exc}"
        )
    extra = sorted(base_paths | scope_paths)
    current = snapshot_workspace(workspace, strict=False, extra_paths=extra)
    if not current.get("supported"):
        _fail(
            "Cannot verify workspace scope; final content observation is "
            f"unsupported: {current.get('unsupported_reason')}"
        )
    report = changed_paths(baseline, current)
    violations = _scope_messages(report["paths"], scope)
    if report["head_changed"]:
        violations.append(
            "repository HEAD changed from "
            f"{report['baseline_head']} to {report['current_head']}"
        )
    if report["branch_changed"]:
        violations.append(
            "repository branch changed from "
            f"{report['baseline_branch']} to {report['current_branch']}"
        )
    return violations


def _status_paths(status_lines: list[str]) -> set[str]:
    paths: set[str] = set()
    for line in status_lines:
        value = line[3:] if len(line) > 3 else line
        if " -> " in value:
            value = value.split(" -> ", 1)[1]
        paths.add(value.strip('"'))
    return paths


def _scope_messages(paths: list[str] | set[str], scope: dict[str, Any]) -> list[str]:
    allowed = scope.get("allowed_paths", []) or []
    denied = scope.get("denied_paths", []) or []
    violations: list[str] = []
    for path in sorted(paths):
        if denied and any(fnmatch.fnmatch(path, pattern) for pattern in denied):
            violations.append(f"denied path changed: {path}")
        elif allowed and not any(
            fnmatch.fnmatch(path, pattern) for pattern in allowed
        ):
            violations.append(f"out-of-scope path changed: {path}")
    limit = scope.get("max_changed_files")
    if limit is not None and len(paths) > limit:
        violations.append(f"changed file count {len(paths)} exceeds limit {limit}")
    return violations


def final_integrity_report(
    workspace: Path, baseline: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any]:
    """Build the post-descendant integrity evidence written by the supervisor."""
    if not isinstance(baseline, dict) or not baseline.get("is_git"):
        return {
            "version": SNAPSHOT_VERSION,
            "supported": False,
            "reason": "job has no Git baseline",
            "scope_violations": [],
            "changed_paths": [],
        }
    if baseline.get("version") != SNAPSHOT_VERSION or not baseline.get(
        "supported"
    ):
        violations = scope_violations(workspace, baseline, scope)
        return {
            "version": SNAPSHOT_VERSION,
            "supported": False,
            "reason": "legacy status-subtraction baseline",
            "scope_violations": violations,
            "changed_paths": [],
        }
    base_entries = baseline.get("entries", {})
    base_paths = set(base_entries) if isinstance(base_entries, dict) else set()
    try:
        scope_paths = set(_scope_observation_paths(workspace, scope))
    except _UnsupportedSnapshot as exc:
        return {
            "version": SNAPSHOT_VERSION,
            "supported": False,
            "reason": f"explicit scope path observation is unsupported: {exc}",
            "scope_violations": (
                [f"explicit scope path observation is unsupported: {exc}"]
                if _scope_configured(scope)
                else []
            ),
            "changed_paths": [],
        }
    extra = sorted(base_paths | scope_paths)
    current = snapshot_workspace(workspace, strict=False, extra_paths=extra)
    if not current.get("supported"):
        return {
            "version": SNAPSHOT_VERSION,
            "supported": False,
            "reason": current.get("unsupported_reason")
            or "final integrity snapshot is unsupported",
            "scope_violations": (
                [
                    "final integrity snapshot is unsupported: "
                    + str(
                        current.get("unsupported_reason")
                        or "unknown reason"
                    )
                ]
                if _scope_configured(scope)
                else []
            ),
            "changed_paths": [],
        }
    report = changed_paths(baseline, current)
    violations = _scope_messages(report["paths"], scope)
    if _scope_configured(scope):
        if report["head_changed"]:
            violations.append(
                "repository HEAD changed from "
                f"{report['baseline_head']} to {report['current_head']}"
            )
        if report["branch_changed"]:
            violations.append(
                "repository branch changed from "
                f"{report['baseline_branch']} to {report['current_branch']}"
            )
    return {
        **report,
        "supported": True,
        "scope_violations": violations,
        "scope_observation_paths": extra[:MAX_SNAPSHOT_PATHS],
        "baseline_lease_epoch": baseline.get("lease_epoch"),
        "current_index": current.get("index", {}),
        "current_staged": current.get("staged", {}),
        "current_status": current.get("status", []),
        "observed_at": _now(),
    }


# ---------------------------------------------------------------------------
# Protected research workspace validation
# ---------------------------------------------------------------------------


def _current_branch(workspace: Path) -> str | None:
    result = _run_git(
        workspace, ["symbolic-ref", "--short", "-q", "HEAD"], text=True
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def validate_protected_workspace(
    workspace: Path,
    *,
    target_branch: str | None,
    protected_branches: list[str] | tuple[str, ...] | None,
    allowed_paths: list[str] | None = None,
    denied_paths: list[str] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a dedicated protected-research branch and dirty overlap.

    The target and protected branches are explicit caller configuration; this
    function never invents a remote, creates a branch, switches HEAD or mutates
    the index.  A protected HEAD, a non-target HEAD, a detached HEAD and any
    preexisting dirty path overlapping the writer's allowed scope are rejected
    before writer admission.
    """
    protected = [str(value) for value in (protected_branches or []) if value]
    if not target_branch or not protected:
        _fail(
            "Protected research admission requires explicit --target-branch and "
            "at least one --protected-branch"
        )
    if target_branch in protected:
        _fail(
            f"Protected research target branch {target_branch!r} is itself protected"
        )
    identity = _hook("canonical_workspace")(Path(workspace).expanduser())
    if not identity.get("is_git") or not identity.get("is_work_tree"):
        _fail(
            f"Protected research admission requires a Git work tree: {workspace}"
        )
    branch = _current_branch(Path(workspace).expanduser())
    problems: list[str] = []
    if branch is None:
        problems.append("HEAD is detached; check out the dedicated target branch")
    else:
        if branch in protected:
            problems.append(
                f"HEAD branch {branch!r} is protected and cannot admit a writer"
            )
        if branch != target_branch:
            problems.append(
                f"HEAD branch {branch!r} is not the configured target branch "
                f"{target_branch!r}"
            )
    current = snapshot
    if current is None:
        current = snapshot_workspace(Path(workspace).expanduser(), strict=True)
    if not current.get("is_git"):
        _fail(f"Protected research admission requires a Git work tree: {workspace}")
    if not current.get("supported"):
        problems.append(
            "workspace snapshot is unsupported: "
            + str(current.get("unsupported_reason"))
        )
    dirty = list(current.get("dirty_paths", []))
    allowed = [str(value) for value in (allowed_paths or []) if value]
    overlap: list[str] = []
    for path in dirty:
        if not allowed or any(
            fnmatch.fnmatch(path, pattern) for pattern in allowed
        ):
            overlap.append(path)
    if overlap:
        problems.append(
            "preexisting dirty paths overlap the writer's allowed scope: "
            + ", ".join(sorted(overlap))
        )
    if problems:
        _fail(
            "Protected research workspace validation failed for "
            f"{identity['root']}: " + "; ".join(problems)
        )
    return {
        "protected": True,
        "canonical_workspace": identity["root"],
        "branch": branch,
        "target_branch": target_branch,
        "protected_branches": protected,
        "dirty_paths": sorted(dirty),
        "allowed_paths": allowed,
        "denied_paths": [str(value) for value in (denied_paths or [])],
        "head": current.get("head"),
        "dirty_overlap": sorted(overlap),
    }


# ---------------------------------------------------------------------------
# Repository writer lease
# ---------------------------------------------------------------------------


def lease_supported() -> tuple[bool, str | None]:
    if sys.platform != "linux":
        return False, "repository writer leases require Linux subreaper semantics"
    if not Path("/proc/self/stat").exists():
        return False, "repository writer leases require /proc process identity"
    if not hasattr(fcntl, "flock"):
        return False, "repository writer leases require flock"
    return True, None


def lease_directory(identity: dict[str, Any]) -> Path | None:
    common = identity.get("git_common_dir")
    if not isinstance(common, str) or not common:
        return None
    return Path(common) / "agent-orchestrator" / LEASE_DIR_NAME


def lease_paths(identity: dict[str, Any]) -> dict[str, Path] | None:
    directory = lease_directory(identity)
    if directory is None:
        return None
    return {
        "directory": directory,
        "lock": directory / LEASE_LOCK_NAME,
        "owner": directory / LEASE_OWNER_NAME,
        "reconciliations": directory / RECONCILIATION_DIR,
    }


def _ensure_lease_directory(paths: dict[str, Path]) -> None:
    directory = paths["directory"]
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = os.lstat(directory)
    except OSError as exc:
        _fail(f"Cannot create the repository lease directory {directory}: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(f"The repository lease path is not a real directory: {directory}")
    os.chmod(directory, 0o700)


def _validate_owner(record: Any, identity: dict[str, Any], path: Path) -> dict[str, Any]:
    if not isinstance(record, dict):
        _fail(f"Repository writer lease owner record {path} is not a JSON object")
    required = {
        "version",
        "epoch",
        "canonical_workspace",
        "git_common_dir",
        "lock_path",
        "lock_dev",
        "lock_ino",
        "job_id",
        "job_dir",
        "state_home",
        "state",
        "coordinator",
        "supervisor",
        "created_at",
        "updated_at",
    }
    missing = sorted(required - set(record))
    if missing:
        _fail(
            f"Repository writer lease owner record {path} is incomplete: "
            + ", ".join(missing)
        )
    if record.get("version") != LEASE_VERSION:
        _fail(f"Repository writer lease owner record {path} has an unknown version")
    if not isinstance(record.get("epoch"), str) or not EPOCH_RE.fullmatch(
        record["epoch"]
    ):
        _fail(f"Repository writer lease owner record {path} has an invalid epoch")
    if record.get("canonical_workspace") != identity.get("root"):
        _fail(f"Repository writer lease owner record {path} belongs to another workspace")
    if record.get("git_common_dir") != identity.get("git_common_dir"):
        _fail(
            f"Repository writer lease owner record {path} belongs to another "
            "Git repository"
        )
    if record.get("state") not in LEASE_STATES:
        _fail(f"Repository writer lease owner record {path} has an unknown state")
    for key in ("lock_dev", "lock_ino"):
        value = record.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            _fail(f"Repository writer lease owner record {path} has an invalid {key}")
    for key in ("lock_path", "job_id", "job_dir", "state_home"):
        value = record.get(key)
        if not isinstance(value, str) or not value:
            _fail(f"Repository writer lease owner record {path} has an invalid {key}")
    for key in ("coordinator", "supervisor", "worker"):
        if key in record and record[key] is not None and not _valid_process_record(
            record[key]
        ):
            _fail(
                f"Repository writer lease owner record {path} has an invalid "
                f"{key} process identity"
            )
    for key in ("created_at", "updated_at"):
        if not isinstance(record.get(key), str) or not record[key]:
            _fail(f"Repository writer lease owner record {path} has an invalid {key}")
    return record


def read_owner(identity: dict[str, Any]) -> dict[str, Any] | None:
    paths = lease_paths(identity)
    if paths is None:
        return None
    path = paths["owner"]
    try:
        if not path.exists():
            return None
    except OSError:
        return None
    return _validate_owner(_read_json(path), identity, path)


def _write_owner(identity: dict[str, Any], record: dict[str, Any]) -> None:
    paths = lease_paths(identity)
    if paths is None:
        _fail("Cannot write a repository writer lease without a Git common directory")
    _write_json(paths["owner"], record)


# ---------------------------------------------------------------------------
# Per-job terminal completion receipts
# ---------------------------------------------------------------------------
#
# ``owner.json`` is the live admission record and is intentionally replaced by
# the next lease epoch.  It therefore cannot be the durable proof that an older
# job finished: doing so would make every historical success depend on the
# newest owner.  The supervisor instead writes an immutable per-job receipt in
# the job directory after the final descendant drain and final integrity check,
# while it still holds the flock.  The receipt names the epoch, job, workspace,
# lock inode and the exact final-check digest, so completion of every job stays
# verifiable after later owners take over.  Malformed, mismatched or unbound
# receipts fail closed instead of being interpreted as success.


def completion_receipt_path(job_dir: Path) -> Path:
    return Path(job_dir) / LEASE_RECEIPT_NAME


def _sha256_file(path: Path) -> str:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        _fail(f"Cannot read completion evidence {path}: {exc}")
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            _fail(f"Completion evidence {path} is not a regular file")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def publish_completion_receipt(
    identity: dict[str, Any],
    epoch: str,
    *,
    job_id: str,
    job_dir: Path,
    final_check: dict[str, Any],
    worker_state: Any = None,
) -> dict[str, Any]:
    """Persist the immutable per-job completion proof before releasing flock.

    The receipt is written after ``finalize_after_descendants`` (which runs only
    after ``ECHILD``) and before ``owner.json`` becomes terminal.  It is bound to
    the current lease epoch, job identity, lock inode and final-check digest.
    """
    paths = lease_paths(identity)
    if paths is None:
        _fail("Cannot publish a completion receipt without a Git common directory")
    owner = read_owner(identity)
    if owner is None:
        _fail("Cannot publish a completion receipt without an owner record")
    if owner.get("epoch") != epoch:
        _fail("Cannot publish a completion receipt for another lease epoch")
    if owner.get("job_id") != job_id:
        _fail("Cannot publish a completion receipt for another job")
    if owner.get("state") not in LEASE_ACTIVE_STATES:
        _fail(
            "Cannot publish a completion receipt while the lease is "
            f"{owner.get('state')!r}"
        )
    final_path = (Path(job_dir) / "final-check.json").resolve()
    if not final_path.is_file():
        _fail("Cannot publish a completion receipt without a final check")
    descendants = final_check.get("descendants")
    if not isinstance(descendants, dict):
        _fail(
            "Cannot publish a completion receipt without descendant drain evidence"
        )
    receipt = {
        "version": RECEIPT_VERSION,
        "state": "completed",
        "job_id": str(job_id),
        "epoch": epoch,
        "canonical_workspace": identity.get("root"),
        "git_common_dir": identity.get("git_common_dir"),
        "lock_path": str(paths["lock"]),
        "lock_dev": owner.get("lock_dev"),
        "lock_ino": owner.get("lock_ino"),
        "job_dir": str(Path(job_dir).resolve()),
        "completed_at": _now(),
        "supervisor": _record_or_none(os.getpid()),
        "worker_result_state": (
            str(worker_state) if isinstance(worker_state, str) else None
        ),
        "final_check": {
            "path": str(final_path),
            "sha256": _sha256_file(final_path),
            "state": final_check.get("state"),
            "violations_count": len(final_check.get("violations") or []),
            "descendants": {
                "reaped": descendants.get("reaped"),
                "terminated": descendants.get("terminated"),
            },
        },
    }
    _write_json(completion_receipt_path(job_dir), receipt)
    return receipt


def _load_completion_receipt(
    job_dir: Path,
    *,
    epoch: str,
    job_id: Any,
    lease: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None, str | None]:
    """Load and strictly validate one per-job completion receipt.

    Returns ``(receipt, final_check, gap_kind, reason)`` where ``gap_kind`` is
    ``None`` for a valid proof, ``"missing"`` when no receipt exists (legacy
    job) and ``"unclean"`` when the receipt or the final evidence it binds is
    unreadable, malformed or inconsistent.  Callers must fail closed for
    ``"unclean"``.
    """
    path = completion_receipt_path(job_dir)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, None, "missing", None
    except OSError as exc:
        return (
            None,
            None,
            "unclean",
            f"the durable completion receipt is unreadable: {exc}",
        )
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return (
            None,
            None,
            "unclean",
            f"the durable completion receipt is not a regular file: {path}",
        )
    try:
        receipt = _read_json(path)
    except Exception as exc:
        return (
            None,
            None,
            "unclean",
            f"the durable completion receipt is unreadable: {exc}",
        )
    required = {
        "version",
        "state",
        "job_id",
        "epoch",
        "canonical_workspace",
        "git_common_dir",
        "lock_path",
        "lock_dev",
        "lock_ino",
        "job_dir",
        "completed_at",
        "final_check",
    }
    missing = sorted(required - set(receipt))
    if missing:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt is incomplete: " + ", ".join(missing),
        )
    if receipt.get("version") != RECEIPT_VERSION:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has an unknown version",
        )
    if receipt.get("state") != "completed":
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt does not prove completion",
        )
    if receipt.get("epoch") != epoch:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt belongs to another lease epoch",
        )
    if job_id is not None and receipt.get("job_id") != job_id:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt belongs to another job",
        )
    for key in ("lock_dev", "lock_ino"):
        value = receipt.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return (
                None,
                None,
                "unclean",
                f"the durable completion receipt has an invalid {key}",
            )
    for key in ("canonical_workspace", "git_common_dir", "lock_path", "job_dir"):
        if not isinstance(receipt.get(key), str) or not receipt[key]:
            return (
                None,
                None,
                "unclean",
                f"the durable completion receipt has an invalid {key}",
            )
    if not isinstance(receipt.get("completed_at"), str) or not receipt["completed_at"]:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has an invalid completed_at",
        )
    supervisor = receipt.get("supervisor")
    if supervisor is not None and not _valid_process_record(supervisor):
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has an invalid supervisor identity",
        )
    if identity is not None:
        if receipt["canonical_workspace"] != identity.get("root"):
            return (
                None,
                None,
                "unclean",
                "the durable completion receipt belongs to another workspace",
            )
        if receipt["git_common_dir"] != identity.get("git_common_dir"):
            return (
                None,
                None,
                "unclean",
                "the durable completion receipt belongs to another Git repository",
            )
    if isinstance(lease, dict):
        for key in ("lock_dev", "lock_ino"):
            expected = lease.get(key)
            if (
                expected is not None
                and receipt.get(key) != expected
            ):
                return (
                    None,
                    None,
                    "unclean",
                    "the durable completion receipt does not match the job's "
                    f"recorded lease {key}",
                )
        if (
            isinstance(lease.get("lock_path"), str)
            and receipt["lock_path"] != lease["lock_path"]
        ):
            return (
                None,
                None,
                "unclean",
                "the durable completion receipt names another lease lock path",
            )
        receipt_path = lease.get("receipt_path")
        if isinstance(receipt_path, str) and (
            Path(receipt_path).resolve() != path.resolve()
        ):
            return (
                None,
                None,
                "unclean",
                "the durable completion receipt path does not match the job record",
            )
    if Path(receipt["job_dir"]).resolve() != Path(job_dir).resolve():
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt belongs to another job directory",
        )
    final_meta = receipt.get("final_check")
    if not isinstance(final_meta, dict):
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has no final check binding",
        )
    for key in ("path", "sha256", "state"):
        if not isinstance(final_meta.get(key), str) or not final_meta[key]:
            return (
                None,
                None,
                "unclean",
                "the durable completion receipt has an invalid final check binding",
            )
    if not _valid_sha256(final_meta["sha256"]):
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has an invalid final check digest",
        )
    if final_meta["state"] not in {"clean", "violations", "error"}:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has an unknown final check outcome",
        )
    if not isinstance(final_meta.get("descendants"), dict):
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt has no descendant drain evidence",
        )
    expected_final = (Path(job_dir) / "final-check.json").resolve()
    try:
        recorded_final = Path(final_meta["path"]).resolve()
    except (OSError, RuntimeError, ValueError):
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt names an unreadable final check path",
        )
    if recorded_final != expected_final:
        return (
            None,
            None,
            "unclean",
            "the durable completion receipt binds a final check from another job",
        )
    try:
        if not expected_final.is_file():
            return (
                None,
                None,
                "unclean",
                "the matching supervisor final check has not been published",
            )
        final = _read_json(expected_final)
    except Exception as exc:
        return (
            None,
            None,
            "unclean",
            f"the supervisor final check is unreadable: {exc}",
        )
    try:
        digest = _sha256_file(expected_final)
    except Exception as exc:
        return (
            None,
            None,
            "unclean",
            f"the matching supervisor final check is unreadable: {exc}",
        )
    if digest != final_meta["sha256"]:
        return (
            None,
            None,
            "unclean",
            "the supervisor final check does not match the durable completion receipt",
        )
    if final.get("epoch") != epoch:
        return (
            None,
            None,
            "unclean",
            "the supervisor final check belongs to another lease epoch",
        )
    if job_id is not None and final.get("job_id") != job_id:
        return (
            None,
            None,
            "unclean",
            "the supervisor final check belongs to another job",
        )
    if final.get("state") not in {"clean", "violations", "error"}:
        return (
            None,
            None,
            "unclean",
            "the supervisor final check has an unknown outcome",
        )
    if not isinstance(final.get("descendants"), dict):
        return (
            None,
            None,
            "unclean",
            "the supervisor final check has no durable descendant drain evidence",
        )
    return receipt, final, None, None


def _owner_completion_receipt(
    identity: dict[str, Any], owner: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Return a valid per-job receipt for an owner record, or ``None``."""
    if not isinstance(owner, dict):
        return None
    job_dir = owner.get("job_dir")
    epoch = owner.get("epoch")
    job_id = owner.get("job_id")
    if not isinstance(job_dir, str) or not job_dir:
        return None
    if not isinstance(epoch, str) or not EPOCH_RE.fullmatch(epoch):
        return None
    lease = {
        "lock_dev": owner.get("lock_dev"),
        "lock_ino": owner.get("lock_ino"),
        "lock_path": owner.get("lock_path"),
    }
    try:
        receipt, _final, gap, _reason = _load_completion_receipt(
            Path(job_dir),
            epoch=epoch,
            job_id=job_id,
            lease=lease,
            identity=identity,
        )
    except Exception:
        return None
    if gap is not None:
        return None
    return receipt


def _lock_inode(path: Path) -> dict[str, Any]:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"exists": False}
    except OSError as exc:
        _fail(f"Cannot inspect the repository writer lease lock {path}: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail(f"The repository writer lease lock is not a regular file: {path}")
    return {
        "exists": True,
        "dev": info.st_dev,
        "ino": info.st_ino,
        "size": info.st_size,
        "nlink": info.st_nlink,
    }


def probe_lock_file(lock_path: Path) -> dict[str, Any]:
    """Report whether one lease lock inode is currently held.

    A failed probe is reported as ``held=None`` so callers treat it as
    unproveable rather than free.  The probe only opens and briefly locks the
    existing never-unlinked inode; it never creates or removes anything.
    """
    inode = _lock_inode(lock_path)
    if not inode.get("exists"):
        return {**inode, "held": False}
    try:
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        return {**inode, "held": None, "error": str(exc)}
    try:
        opened = os.fstat(descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "exists": True,
                "held": True,
                "dev": opened.st_dev,
                "ino": opened.st_ino,
                "nlink": opened.st_nlink,
            }
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return {
            "exists": True,
            "held": False,
            "dev": opened.st_dev,
            "ino": opened.st_ino,
            "nlink": opened.st_nlink,
        }
    finally:
        os.close(descriptor)


def probe_lock(identity: dict[str, Any]) -> dict[str, Any]:
    """Report whether the lease lock is currently held without disturbing it."""
    paths = lease_paths(identity)
    if paths is None:
        return {"exists": False, "held": False}
    try:
        return probe_lock_file(paths["lock"])
    except Exception as exc:
        _fail(
            f"Cannot probe the repository writer lease lock {paths['lock']}: {exc}"
        )


def _owner_message(owner: dict[str, Any] | None) -> str:
    if not owner:
        return "no durable owner record exists"
    return (
        f"job {owner.get('job_id')} epoch {owner.get('epoch')} is in state "
        f"{owner.get('state')}"
    )


def _uncertain_message(identity: dict[str, Any], owner: dict[str, Any] | None) -> str:
    recovery = (
        "If you have independently verified that no worker or provider process "
        "for this job remains, record an evidence-backed reconciliation: "
        "agent-orchestrator lease-reconcile --workspace "
        f"{identity.get('root') or identity.get('workspace')} "
        f"--job-id {owner.get('job_id') if owner else '<job>'} "
        "--operator '<name>' --evidence '<what you verified>'"
    )
    if owner and owner.get("state") == "admission":
        missing = (
            "the launcher acquired the lock but no supervisor completion marker "
            "was published; a pre-spawn crash cannot be distinguished from an "
            "unpublished descendant tree"
        )
    else:
        missing = (
            "the supervisor did not publish state=completed before the flock was "
            "released; a stale PID and an empty process group do not prove that an "
            "adopted descendant tree (setsid/double-fork) exited"
        )
    return (
        "Repository writer lease for "
        f"{identity.get('root') or identity.get('workspace')} is blocked: "
        f"{_owner_message(owner)} but the lock is free. Cannot prove that all "
        f"writer descendants exited: {missing}. {recovery}. No writer will be "
        "admitted until that reconciliation is recorded."
    )


def assess_lease(identity: dict[str, Any]) -> dict[str, Any]:
    """Return lock, owner and fail-closed assessment without mutating state."""
    paths = lease_paths(identity)
    if paths is None:
        return {
            "state": "unsupported",
            "blocked": True,
            "message": "Workspace has no canonical Git common directory",
        }
    owner: dict[str, Any] | None = None
    owner_error: str | None = None
    try:
        owner = read_owner(identity)
    except Exception as exc:
        owner_error = str(exc)
    if owner_error:
        return {
            "state": "corrupt_owner",
            "blocked": True,
            "owner_path": str(paths["owner"]),
            "message": (
                "Repository writer lease state is unreadable and fails closed: "
                f"{owner_error}"
            ),
        }
    lock = probe_lock(identity)
    if owner is not None and not lock.get("exists"):
        return {
            "state": "lock_missing",
            "blocked": True,
            "owner": owner,
            "lock": lock,
            "owner_path": str(paths["owner"]),
            "lock_path": str(paths["lock"]),
            "message": (
                "Repository writer lease owner record exists but the "
                "never-unlinked lock inode is missing; inspect the lease "
                "directory and reconcile explicitly"
            ),
        }
    inode_mismatch = bool(
        owner
        and lock.get("exists")
        and (
            owner.get("lock_dev") != lock.get("dev")
            or owner.get("lock_ino") != lock.get("ino")
        )
    )
    if inode_mismatch:
        return {
            "state": "inode_mismatch",
            "blocked": True,
            "owner": owner,
            "lock": lock,
            "owner_path": str(paths["owner"]),
            "lock_path": str(paths["lock"]),
            "message": (
                "Repository writer lease lock inode changed under an existing "
                "owner record; the never-unlinked lock guarantee is broken. "
                "Inspect both paths and reconcile explicitly."
            ),
        }
    if lock.get("held"):
        return {
            "state": "held",
            "blocked": True,
            "owner": owner,
            "lock": lock,
            "owner_path": str(paths["owner"]),
            "lock_path": str(paths["lock"]),
            "message": (
                "Repository writer lease for "
                f"{identity.get('root') or identity.get('workspace')} is held by "
                + (
                    _owner_message(owner)
                    if owner
                    else "another admission that has not yet published its "
                    "owner record"
                )
                + ". The concurrent-workspace override cannot bypass this lease."
            ),
        }
    if owner is None:
        return {
            "state": "free",
            "blocked": False,
            "lock": lock,
            "owner_path": str(paths["owner"]),
            "lock_path": str(paths["lock"]),
            "message": None,
        }
    if owner.get("state") in LEASE_TERMINAL_STATES:
        return {
            "state": "free",
            "blocked": False,
            "owner": owner,
            "lock": lock,
            "owner_path": str(paths["owner"]),
            "lock_path": str(paths["lock"]),
            "message": None,
        }
    # A crash after the supervisor published the per-job completion receipt but
    # before it updated ``owner.json`` is recoverable when the receipt (written
    # after ECHILD while the lock was held) is valid and the lock is now free.
    receipt = _owner_completion_receipt(identity, owner)
    if receipt is not None:
        return {
            "state": "completed_receipt",
            "blocked": False,
            "owner": owner,
            "lock": lock,
            "recovery": {
                "kind": "completion_receipt",
                "epoch": owner.get("epoch"),
                "job_id": owner.get("job_id"),
                "receipt_path": str(
                    completion_receipt_path(Path(owner["job_dir"]))
                ),
            },
            "owner_path": str(paths["owner"]),
            "lock_path": str(paths["lock"]),
            "message": None,
        }
    return {
        "state": "uncertain_guardian_loss",
        "blocked": True,
        "owner": owner,
        "lock": lock,
        "owner_path": str(paths["owner"]),
        "lock_path": str(paths["lock"]),
        "missing_evidence": [
            "durable state=completed marker written by the lease supervisor for "
            f"epoch {owner.get('epoch')}",
            "proof that every adopted descendant of supervisor pid "
            f"{(owner.get('supervisor') or {}).get('pid')} exited",
        ],
        "recovery": (
            "Verify independently that no worker/provider process for job "
            f"{owner.get('job_id')} remains, then run lease-reconcile with "
            "--operator and --evidence; or inspect "
            f"{paths['owner']} and preserve it as incident evidence."
        ),
        "message": _uncertain_message(identity, owner),
    }


def lease_blocker(identity: dict[str, Any] | None) -> str | None:
    """Return a fail-closed reason when a writer lease must block admission."""
    if not isinstance(identity, dict) or not identity.get("is_git"):
        return None
    if lease_directory(identity) is None:
        return None
    try:
        assessment = assess_lease(identity)
    except Exception as exc:
        return f"Repository writer lease state unavailable; failing closed: {exc}"
    if assessment.get("blocked"):
        return str(assessment.get("message"))
    return None


def lease_owner_assessment(
    meta: dict[str, Any], job_dir: Path | None = None
) -> dict[str, Any]:
    """Classify the durable lease completion evidence for one job record.

    Returned ``kind`` values:

    * ``unleased`` -- the job has no B2 lease metadata (legacy or non-Git);
    * ``active`` -- a well-formed owner record is in ``admission`` or
      ``supervising`` and no terminal per-job receipt exists;
    * ``terminal`` -- a durable terminal hand-off exists: either the current
      owner record is terminal (``completed``, ``failed_admission`` or
      ``reconciled``), or an immutable per-job completion receipt bound to this
      job's epoch and final check survives later owner epochs, or a valid
      receipt proves completion while a free lock remains after a crash between
      publication steps;
    * ``unclean`` -- metadata, path, epoch, job identity, receipt or final
      evidence is missing, unreadable or inconsistent.  Callers must fail
      closed.

    This helper only reads evidence.  It never takes the lock or mutates the
    owner record.
    """
    lease = meta.get("workspace_lease") if isinstance(meta, dict) else None
    if not isinstance(lease, dict):
        return {"leased": False, "kind": "unleased", "reason": None}
    epoch = lease.get("epoch")
    owner_path = lease.get("owner_path")
    lock_path = lease.get("lock_path")
    job_id = meta.get("job_id")
    receipt_path = lease.get("receipt_path")
    base = {
        "leased": True,
        "epoch": epoch if isinstance(epoch, str) else None,
        "owner_path": owner_path if isinstance(owner_path, str) else None,
        "lock_path": lock_path if isinstance(lock_path, str) else None,
        "receipt_path": receipt_path if isinstance(receipt_path, str) else None,
    }
    if not isinstance(epoch, str) or not EPOCH_RE.fullmatch(epoch):
        return {
            **base,
            "kind": "unclean",
            "reason": "job record has an invalid repository lease epoch",
        }
    if not isinstance(owner_path, str) or not owner_path:
        return {
            **base,
            "kind": "unclean",
            "reason": "job record has no durable repository lease owner path",
        }
    receipt: dict[str, Any] | None = None
    receipt_final: dict[str, Any] | None = None
    resolved_job_dir: Path | None = None
    if job_dir is not None:
        resolved_job_dir = Path(job_dir)
    elif isinstance(lease.get("job_dir"), str) and lease["job_dir"]:
        resolved_job_dir = Path(lease["job_dir"])
    elif isinstance(receipt_path, str) and receipt_path:
        # The receipt lives in the job directory; support callers that only
        # carry its explicit path.
        resolved_job_dir = Path(receipt_path).parent
    if resolved_job_dir is not None:
        receipt, receipt_final, gap, gap_reason = _load_completion_receipt(
            resolved_job_dir,
            epoch=epoch,
            job_id=job_id,
            lease=lease,
        )
        if gap == "unclean":
            return {
                **base,
                "kind": "unclean",
                "receipt_path": str(
                    completion_receipt_path(resolved_job_dir)
                ),
                "reason": "durable completion evidence fails closed: "
                + str(gap_reason),
            }
    try:
        owner = _read_json(Path(owner_path))
    except Exception as exc:
        return {
            **base,
            "kind": "unclean",
            "reason": f"durable repository lease owner record is unreadable: {exc}",
        }
    if not isinstance(owner, dict):
        return {
            **base,
            "kind": "unclean",
            "reason": "durable repository lease owner record is not a JSON object",
        }
    owner_epoch = owner.get("epoch")
    owner_state = owner.get("state")
    if not isinstance(owner_epoch, str) or not EPOCH_RE.fullmatch(owner_epoch):
        return {
            **base,
            "kind": "unclean",
            "owner": owner,
            "reason": "durable repository lease owner record has an invalid epoch",
        }
    if owner_state not in LEASE_STATES:
        return {
            **base,
            "kind": "unclean",
            "owner": owner,
            "owner_state": owner_state,
            "reason": (
                "durable repository lease owner has an unknown state: "
                f"{owner_state!r}"
            ),
        }
    receipt_fields = {
        "receipt": receipt,
        "receipt_final_check": receipt_final,
    }
    if owner_epoch != epoch:
        if receipt is not None:
            # The live owner record now belongs to a later lease epoch.  The
            # immutable per-job receipt still proves this job's completion.
            return {
                **base,
                **receipt_fields,
                "kind": "terminal",
                "owner": owner,
                "owner_state": owner_state,
                "completion_proof": "receipt",
                "reason": None,
            }
        return {
            **base,
            "kind": "unclean",
            "owner": owner,
            "owner_state": owner_state,
            "reason": "durable repository lease owner epoch does not match the job",
        }
    if job_id is not None and owner.get("job_id") != job_id:
        return {
            **base,
            "kind": "unclean",
            "owner": owner,
            "owner_state": owner_state,
            "reason": "durable repository lease owner belongs to another job",
        }
    if receipt is not None:
        if owner_state in LEASE_TERMINAL_STATES:
            return {
                **base,
                **receipt_fields,
                "kind": "terminal",
                "owner": owner,
                "owner_state": owner_state,
                "completion_proof": "receipt",
                "reason": None,
            }
        # A crash after the receipt but before the owner update is recoverable
        # only when the lock is demonstrably free; while the lock is held the
        # supervisor may still be inside its publication window.
        try:
            probe = probe_lock_file(Path(lock_path)) if isinstance(lock_path, str) else None
        except Exception:
            probe = None
        if isinstance(probe, dict) and probe.get("held") is False:
            return {
                **base,
                **receipt_fields,
                "kind": "terminal",
                "owner": owner,
                "owner_state": owner_state,
                "completion_proof": "receipt_after_owner_crash",
                "reason": None,
            }
        return {
            **base,
            **receipt_fields,
            "kind": "active",
            "owner": owner,
            "owner_state": owner_state,
            "reason": None,
        }
    if (
        owner_state == "completed"
        and isinstance(lease.get("receipt_path"), str)
        and lease["receipt_path"]
    ):
        # This job was launched by a runner that records the per-job receipt
        # path.  A terminal completed owner without that durable proof means the
        # evidence was lost or publication never finished; fail closed instead
        # of falling back to the mutable owner record alone.
        return {
            **base,
            "kind": "unclean",
            "owner": owner,
            "owner_state": owner_state,
            "reason": (
                "the durable per-job completion receipt is missing for a "
                "completed lease owner"
            ),
        }
    return {
        **base,
        "kind": (
            "active" if owner_state in LEASE_ACTIVE_STATES else "terminal"
        ),
        "owner": owner,
        "owner_state": owner_state,
        "reason": None,
    }


def _final_check_evidence(
    job_dir: Path, epoch: Any, job_id: Any
) -> tuple[dict[str, Any] | None, str | None]:
    """Read one job's legacy final check and validate its identity binding."""
    final_path = Path(job_dir) / "final-check.json"
    try:
        if not final_path.is_file():
            return (
                None,
                "the matching supervisor final check has not been published",
            )
        value = _read_json(final_path)
    except Exception as exc:
        return None, f"the supervisor final check is unreadable: {exc}"
    if not isinstance(value, dict):
        return None, "the supervisor final check is not a JSON object"
    if value.get("epoch") != epoch:
        return None, "the supervisor final check belongs to another lease epoch"
    if job_id is not None and value.get("job_id") != job_id:
        return None, "the supervisor final check belongs to another job"
    if value.get("state") not in {"clean", "violations", "error"}:
        return None, (
            "the supervisor final check has an unknown outcome: "
            f"{value.get('state')!r}"
        )
    if not isinstance(value.get("descendants"), dict):
        return None, (
            "the supervisor final check has no durable descendant drain evidence"
        )
    return value, None


def completion_evidence(
    meta: dict[str, Any], job_dir: Path
) -> dict[str, Any]:
    """Report whether a leased job's completion is durably finalized.

    Externally visible completion requires the immutable per-job completion
    receipt written by the supervisor after the full adopted descendant tree
    drained (the receipt binds the exact ``final-check.json`` digest).  A
    terminal owner record alone is the legacy path for jobs that predate
    receipts.  A preliminary worker result -- success, failure, cancellation,
    timeout or scope violation -- never authorizes completion, review,
    dependencies or plan completion on its own.

    ``kind`` is ``pending`` while the supervisor can still prove it is running,
    and ``uncertain``/``missing_evidence``/``unclean`` when completion cannot be
    proven.  Callers must fail closed for every non-finalized result.
    """
    assessment = lease_owner_assessment(meta, job_dir)
    if not assessment.get("leased"):
        return {
            "leased": False,
            "finalized": False,
            "kind": "unleased",
            "reason": None,
        }
    if assessment.get("kind") == "unclean":
        return {
            **assessment,
            "finalized": False,
            "final_check": None,
        }
    epoch = assessment.get("epoch")
    job_id = meta.get("job_id") if isinstance(meta, dict) else None
    receipt_final = assessment.get("receipt_final_check")
    final: dict[str, Any] | None = None
    final_reason: str | None = None
    if assessment.get("kind") == "terminal":
        if isinstance(receipt_final, dict):
            return {
                **assessment,
                "finalized": True,
                "kind": "finalized",
                "final_check": receipt_final,
                "reason": None,
            }
        if assessment.get("owner_state") == "failed_admission":
            # The launcher or supervisor proved that no worker was ever
            # spawned, so there is no descendant tree and no integrity check to
            # wait for.  The explicit terminal owner state is complete
            # evidence; the failure outcome stands.
            return {
                **assessment,
                "finalized": True,
                "kind": "failed_admission",
                "final_check": None,
                "reason": None,
            }
        final, final_reason = _final_check_evidence(job_dir, epoch, job_id)
        if final is not None:
            return {
                **assessment,
                "finalized": True,
                "kind": "finalized",
                "final_check": final,
                "reason": None,
            }
        return {
            **assessment,
            "finalized": False,
            "kind": "missing_evidence",
            "final_check": None,
            "reason": final_reason,
        }
    def supervisor_can_prove_running() -> bool:
        """Return whether active ownership is backed by a live supervisor/lock."""
        owner = assessment.get("owner")
        probe = (
            process_probe(owner.get("supervisor"))
            if isinstance(owner, dict)
            else "unknown"
        )
        if probe == "alive":
            return True
        lock_path = assessment.get("lock_path")
        if isinstance(lock_path, str):
            try:
                return probe_lock_file(Path(lock_path)).get("held") is True
            except Exception:
                return False
        return False

    if isinstance(receipt_final, dict):
        # The receipt is durable, but the live owner record has not published
        # its terminal state yet.  Do not expose a result during the normal
        # publication window; the supervisor must still prove it is running.
        if supervisor_can_prove_running():
            return {
                **assessment,
                "finalized": False,
                "kind": "pending",
                "final_check": receipt_final,
                "reason": (
                    "the durable completion receipt exists but the terminal "
                    "owner marker is not yet published"
                ),
            }
        return {
            **assessment,
            "finalized": False,
            "kind": "uncertain",
            "final_check": receipt_final,
            "reason": (
                "the durable completion receipt exists but the terminal owner "
                "marker is unpublished and no live supervisor or held lock can "
                "prove the publication completed"
            ),
        }
    final, final_reason = _final_check_evidence(job_dir, epoch, job_id)
    if final is None:
        # The owner still claims active ownership.  Only a live supervisor (or
        # a lock that is actually held) may be treated as pending; anything
        # else is the fail-closed guardian-loss state.
        if supervisor_can_prove_running():
            return {
                **assessment,
                "finalized": False,
                "kind": "pending",
                "final_check": None,
                "reason": final_reason,
            }
        return {
            **assessment,
            "finalized": False,
            "kind": "uncertain",
            "final_check": None,
            "reason": (
                f"{final_reason} and no live lease supervisor or held lock can "
                "prove the adopted descendant tree exited"
            ),
        }
    if supervisor_can_prove_running():
        return {
            **assessment,
            "finalized": False,
            "kind": "pending",
            "final_check": final,
            "reason": (
                "the supervisor final check exists but the durable completion "
                "marker is not yet published"
            ),
        }
    return {
        **assessment,
        "finalized": False,
        "kind": "uncertain",
        "final_check": final,
        "reason": (
            "the supervisor final check exists but the durable completion "
            "marker is missing and the lock is free; completion cannot be "
            "proven until the owner record is terminal or reconciled"
        ),
    }


def job_drain_evidence(meta: dict[str, Any], job_dir: Path) -> bool:
    """Return whether this job's own durable evidence proves its epoch drained.

    Admission uses this only to recognise a lingering reservation whose owner
    record has since been replaced by a later lease epoch.  A valid per-job
    completion receipt (bound to the exact final check) or, for legacy jobs, a
    valid final check for the reservation's own epoch was written after the
    full adopted descendant tree reached ``ECHILD``, so the old job cannot
    still own the checkout.  Completion acceptance is separate and still
    requires ``completion_evidence``; this helper never authorizes success or
    review.
    """
    lease = meta.get("workspace_lease") if isinstance(meta, dict) else None
    if not isinstance(lease, dict):
        return False
    epoch = lease.get("epoch")
    job_id = meta.get("job_id")
    if not isinstance(epoch, str) or not EPOCH_RE.fullmatch(epoch):
        return False
    try:
        _receipt, _final, gap, _reason = _load_completion_receipt(
            Path(job_dir), epoch=epoch, job_id=job_id, lease=lease
        )
    except Exception:
        gap = "unclean"
    if gap is None:
        return True
    if gap == "unclean":
        return False
    try:
        value = _read_json(Path(job_dir) / "final-check.json")
    except Exception:
        return False
    if not isinstance(value, dict):
        return False
    if value.get("epoch") != epoch:
        return False
    if job_id is not None and value.get("job_id") != job_id:
        return False
    if value.get("state") not in {"clean", "violations", "error"}:
        return False
    return isinstance(value.get("descendants"), dict)


class WriterLease:
    """A held repository writer lease awaiting descriptor hand-off."""

    def __init__(
        self,
        identity: dict[str, Any],
        descriptor: int,
        epoch: str,
        owner: dict[str, Any],
        paths: dict[str, Path],
        job_dir: Path,
    ) -> None:
        self.identity = identity
        self.descriptor = descriptor
        self.epoch = epoch
        self.owner = owner
        self.paths = paths
        self.job_dir = Path(job_dir)
        self.handed_off = False

    def metadata(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "job_dir": str(self.job_dir.resolve()),
            "lock_path": str(self.paths["lock"]),
            "owner_path": str(self.paths["owner"]),
            "receipt_path": str(completion_receipt_path(self.job_dir)),
            "lock_dev": self.owner.get("lock_dev"),
            "lock_ino": self.owner.get("lock_ino"),
        }

    def close_parent_copy(self) -> None:
        """Close the launcher's descriptor after a successful hand-off.

        The supervisor shares the same open file description, so the flock is
        still held when this duplicate descriptor is closed.
        """
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        self.handed_off = True

    def abort(self, error: str) -> None:
        """Record a recoverable pre-spawn failure and release the lock."""
        try:
            owner = read_owner(self.identity)
            if (
                owner
                and owner.get("epoch") == self.epoch
                and owner.get("state") == "admission"
            ):
                owner.update(
                    {
                        "state": "failed_admission",
                        "error": str(error)[:MAX_LEASE_ERROR_BYTES],
                        "updated_at": _now(),
                    }
                )
                _write_owner(self.identity, owner)
        except Exception:
            # Preserve the original owner evidence if the failure transition
            # cannot be persisted; a later admission fails closed.
            pass
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        self.handed_off = True


def acquire_writer_lease(
    identity: dict[str, Any], job_id: str, job_dir: Path
) -> WriterLease:
    """Atomically acquire the repository writer lease and publish ownership.

    Must be called while the B1 repository admission lock is held so enrollment
    checks and launch admission share one ordering.  A non-terminal owner record
    is never overwritten: a free lock with an active record means the supervisor
    can no longer prove descendant completion.
    """
    supported, reason = lease_supported()
    if not supported:
        _fail(f"Repository writer leases are unsupported here: {reason}")
    if not identity.get("is_git") or not identity.get("git_common_dir"):
        _fail("Repository writer leases require a canonical Git worktree")
    paths = lease_paths(identity)
    if paths is None:
        _fail("Repository writer leases require a canonical Git common directory")
    _ensure_lease_directory(paths)
    try:
        descriptor = os.open(
            paths["lock"],
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except OSError as exc:
        _fail(f"Cannot open the repository writer lease lock {paths['lock']}: {exc}")
    try:
        try:
            os.fchmod(descriptor, 0o600)
        except OSError as exc:
            _fail(f"Cannot secure the repository writer lease lock: {exc}")
        # A just-completed supervisor writes state=completed before closing the
        # descriptor. Brief retries let a normal wait-then-launch workflow
        # reacquire instead of observing that stable hand-off window as a
        # contention failure. Held active ownership is still refused at once.
        release_deadline = time.monotonic() + 0.5
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                owner: dict[str, Any] | None = None
                try:
                    owner = read_owner(identity)
                except Exception:
                    owner = None
                if (
                    owner is not None
                    and owner.get("state") in LEASE_TERMINAL_STATES
                    and time.monotonic() < release_deadline
                ):
                    time.sleep(0.02)
                    continue
                _fail(
                    "Repository writer lease for "
                    f"{identity.get('root')} is held by "
                    f"{_owner_message(owner) if owner else 'another admission process'}. "
                    "Only one writer may hold a Git checkout; the "
                    "concurrent-workspace override cannot bypass this lease."
                )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink == 0:
            _fail(
                "Repository writer lease lock is not a stable linked regular file; "
                "refusing admission"
            )
        owner = read_owner(identity)
        recovery: dict[str, Any] | None = None
        if owner is not None:
            if (
                owner.get("lock_dev") != opened.st_dev
                or owner.get("lock_ino") != opened.st_ino
            ):
                _fail(
                    "Repository writer lease lock inode changed under an existing "
                    "owner record; inspect the lease directory before admitting a "
                    "writer"
                )
            if owner.get("state") not in LEASE_TERMINAL_STATES:
                # A supervisor crash after publishing the per-job completion
                # receipt but before updating the owner record is provably a
                # finished hand-off: the receipt was written after ECHILD while
                # the flock was held, and it is bound to the exact final check.
                receipt = _owner_completion_receipt(identity, owner)
                if receipt is None:
                    _fail(_uncertain_message(identity, owner))
                recovery = {
                    "kind": "completion_receipt",
                    "epoch": owner.get("epoch"),
                    "job_id": owner.get("job_id"),
                    "receipt_path": str(
                        completion_receipt_path(Path(owner["job_dir"]))
                    ),
                }
        epoch = secrets.token_hex(16)
        owner = {
            "version": LEASE_VERSION,
            "epoch": epoch,
            "canonical_workspace": identity.get("root"),
            "git_common_dir": identity.get("git_common_dir"),
            "lock_path": str(paths["lock"]),
            "owner_path": str(paths["owner"]),
            "lock_dev": opened.st_dev,
            "lock_ino": opened.st_ino,
            "job_id": str(job_id),
            "job_dir": str(Path(job_dir).resolve()),
            "state_home": str(_hook("state_home")()),
            "state": "admission",
            "descendants": "unknown",
            "coordinator": _record_or_none(os.getpid()),
            "supervisor": None,
            "created_at": _now(),
            "updated_at": _now(),
        }
        if recovery is not None:
            owner["recovery"] = recovery
        _write_owner(identity, owner)
        return WriterLease(identity, descriptor, epoch, owner, paths, job_dir)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def supervisor_attach(
    descriptor: int, epoch: str, job_dir: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Adopt an inherited lease descriptor and publish supervisor ownership.

    Any mismatch (descriptor, inode, epoch, owner state) fails closed before a
    worker is spawned.
    """
    supported, reason = lease_supported()
    if not supported:
        _fail(f"Lease supervisor is unsupported here: {reason}")
    meta = _read_json(Path(job_dir) / "meta.json")
    workspace = meta.get("workspace")
    if not isinstance(workspace, str) or not workspace:
        _fail("Job record has no workspace for lease supervision")
    identity = _hook("canonical_workspace")(Path(workspace))
    if not identity.get("is_git"):
        _fail("Lease supervision requires a canonical Git workspace")
    paths = lease_paths(identity)
    if paths is None:
        _fail("Lease supervision requires a Git common directory")
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        _fail(f"Lease supervisor did not inherit a valid lock descriptor: {exc}")
    lock_inode = _lock_inode(paths["lock"])
    if (
        not lock_inode.get("exists")
        or lock_inode.get("dev") != opened.st_dev
        or lock_inode.get("ino") != opened.st_ino
        or lock_inode.get("nlink") in (0, None)
    ):
        _fail(
            "Inherited lease descriptor does not match the canonical, linked "
            "lease lock inode; refusing to supervise"
        )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        _fail(f"Lease supervisor does not actually hold the lock: {exc}")
    owner = read_owner(identity)
    if owner is None:
        _fail("Lease supervisor found no durable owner record")
    if owner.get("epoch") != epoch:
        _fail("Lease supervisor epoch does not match the durable owner record")
    if owner.get("state") != "admission":
        _fail(
            "Lease supervisor refuses owner state "
            f"{owner.get('state')!r}; expected 'admission'"
        )
    if (
        owner.get("lock_dev") != opened.st_dev
        or owner.get("lock_ino") != opened.st_ino
    ):
        _fail("Lease supervisor locked a different inode than the owner record")
    job_meta_lease = meta.get("workspace_lease")
    if not isinstance(job_meta_lease, dict) or job_meta_lease.get("epoch") != epoch:
        _fail("Job record does not name this lease epoch")
    owner.update(
        {
            "state": "supervising",
            "descendants": "running",
            "supervisor": _record_or_none(os.getpid()),
            "updated_at": _now(),
        }
    )
    _write_owner(identity, owner)
    return identity, owner


def supervisor_failure(
    identity: dict[str, Any],
    epoch: str,
    error: str,
    *,
    proven_no_descendants: bool,
) -> None:
    """Mark a provably pre-worker supervisor failure recoverable.

    ``proven_no_descendants`` is only passed by code paths that run before the
    worker is spawned.  Otherwise the owner record stays non-terminal so a
    possibly adopted descendant tree fails admission closed.
    """
    if not proven_no_descendants:
        return
    try:
        owner = read_owner(identity)
    except Exception:
        return
    if not owner or owner.get("epoch") != epoch:
        return
    if owner.get("state") in LEASE_ACTIVE_STATES:
        owner.update(
            {
                "state": "failed_admission",
                "error": str(error)[:MAX_LEASE_ERROR_BYTES],
                "supervisor_error": str(error)[:MAX_LEASE_ERROR_BYTES],
                "updated_at": _now(),
            }
        )
        try:
            _write_owner(identity, owner)
        except Exception:
            return


def supervisor_error(identity: dict[str, Any], epoch: str, error: str) -> None:
    """Attach diagnostic evidence without clearing an uncertain ownership."""
    try:
        owner = read_owner(identity)
    except Exception:
        return
    if not owner or owner.get("epoch") != epoch:
        return
    if owner.get("state") not in LEASE_ACTIVE_STATES:
        return
    owner.update(
        {
            "supervisor_error": str(error)[:MAX_LEASE_ERROR_BYTES],
            "updated_at": _now(),
        }
    )
    try:
        _write_owner(identity, owner)
    except Exception:
        return


def mark_lease_completed(
    identity: dict[str, Any],
    epoch: str,
    *,
    job_id: str,
    final_check: dict[str, Any] | None,
) -> dict[str, Any]:
    """Publish the durable completion proof before the flock is released."""
    owner = read_owner(identity)
    if owner is None:
        _fail("Cannot complete a repository writer lease without an owner record")
    if owner.get("epoch") != epoch:
        _fail("Cannot complete a repository writer lease owned by another epoch")
    if owner.get("job_id") != job_id:
        _fail("Cannot complete a repository writer lease owned by another job")
    if owner.get("state") not in LEASE_ACTIVE_STATES:
        _fail(
            "Cannot complete a repository writer lease in state "
            f"{owner.get('state')!r}"
        )
    owner.update(
        {
            "state": "completed",
            "descendants": "drained",
            "completed_at": _now(),
            "updated_at": _now(),
            "final_check": (
                {
                    **{
                        key: final_check.get(key)
                        for key in ("state", "evidence", "finished_at")
                        if key in final_check
                    },
                    "violations": _bounded_violations(
                        list(final_check.get("violations") or [])
                    )[:MAX_OWNER_VIOLATIONS],
                    "violations_count": len(final_check.get("violations") or []),
                }
                if final_check
                else None
            ),
        }
    )
    _write_owner(identity, owner)
    return owner


def close_lease_descriptor(descriptor: int) -> None:
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError:
            pass


def set_child_subreaper() -> None:
    """Become the nearest reaper for orphaned worker/provider descendants."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        _fail(f"Cannot load libc for subreaper semantics: {exc}")
    result = libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    if result != 0:
        errno_value = ctypes.get_errno()
        _fail(
            "Cannot enable Linux child-subreaper semantics "
            f"(prctl errno {errno_value}); refusing to supervise a writer"
        )


def _proc_ppid(pid: int) -> int | None:
    try:
        data = Path(f"/proc/{pid}/stat").read_bytes()
        tail = data.rsplit(b")", 1)[1].split()
        return int(tail[1])
    except (OSError, IndexError, ValueError):
        return None


def descendant_pids(root_pid: int) -> list[int]:
    """Return every live descendant of ``root_pid`` by walking ``/proc`` PPIDs.

    Orphaned setsid/double-fork children are reparented to the subreaper, but a
    grandchild whose intermediate parent is still alive remains a grandchild;
    the walk covers both shapes before a timeout/cancel termination.
    """
    children: dict[int, list[int]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        ppid = _proc_ppid(pid)
        if ppid is None:
            continue
        children.setdefault(ppid, []).append(pid)
    found: list[int] = []
    queue = list(children.get(root_pid, []))
    seen: set[int] = set()
    while queue:
        pid = queue.pop()
        if pid in seen:
            continue
        seen.add(pid)
        found.append(pid)
        queue.extend(children.get(pid, []))
    return found


def terminate_descendant_tree(root_pid: int) -> list[int]:
    victims = descendant_pids(root_pid)
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            continue
    return victims


def drain_descendants(
    job_dir: Path, timeout_seconds: float | None
) -> dict[str, Any]:
    """Reap every child and adopted descendant until the kernel reports ECHILD.

    Polling rather than a blocking wait lets the supervisor terminate an
    escaped descendant tree once the job deadline or an explicit cancellation
    has passed; otherwise a double-fork daemon could hold the repository lease
    forever.  Termination is recorded as evidence; completion is still proven
    only by ECHILD.
    """
    reaped: list[int] = []
    terminated: str | None = None
    deadline = (
        time.monotonic() + float(timeout_seconds) + 5
        if isinstance(timeout_seconds, (int, float)) and timeout_seconds > 0
        else None
    )
    cancel_first_seen: float | None = None
    last_termination: float | None = None

    def terminate(reason: str) -> str:
        victims = terminate_descendant_tree(os.getpid())
        try:
            _hook("add_event")(
                job_dir,
                "supervisor_terminated_descendants",
                reason=reason,
                pids=victims[-20:],
            )
        except Exception:
            pass
        return reason

    while True:
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return {
                    "reaped": len(reaped),
                    "last_pids": reaped[-8:],
                    "terminated": terminated,
                }
            except InterruptedError:
                continue
            except OSError as exc:
                _fail(f"Lease supervisor cannot reap descendants: {exc}")
            if pid <= 0:
                break
            reaped.append(pid)
        now = time.monotonic()
        if deadline is not None and now >= deadline and terminated is None:
            terminated = terminate("timeout")
            last_termination = now
        if terminated is not None and last_termination is not None:
            if now - last_termination >= 0.5:
                # Re-kill on a short cadence so a descendant that forks during
                # the first sweep cannot hold the lease indefinitely.
                terminate(terminated)
                last_termination = now
        if (job_dir / "cancel-requested").exists():
            if cancel_first_seen is None:
                cancel_first_seen = now
            elif (
                terminated is None
                and now - cancel_first_seen >= CANCEL_GRACE_SECONDS
            ):
                terminated = terminate("cancel")
                last_termination = now
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Worker-side lease validation
# ---------------------------------------------------------------------------


def worker_lease_block(meta: dict[str, Any]) -> str | None:
    """Fail a worker closed when it does not run under the current lease.

    Leased jobs must match the durable epoch and a live supervisor.  Legacy or
    directly restarted jobs with no lease metadata keep working only while no
    lease is held or uncertain.
    """
    if not isinstance(meta, dict):
        return "Job record is not an object"
    workspace = meta.get("workspace")
    if not isinstance(workspace, str) or not workspace:
        return None
    try:
        identity = _hook("canonical_workspace")(Path(workspace))
    except Exception as exc:
        return f"Repository lease state unavailable; failing closed: {exc}"
    if not identity.get("is_git"):
        return None
    lease_meta = meta.get("workspace_lease")
    try:
        assessment = assess_lease(identity)
    except Exception as exc:
        return f"Repository lease state unavailable; failing closed: {exc}"
    if not isinstance(lease_meta, dict):
        if assessment.get("blocked"):
            return (
                "Legacy job may not start while the repository writer lease is "
                f"blocked: {assessment.get('message')}"
            )
        return None
    if assessment.get("state") != "held":
        return (
            "Leased job's repository writer lease is "
            f"{assessment.get('state')!r}; refusing to start a writer: "
            f"{assessment.get('message')}"
        )
    epoch = lease_meta.get("epoch")
    owner = assessment.get("owner")
    if not isinstance(owner, dict):
        return (
            "Leased job has no durable repository lease owner record; failing "
            "closed"
        )
    if owner.get("epoch") != epoch:
        return (
            "Leased job epoch does not match the repository lease owner; "
            "refusing to start a writer"
        )
    if owner.get("job_id") != meta.get("job_id"):
        return "Repository lease owner belongs to another job; refusing to start"
    if owner.get("state") not in LEASE_ACTIVE_STATES:
        return (
            "Repository lease owner is already "
            f"{owner.get('state')!r}; refusing to start a stale worker"
        )
    if not assessment.get("lock", {}).get("held"):
        return (
            "Repository lease owner is active but the lock is free; the "
            "supervisor cannot prove descendant completion. Failing closed"
        )
    supervisor = owner.get("supervisor")
    probe = process_probe(supervisor)
    if probe != "alive":
        return (
            "Repository lease supervisor is "
            f"{probe}; refusing to start a writer without a live supervisor"
        )
    return None


def reconcile_lease(
    identity: dict[str, Any],
    *,
    job_id: str,
    operator: str,
    evidence: str,
) -> dict[str, Any]:
    """Record an explicit, evidence-backed recovery of an unclean lease.

    The lock must be free, the owner record must name ``job_id`` and no recorded
    process identity may still be alive.  The operator's evidence is persisted
    verbatim; ownership is never cleared silently.
    """
    supported, reason = lease_supported()
    if not supported:
        _fail(f"Repository writer leases are unsupported here: {reason}")
    paths = lease_paths(identity)
    if paths is None:
        _fail("Workspace has no canonical Git common directory")
    if not operator.strip() or not evidence.strip():
        _fail("Lease reconciliation requires a non-empty operator and evidence")
    if len(evidence.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        _fail(f"Lease reconciliation evidence exceeds {MAX_EVIDENCE_BYTES} bytes")
    _ensure_lease_directory(paths)
    try:
        descriptor = os.open(
            paths["lock"], os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        _fail(f"Cannot open the repository writer lease lock: {exc}")
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail(
                "Refusing to reconcile: the repository writer lease lock is "
                "currently held"
            )
        owner = read_owner(identity)
        if owner is None:
            _fail("No repository writer lease owner record exists to reconcile")
        if owner.get("job_id") != job_id:
            _fail(
                "Refusing to reconcile lease owner for job "
                f"{owner.get('job_id')!r}; requested {job_id!r}"
            )
        if owner.get("state") in LEASE_TERMINAL_STATES:
            return {"reconciled": False, "owner": owner, "already_terminal": True}
        checks: list[dict[str, Any]] = []
        live: list[str] = []
        unknown: list[str] = []
        for key in ("coordinator", "supervisor", "worker"):
            record = owner.get(key)
            if record is None:
                continue
            probe = process_probe(record)
            checks.append({"role": key, "probe": probe, "record": record})
            if probe == "alive":
                live.append(key)
            elif probe == "unknown":
                unknown.append(key)
        job_dir = owner.get("job_dir")
        if isinstance(job_dir, str) and job_dir:
            try:
                meta = _read_json(Path(job_dir) / "meta.json")
            except Exception:
                meta = {}
            for key in ("worker_pid", "provider_pid", "child_pid"):
                pid = meta.get(key)
                if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
                    continue
                record = process_record(pid)
                if record is None:
                    checks.append(
                        {"role": key, "probe": "dead", "record": {"pid": pid, "start": None}}
                    )
                    continue
                probe = process_probe(record)
                checks.append({"role": key, "probe": probe, "record": record})
                if probe == "alive":
                    live.append(key)
                elif probe == "unknown":
                    unknown.append(key)
        if live or unknown:
            os.close(descriptor)
            _fail(
                "Refusing to reconcile: recorded processes are "
                + ("alive: " + ", ".join(sorted(live)) if live else "")
                + ("unprobeable: " + ", ".join(sorted(unknown)) if unknown else "")
                + ". Stop them and verify their exit first"
            )
        record_path = paths["reconciliations"] / (
            f"{owner['epoch']}-{int(time.time())}-{secrets.token_hex(4)}.json"
        )
        record = {
            "version": 1,
            "epoch": owner["epoch"],
            "job_id": job_id,
            "operator": operator.strip()[:200],
            "evidence": evidence.strip(),
            "reconciled_at": _now(),
            "lock_path": str(paths["lock"]),
            "lock_dev": owner.get("lock_dev"),
            "lock_ino": owner.get("lock_ino"),
            "owner_state": owner.get("state"),
            "process_checks": checks,
            "prior_owner": owner,
        }
        _write_json(record_path, record)
        owner.update(
            {
                "state": "reconciled",
                "reconciled_at": record["reconciled_at"],
                "reconciliation": str(record_path),
                "updated_at": _now(),
            }
        )
        _write_owner(identity, owner)
        return {
            "reconciled": True,
            "owner": owner,
            "evidence_path": str(record_path),
            "process_checks": checks,
        }
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Lease supervisor runtime
# ---------------------------------------------------------------------------

MAX_RESULT_PATHS = 200
MAX_OWNER_VIOLATIONS = 20


def _bounded_violations(values: list[str]) -> list[str]:
    unique = list(dict.fromkeys(values))
    if len(unique) <= MAX_RESULT_PATHS:
        return unique
    remaining = len(unique) - MAX_RESULT_PATHS
    return unique[:MAX_RESULT_PATHS] + [
        f"{remaining} additional violations recorded in final-check.json"
    ]


def _spawn_worker(job_dir: Path) -> subprocess.Popen[Any]:
    runner = Path(__file__).resolve().with_name("cli_agent_job.py")
    log_path = job_dir / "runner.log"
    log = log_path.open("ab", buffering=0)
    try:
        return subprocess.Popen(
            [
                sys.executable,
                str(runner),
                "_worker",
                "--job-dir",
                str(job_dir),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            close_fds=True,
        )
    finally:
        log.close()


def _record_supervisor_process(
    meta_path: Path, meta: dict[str, Any], worker_pid: int
) -> dict[str, Any]:
    """Record supervisor/worker identities without resurrecting a result."""
    if not meta_path.is_file():
        return meta
    lock = _hook("record_lock")
    try:
        with lock(meta_path):
            latest = _read_json(meta_path) if meta_path.is_file() else dict(meta)
            if (meta_path.parent / "result.json").is_file():
                return latest
            if latest.get("state") in {
                "succeeded",
                "failed",
                "cancelled",
                "timed_out",
                "scope_violated",
                "lost",
            }:
                return latest
            latest.update(
                {
                    "supervisor_pid": os.getpid(),
                    "supervisor_start": process_start_identity(os.getpid()),
                    "worker_pid": worker_pid,
                    "worker_start": process_start_identity(worker_pid),
                }
            )
            _hook("write_json")(meta_path, latest)
            return latest
    except Exception:
        return meta


def _compact_final_check(final: dict[str, Any]) -> dict[str, Any]:
    report = final.get("report") if isinstance(final.get("report"), dict) else {}
    paths = report.get("paths") if isinstance(report.get("paths"), list) else []
    compact_paths = [str(path) for path in paths[:MAX_RESULT_PATHS]]
    return {
        "version": final.get("version"),
        "job_id": final.get("job_id"),
        "epoch": final.get("epoch"),
        "state": final.get("state"),
        "finished_at": final.get("finished_at"),
        "evidence": final.get("evidence"),
        "descendants": final.get("descendants"),
        "violations": list(final.get("violations") or [])[:MAX_RESULT_PATHS],
        "changed_count": report.get("count"),
        "changed_paths": compact_paths,
        "changed_truncated": bool(report.get("changed_truncated"))
        or len(paths) > MAX_RESULT_PATHS,
        "head_changed": report.get("head_changed"),
        "branch_changed": report.get("branch_changed"),
        "index_changed": report.get("index_changed"),
        "index_baseline_sha256": report.get("index_baseline_sha256"),
        "index_current_sha256": report.get("index_current_sha256"),
        "error": final.get("error"),
    }


def finalize_after_descendants(
    job_dir: Path,
    epoch: str,
    identity: dict[str, Any],
    *,
    terminated: str | None = None,
    drain: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the final integrity check after every descendant has exited.

    The caller still holds the lease, so no other writer can interleave.  The
    full attributable report is persisted in ``final-check.json``; the job
    result carries a compact summary and any scope violations.
    """
    meta_path = job_dir / "meta.json"
    meta = _read_json(meta_path) if meta_path.is_file() else {}
    job_id = str(meta.get("job_id") or job_dir.name)
    evidence_path = job_dir / "final-check.json"
    base = {
        "version": 1,
        "job_id": job_id,
        "epoch": epoch,
        "supervisor": _record_or_none(os.getpid()),
        "finished_at": _now(),
        "evidence": str(evidence_path),
    }
    try:
        lease_meta = meta.get("workspace_lease")
        if not isinstance(lease_meta, dict) or lease_meta.get("epoch") != epoch:
            raise _hook("runner_error")(
                "job record does not name the lease epoch being finalized"
            )
        workspace = meta.get("workspace")
        if not isinstance(workspace, str) or not workspace:
            raise _hook("runner_error")("job record has no workspace")
        report = final_integrity_report(
            Path(workspace),
            meta.get("git_baseline") or {},
            meta.get("scope") or {},
        )
        violations = list(report.get("scope_violations") or [])
        if not report.get("supported", False):
            # An unfinished integrity observation must never be reported as a
            # clean final check; the job fails closed instead.
            final_state = "error"
            final_error = str(
                report.get("reason") or "final integrity snapshot is unsupported"
            )
        else:
            final_state = "violations" if violations else "clean"
            final_error = None
    except Exception as exc:
        report = {
            "supported": False,
            "reason": f"{type(exc).__name__}: {exc}",
            "scope_violations": [],
            "paths": [],
        }
        violations = []
        final_state = "error"
        final_error = f"{type(exc).__name__}: {exc}"
    final = {
        **base,
        "state": final_state,
        "report": report,
        "violations": violations,
        "error": final_error,
        "descendants": drain or {"reaped": 0, "terminated": terminated},
    }
    _write_json(evidence_path, final)
    compact = _compact_final_check(final)
    lock = _hook("record_lock")
    with lock(meta_path):
        latest = _read_json(meta_path) if meta_path.is_file() else dict(meta)
        result: dict[str, Any] = {}
        if (job_dir / "result.json").is_file():
            result = _read_json(job_dir / "result.json")
        if not result:
            if violations:
                inferred = "scope_violated"
            elif (job_dir / "cancel-requested").exists() or terminated == "cancel":
                inferred = "cancelled"
            elif terminated == "timeout":
                inferred = "timed_out"
            else:
                inferred = "lost"
            result = {
                "state": inferred,
                "started_at": latest.get("started_at") or latest.get("created_at"),
                "finished_at": _now(),
                "duration_seconds": 0.0,
                "exit_code": None,
                "timed_out": False,
                "scope_violations": [],
                "usage_summary": None,
                "supervisor_inferred": True,
            }
        if violations:
            merged = sorted(
                set(result.get("scope_violations") or []) | set(violations)
            )
            result["scope_violations"] = _bounded_violations(merged)
            if result.get("state") != "scope_violated":
                result.setdefault("previous_state", result.get("state"))
                result["state"] = "scope_violated"
        elif result.get("state") != "scope_violated" and terminated == "timeout":
            result.setdefault("previous_state", result.get("state"))
            result["state"] = "timed_out"
            result["timed_out"] = True
            result["descendant_timeout"] = True
        elif result.get("state") != "scope_violated" and (
            terminated == "cancel" or (job_dir / "cancel-requested").exists()
        ):
            if result.get("state") in {None, "starting", "running", "failed", "lost"}:
                result.setdefault("previous_state", result.get("state"))
                result["state"] = "cancelled"
        elif final_state == "error" and result.get("state") in {
            None,
            "starting",
            "running",
            "succeeded",
        }:
            result.setdefault("previous_state", result.get("state"))
            result["state"] = "failed"
            result["final_check_error"] = final_error
        if terminated:
            compact["terminated_descendants"] = terminated
        result["final_check"] = compact
        latest.update(result)
        _hook("write_json")(job_dir / "result.json", result)
        _hook("write_json")(meta_path, latest)
    try:
        _hook("add_event")(
            job_dir,
            "supervisor_finalized",
            state=compact.get("state"),
            changed_count=compact.get("changed_count"),
            violations=violations[:10],
        )
        if violations:
            _hook("add_event")(
                job_dir, "final_scope_violation", violations=violations[:10]
            )
    except Exception:
        pass
    return final, latest


def _release_reservation(identity: dict[str, Any], meta: dict[str, Any]) -> None:
    release = _optional_hook("release_reservation")
    if release is None:
        return
    job_id = meta.get("job_id")
    reservation_id = meta.get("reservation_id")
    if not isinstance(job_id, str) or not reservation_id:
        return
    try:
        release(identity, job_id, reservation_id)
    except Exception:
        # The expired reservation is pruned by B1; completion evidence is
        # already durable and the lease cannot silently admit another writer.
        pass


def run_supervisor(job_dir: Path, descriptor: int, epoch: str) -> int:
    """Hold the lease, adopt every descendant, then finalize and release.

    Returns 0 only after durable completion was published.  Any exception after
    the worker was spawned leaves the owner record non-terminal, so the next
    admission fails closed until an explicit reconciliation.
    """
    try:
        identity, owner = supervisor_attach(descriptor, epoch, job_dir)
    except Exception:
        close_lease_descriptor(descriptor)
        return 3
    for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(name, signal.SIG_IGN)
        except (OSError, ValueError):
            pass
    worker_spawned = False
    try:
        meta = _read_json(job_dir / "meta.json")
        try:
            set_child_subreaper()
        except Exception as exc:
            supervisor_failure(
                identity,
                epoch,
                f"{type(exc).__name__}: {exc}",
                proven_no_descendants=True,
            )
            close_lease_descriptor(descriptor)
            return 3
        try:
            worker = _spawn_worker(job_dir)
        except Exception as exc:
            supervisor_failure(
                identity,
                epoch,
                f"{type(exc).__name__}: {exc}",
                proven_no_descendants=True,
            )
            close_lease_descriptor(descriptor)
            return 3
        worker_spawned = True
        meta = _record_supervisor_process(job_dir / "meta.json", meta, worker.pid)
        try:
            owner = read_owner(identity)
            if owner is not None and owner.get("epoch") == epoch:
                owner.update(
                    {
                        "worker": _record_or_none(worker.pid),
                        "updated_at": _now(),
                    }
                )
                _write_owner(identity, owner)
        except Exception:
            pass
        drain = drain_descendants(job_dir, meta.get("timeout_seconds"))
        final, latest = finalize_after_descendants(
            job_dir,
            epoch,
            identity,
            terminated=drain.get("terminated"),
            drain=drain,
        )
        job_id = str(latest.get("job_id") or job_dir.name)
        # Publish the immutable, per-epoch completion proof before making the
        # mutable owner record terminal.  It stays verifiable after later lease
        # epochs replace owner.json.
        publish_completion_receipt(
            identity,
            epoch,
            job_id=job_id,
            job_dir=job_dir,
            final_check=final,
            worker_state=latest.get("state"),
        )
        owner = mark_lease_completed(
            identity,
            epoch,
            job_id=job_id,
            final_check={
                "state": final.get("state"),
                "violations": final.get("violations"),
                "evidence": final.get("evidence"),
                "finished_at": final.get("finished_at"),
            },
        )
        close_lease_descriptor(descriptor)
        _release_reservation(identity, latest)
        return 0
    except Exception as exc:
        if worker_spawned:
            supervisor_error(identity, epoch, f"{type(exc).__name__}: {exc}")
        else:
            supervisor_failure(
                identity,
                epoch,
                f"{type(exc).__name__}: {exc}",
                proven_no_descendants=True,
            )
        close_lease_descriptor(descriptor)
        return 4
