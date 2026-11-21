#!/usr/bin/env python3
"""D2 independent validation, active-Codex review and bounded DeepSeek repair.

The module is loaded by ``cli_agent_job.py`` by absolute path, matching the
B1/B2/C/D1 pattern. It adds one bounded D2 layer over the existing engine:

* every validation batch is an actual process run under the same B2 exclusive
  common-Git lease, supervisor, descendant drain and per-epoch receipt;
* structured unittest evidence comes from a pinned coordinator-owned stdlib
  adapter (never from prose or a JUnit summary);
* review is performed by the single active trusted Codex leader through a
  dedicated coordinator operation and a single-use session, never a native
  provider job;
* formal repair slots are consumed by a durable allocation event at allocation
  time, with at most three pre-claim setup attempts and no refund or reset;
* D2 ends at REVIEW_APPROVED. Done, MERGED, dependency opening, appender and
  manual-SHA custody remain closed until E.

D2 facts live in the existing execution journal under their own reducer
namespaces. They never carry a top-level writer ``attempt_id``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any

D2_VERSION = 1
VALIDATION_BATCH_VERSION = 1
REVIEW_VERSION = 1
REPAIR_VERSION = 1
POLICY_VERSION = 1
SESSION_VERSION = 1
DESIGN_LINK_VERSION = 1

MAX_EVENT_TEXT = 4_096
MAX_REVIEW_BYTES = 60_000
MAX_VALIDATION_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_STRUCTURED_REPORT_BYTES = 2 * 1024 * 1024
MAX_ENTRY_REASONS = 20
MAX_FINDINGS = 32
MAX_CRITERIA = 50
MAX_CAPTURE_TOTAL = 16 * 1024 * 1024
MAX_PROCESS_CMDLINE_BYTES = 65_536
VALIDATION_PROOF_FILES = (
    "meta.json",
    "result.json",
    "final-check.json",
    "lease-completion.json",
    "validation-evidence.json",
)
SETUP_ATTEMPT_LIMIT = 3
FORMAL_REPAIR_LIMIT = 3
DEFAULT_ADAPTER_ID = "coordinator-stdlib-unittest"
DEFAULT_REPORT_ENV = "D2_STRUCTURED_REPORT"
RUN_ID_ENV = "D2_STRUCTURED_RUN_ID"
# The sandbox root is a read-only bind of the host root, so no new directory
# can be created at the top level (mkdir /d2scratch fails with EROFS). The
# private scratch is therefore mounted inside the private /tmp tmpfs, which is
# writable and per-invocation. Host bind sources remain host paths; the tmpfs
# only owns the destination namespace.
SANDBOX_SCRATCH_PATH = "/tmp/d2scratch"
ZERO_DIGEST = "0" * 64
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
INVOCATION_ID_RE = re.compile(r"^V[0-9]{3}$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")

STAGE_AWAITING_VALIDATION = "AWAITING_VALIDATION"
STAGE_VALIDATING = "VALIDATING"
STAGE_VALIDATION_FAILED = "VALIDATION_FAILED"
STAGE_VALIDATION_BLOCKED = "VALIDATION_BLOCKED"
STAGE_AWAITING_REVIEW = "AWAITING_REVIEW"
STAGE_REPAIR_REQUIRED = "REPAIR_REQUIRED"
STAGE_REPAIR_PREPARED = "REPAIR_PREPARED"
STAGE_REPAIRING = "REPAIRING"
STAGE_REVIEW_APPROVED = "REVIEW_APPROVED"
STAGE_BLOCKED = "BLOCKED"

VERDICT_APPROVE = "APPROVE"
VERDICT_REQUEST_CHANGES = "REQUEST_CHANGES"

CALLER_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "TZ",
)
PRIVATE_ENV_KEYS = (
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_CACHE_HOME",
    "PYTHONPYCACHEPREFIX",
    "RUFF_CACHE_DIR",
    "MPLCONFIGDIR",
)
DENIED_ENV_PREFIXES = (
    "ANTHROPIC",
    "CLAUDE",
    "OPENAI",
    "DEEPSEEK",
    "GLM",
    "ZHIPU",
    "AWS",
    "AZURE",
    "GOOGLE",
    "GCP",
    "GH_",
    "GITHUB",
    "GITLAB",
    "SSH_",
    "DOCKER",
    "KUBECONFIG",
    "VAULT",
    "NPM_TOKEN",
    "CI_",
    "C_FAKE_",
)
DENIED_ENV_NAMES = {
    "BASH_ENV",
    "ENV",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "PYTHONWARNINGS",
    "PERL5OPT",
    "RUBYOPT",
    "NODE_OPTIONS",
    "CDPATH",
    "MAKEFLAGS",
    "MFLAGS",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
}
CLOSED_D2_ROUTES = {
    "done": "CLOSED_UNTIL_E",
    "pr": "CLOSED_UNTIL_E",
    "ci": "CLOSED_UNTIL_E",
    "merged": "CLOSED_UNTIL_E",
    "dependency_opening": "CLOSED_UNTIL_E",
    "legacy_review_done": "CLOSED",
    "manual_sha_custody": "CLOSED",
    "appender": "CLOSED",
}
SYSTEMS_PRIVILEGE_SUBSET = [
    "live_source_read_only",
    "private_writable_scratch",
    "host_pid_access",
    "shared_network",
    "current_coordinator_capabilities",
]
SUPPORTED_ADAPTER_INTERPRETER_FLAGS = frozenset({"-I", "-B", "-E", "-s", "-u"})

_HOOKS: dict[str, Any] = {}

# The ordinary_ro/system_trusted probe runs inside the *actual* mount layout
# used for the invocation. It distinguishes a real EROFS refusal from a missing
# path or a permission error, and records the concrete child context. Existence
# of a wrapper or a failed write alone is never accepted as read-only proof.
_SANDBOX_PROBE_SCRIPT = r'''
import errno
import json
import os
import sys

path = sys.argv[1]
result = {
    "euid": os.geteuid(),
    "pid": os.getpid(),
    "ppid": os.getppid(),
    "pid_namespace": None,
    "cap_eff": None,
}
try:
    result["pid_namespace"] = os.readlink("/proc/self/ns/pid")
except OSError:
    pass
try:
    with open("/proc/self/status", "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("CapEff:"):
                result["cap_eff"] = line.split()[1]
                break
except OSError:
    pass
try:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
except OSError as error:
    result["wrote"] = False
    result["write_errno"] = errno.errorcode.get(error.errno, str(error.errno))
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if error.errno == errno.EROFS else 20)
else:
    os.close(descriptor)
    try:
        os.unlink(path)
    except OSError:
        pass
    result["wrote"] = True
    result["write_errno"] = None
    print(json.dumps(result, sort_keys=True))
    sys.exit(17)
'''


def configure(**hooks: Any) -> None:
    _HOOKS.update(hooks)


def _hook(name: str) -> Any:
    try:
        return _HOOKS[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise RuntimeError(f"d_review is not configured: missing {name}") from exc


def _error(message: str) -> Exception:
    return _hook("runner_error")(message)


def _fail(message: str) -> None:
    raise _error(message)


def _d() -> Any:
    return _hook("d_module")()


def _b1() -> Any:
    return _hook("b1_module")()


def _b2() -> Any:
    return _hook("b2_module")()


def _now() -> str:
    return _hook("utc_now")()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(DIGEST_RE.fullmatch(value))


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def _require_digest(value: Any, label: str) -> str:
    if not _is_digest(value):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_id(value: Any, label: str) -> str:
    if not _is_id(value):
        _fail(f"{label} must be a bounded identifier")
    return value


def _require_text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    text = value.strip()
    if len(text) < minimum:
        _fail(f"{label} is too short")
    if len(text.encode("utf-8")) > MAX_EVENT_TEXT:
        _fail(f"{label} exceeds {MAX_EVENT_TEXT} bytes")
    return text


def _require_text_list(
    value: Any,
    label: str,
    *,
    minimum_items: int = 0,
    maximum_items: int = 64,
    minimum_chars: int = 1,
) -> list[str]:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array")
    if not minimum_items <= len(value) <= maximum_items:
        _fail(f"{label} has an invalid number of entries")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(
            _require_text(item, f"{label}[{index}]", minimum=minimum_chars)
        )
    if len(set(result)) != len(result):
        _fail(f"{label} must not repeat an entry")
    return result


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        _fail(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        _fail(f"{label} has unknown fields: {', '.join(extra)}")
    return value


def _plans_dir() -> Path:
    return Path(_hook("plans_dir")())


def _plan_dir(plan_id: str) -> Path:
    return Path(_hook("plan_dir")(plan_id, must_exist=True))


def _jobs_dir() -> Path:
    return Path(_hook("jobs_dir")())


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Cannot read JSON evidence {path}: {exc}")
    if not isinstance(value, dict):
        _fail(f"JSON evidence {path} is not an object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _hook("write_json")(Path(path), value)


def _session_dir(plan_id: str) -> Path:
    path = _plan_dir(plan_id) / "execution" / "review-sessions"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _append(
    plan_id_value: str,
    specs: list[dict[str, Any]],
    command: str,
    **fields: Any,
) -> list[dict[str, Any]]:
    d = _d()
    plan_id = plan_id_value
    request = d._request_digest(command, **fields)
    operation = d._next_operation("d2-" + command.replace("_", "-"), request)
    return d._append_journal(plan_id, specs, operation, request)


def _event_spec(event_type: str, step_id: str, cycle: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": event_type, "step_id": step_id, "cycle": cycle, "payload": payload}


# ---------------------------------------------------------------------------
# D2 event schemas (called by d_execution under the plan lock)
# ---------------------------------------------------------------------------


def _cmdline_digest(pid: int) -> str | None:
    """Digest the actual NUL-separated process command line, never its text.

    Only the bounded digest is persisted; raw argv, environment or tokens are
    never copied into a journal, blob or rendered view.
    """
    try:
        with open(f"/proc/{int(pid)}/cmdline", "rb") as handle:
            data = handle.read(MAX_PROCESS_CMDLINE_BYTES + 1)
    except (OSError, TypeError, ValueError):
        return None
    if not data or len(data) > MAX_PROCESS_CMDLINE_BYTES:
        return None
    return _sha256_bytes(data)


def _process_identity() -> dict[str, Any]:
    pid = os.getpid()
    digest = _cmdline_digest(pid)
    if digest is None:
        _fail("Cannot record the actual process command-line digest")
    start = _b2().process_start_identity(pid)
    if not isinstance(start, str) or not start:
        _fail("Cannot record a deterministic process start identity")
    return {"pid": pid, "start": start, "cmdline_digest": digest}


def _require_process_cmdline(record: dict[str, Any], label: str) -> None:
    """Audit a live issuer's actual command line against its recorded digest."""
    current = _cmdline_digest(record["pid"])
    if current is None:
        # A drained issuer is no longer observable; the immutable recorded
        # digest remains provenance and no live match can be claimed.
        return
    if current != record["cmdline_digest"]:
        _fail(f"{label} actual command line does not match its recorded digest")


def _validate_process(value: Any, label: str) -> dict[str, Any]:
    item = _exact_keys(value, {"pid", "start", "cmdline_digest"}, label)
    if (
        not isinstance(item.get("pid"), int)
        or isinstance(item.get("pid"), bool)
        or item["pid"] <= 0
    ):
        _fail(f"{label}.pid is invalid")
    if not isinstance(item.get("start"), str) or not item["start"]:
        _fail(f"{label}.start is invalid")
    _require_digest(item.get("cmdline_digest"), f"{label}.cmdline_digest")
    return item


def _validate_lease(value: Any, label: str) -> dict[str, Any]:
    item = _exact_keys(
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
    if not isinstance(item.get("epoch"), str) or not re.fullmatch(
        r"^[0-9a-f]{32}$", item["epoch"]
    ):
        _fail(f"{label}.epoch is invalid")
    for key in ("owner_path", "lock_path", "job_dir", "receipt_path"):
        if not isinstance(item.get(key), str) or not item[key]:
            _fail(f"{label}.{key} is invalid")
    for key in ("lock_dev", "lock_ino"):
        if (
            not isinstance(item.get(key), int)
            or isinstance(item.get(key), bool)
            or item[key] <= 0
        ):
            _fail(f"{label}.{key} is invalid")
    return item


def _validate_counts(value: Any, label: str) -> dict[str, int]:
    item = _exact_keys(
        value,
        {"collected", "run", "passed", "failures", "errors", "skips"},
        label,
    )
    for key, count in item.items():
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            _fail(f"{label}.{key} must be a non-negative integer")
    return item


def _validate_entry_summary(value: Any, label: str) -> dict[str, Any]:
    item = _exact_keys(
        value,
        {
            "invocation_id",
            "evidence_kind",
            "exit_code",
            "timed_out",
            "cancelled",
            "overflow",
            "passed",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_bytes",
            "stderr_bytes",
            "counts",
            "context",
            "ro_enforcement",
            "reasons",
        },
        label,
    )
    if not isinstance(item.get("invocation_id"), str) or not INVOCATION_ID_RE.fullmatch(
        item["invocation_id"]
    ):
        _fail(f"{label}.invocation_id is invalid")
    if item.get("evidence_kind") not in {"command_check", "structured_unittest"}:
        _fail(f"{label}.evidence_kind is invalid")
    if item.get("exit_code") is not None and (
        not isinstance(item.get("exit_code"), int)
        or isinstance(item.get("exit_code"), bool)
    ):
        _fail(f"{label}.exit_code is invalid")
    for key in ("timed_out", "cancelled", "overflow", "passed"):
        if not isinstance(item.get(key), bool):
            _fail(f"{label}.{key} must be a boolean")
    for key in ("stdout_sha256", "stderr_sha256"):
        _require_digest(item.get(key), f"{label}.{key}")
    for key in ("stdout_bytes", "stderr_bytes"):
        size = item.get(key)
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            _fail(f"{label}.{key} is invalid")
    if item.get("counts") is not None:
        _validate_counts(item.get("counts"), f"{label}.counts")
        if item.get("evidence_kind") == "command_check":
            _fail(f"{label}.command_check cannot claim structured test counts")
    if item.get("context") not in {"ordinary_ro", "systems_trusted"}:
        _fail(f"{label}.context is invalid")
    if item.get("ro_enforcement") != "required":
        _fail(
            f"{label}.ro_enforcement must be required; observed or unconfined "
            "execution is not an eligible D2 context"
        )
    if not isinstance(item.get("reasons"), list) or len(item["reasons"]) > MAX_ENTRY_REASONS:
        _fail(f"{label}.reasons is invalid")
    return item


def _validate_validation_intent(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "validation_id",
            "batch_id",
            "job_id",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "policy_digest",
            "plan_sha256",
            "manifest_digest",
            "source_attempt_id",
            "source_job_id",
            "source_evidence_digest",
            "source_final_snapshot_digest",
            "source_kind",
            "generation",
            "issuer",
            "base_snapshot_digest",
            "base_snapshot_blob_sha256",
            "original_base_snapshot_digest",
            "original_base_blob_sha256",
            "user_baseline_digest",
            "task_source_sha256",
        },
        "validation_intent",
    )
    if item.get("version") != VALIDATION_BATCH_VERSION:
        _fail("validation_intent version is not supported")
    for key in ("validation_id", "batch_id", "job_id"):
        _require_id(item.get(key), f"validation_intent.{key}")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "policy_digest",
        "plan_sha256",
        "manifest_digest",
        "source_attempt_id",
        "source_evidence_digest",
        "source_final_snapshot_digest",
        "base_snapshot_digest",
        "base_snapshot_blob_sha256",
        "original_base_snapshot_digest",
        "original_base_blob_sha256",
        "user_baseline_digest",
        "task_source_sha256",
    ):
        _require_digest(item.get(key), f"validation_intent.{key}")
    _require_id(item.get("source_job_id"), "validation_intent.source_job_id")
    if item.get("source_kind") not in {"complete", "drained_failure"}:
        _fail("validation_intent.source_kind is invalid")
    generation = item.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 0 <= generation <= FORMAL_REPAIR_LIMIT
    ):
        _fail("validation_intent.generation is invalid")
    _validate_process(item.get("issuer"), "validation_intent.issuer")


def _validate_validation_claim(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "validation_id",
            "batch_id",
            "job_id",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "policy_digest",
            "lease",
            "base_snapshot_digest",
            "head",
            "branch",
            "index_sha256",
            "claim_digest",
        },
        "validation_claim",
    )
    if item.get("version") != VALIDATION_BATCH_VERSION:
        _fail("validation_claim version is not supported")
    for key in ("validation_id", "batch_id", "job_id"):
        _require_id(item.get(key), f"validation_claim.{key}")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "policy_digest",
        "base_snapshot_digest",
        "claim_digest",
    ):
        _require_digest(item.get(key), f"validation_claim.{key}")
    if item.get("index_sha256") is not None:
        _require_digest(item.get("index_sha256"), "validation_claim.index_sha256")
    for key in ("head", "branch"):
        if not isinstance(item.get(key), str) or not item[key]:
            _fail(f"validation_claim.{key} is invalid")
    _validate_lease(item.get("lease"), "validation_claim.lease")


def _validate_validation_result(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "validation_id",
            "batch_id",
            "job_id",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "policy_digest",
            "classification",
            "state",
            "entries",
            "counts",
            "reasons",
            "evidence_digest",
            "evidence_blob_sha256",
            "job_meta_sha256",
            "job_result_sha256",
            "final_check_sha256",
            "receipt_sha256",
            "source_attempt_id",
            "source_evidence_digest",
            "source_final_snapshot_digest",
            "generation",
        },
        "validation_result",
    )
    if item.get("version") != VALIDATION_BATCH_VERSION:
        _fail("validation_result version is not supported")
    for key in ("validation_id", "batch_id", "job_id"):
        _require_id(item.get(key), f"validation_result.{key}")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "policy_digest",
        "evidence_digest",
        "evidence_blob_sha256",
        "source_attempt_id",
        "source_evidence_digest",
        "source_final_snapshot_digest",
    ):
        _require_digest(item.get(key), f"validation_result.{key}")
    for key in (
        "job_meta_sha256",
        "job_result_sha256",
        "final_check_sha256",
        "receipt_sha256",
    ):
        if item.get(key) is not None:
            _require_digest(item.get(key), f"validation_result.{key}")
    if item.get("classification") not in {
        "passed",
        "failed",
        "cancelled",
        "blocked",
        "overflow",
        "uncertain",
    }:
        _fail("validation_result.classification is invalid")
    if item.get("state") not in {"clean", "violations", "error", "missing"}:
        _fail("validation_result.state is invalid")
    if not isinstance(item.get("entries"), list) or len(item["entries"]) > 32:
        _fail("validation_result.entries is invalid")
    for index, entry in enumerate(item["entries"]):
        _validate_entry_summary(entry, f"validation_result.entries[{index}]")
    _validate_counts(item.get("counts"), "validation_result.counts")
    if not isinstance(item.get("reasons"), list) or len(item["reasons"]) > 50:
        _fail("validation_result.reasons is invalid")
    generation = item.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 0 <= generation <= FORMAL_REPAIR_LIMIT
    ):
        _fail("validation_result.generation is invalid")


def _validate_preflight(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "invocation_id",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "policy_digest",
            "argv_sha256",
            "cwd",
            "purpose_sha256",
            "source_attempt_id",
            "source_final_snapshot_digest",
            "user_baseline_digest",
            "privilege_subset",
            "leader",
            "issuer",
            "contract_sequence",
        },
        "validation_preflight",
    )
    if item.get("version") != VALIDATION_BATCH_VERSION:
        _fail("validation_preflight version is not supported")
    if not isinstance(item.get("invocation_id"), str) or not INVOCATION_ID_RE.fullmatch(
        item["invocation_id"]
    ):
        _fail("validation_preflight.invocation_id is invalid")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "policy_digest",
        "argv_sha256",
        "purpose_sha256",
        "source_final_snapshot_digest",
        "user_baseline_digest",
    ):
        _require_digest(item.get(key), f"validation_preflight.{key}")
    _require_digest(item.get("source_attempt_id"), "validation_preflight.source_attempt_id")
    if not isinstance(item.get("cwd"), str) or not item["cwd"]:
        _fail("validation_preflight.cwd is invalid")
    if not isinstance(item.get("leader"), str) or not item["leader"].strip():
        _fail("validation_preflight.leader must be the active trusted leader")
    _validate_process(item.get("issuer"), "validation_preflight.issuer")
    subset = item.get("privilege_subset")
    if not isinstance(subset, list) or not all(
        isinstance(entry, str) and entry for entry in subset
    ):
        _fail("validation_preflight.privilege_subset is invalid")
    sequence = item.get("contract_sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        _fail("validation_preflight.contract_sequence is invalid")


def _validate_session(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "review_id",
            "purpose",
            "leader",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "policy_digest",
            "source_attempt_id",
            "source_kind",
            "source_evidence_digest",
            "source_final_snapshot_digest",
            "generation",
            "validation_id",
            "validation_digest",
            "input_bundle_digest",
            "input_bundle_blob_sha256",
            "token_sha256",
            "issuer",
        },
        "review_session",
    )
    if item.get("version") != SESSION_VERSION:
        _fail("review_session version is not supported")
    _require_id(item.get("review_id"), "review_session.review_id")
    _require_id(item.get("validation_id"), "review_session.validation_id")
    _require_text(item.get("purpose"), "review_session.purpose", minimum=3)
    if not isinstance(item.get("leader"), str) or not item["leader"].strip():
        _fail("review_session.leader must be the active trusted leader")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "policy_digest",
        "source_attempt_id",
        "source_evidence_digest",
        "source_final_snapshot_digest",
        "validation_digest",
        "input_bundle_digest",
        "input_bundle_blob_sha256",
        "token_sha256",
    ):
        _require_digest(item.get(key), f"review_session.{key}")
    if item.get("source_kind") not in {"complete", "drained_failure"}:
        _fail("review_session.source_kind is invalid")
    generation = item.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 0 <= generation <= FORMAL_REPAIR_LIMIT
    ):
        _fail("review_session.generation is invalid")
    _validate_process(item.get("issuer"), "review_session.issuer")


def _validate_review(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "review_id",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "policy_digest",
            "source_attempt_id",
            "source_job_id",
            "source_kind",
            "source_evidence_digest",
            "generation",
            "validation_id",
            "validation_digest",
            "input_bundle_digest",
            "review_digest",
            "review_blob_sha256",
            "verdict",
            "finding_counts",
            "criteria_counts",
            "leader",
            "recorder",
        },
        "independent_review",
    )
    if item.get("version") != REVIEW_VERSION:
        _fail("independent_review version is not supported")
    for key in ("review_id", "source_job_id"):
        _require_id(item.get(key), f"independent_review.{key}")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "policy_digest",
        "source_attempt_id",
        "source_evidence_digest",
        "validation_digest",
        "input_bundle_digest",
        "review_digest",
        "review_blob_sha256",
    ):
        _require_digest(item.get(key), f"independent_review.{key}")
    if item.get("source_kind") not in {"complete", "drained_failure"}:
        _fail("independent_review.source_kind is invalid")
    if item.get("verdict") not in {VERDICT_APPROVE, VERDICT_REQUEST_CHANGES}:
        _fail("independent_review.verdict is invalid")
    generation = item.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 0 <= generation <= FORMAL_REPAIR_LIMIT
    ):
        _fail("independent_review.generation is invalid")
    if not isinstance(item.get("leader"), str) or not item["leader"].strip():
        _fail("independent_review.leader must be the active trusted leader")
    _validate_process(item.get("recorder"), "independent_review.recorder")
    for key in ("finding_counts", "criteria_counts"):
        value = item.get(key)
        if not isinstance(value, dict):
            _fail(f"independent_review.{key} is invalid")
    for key in ("defects", "suggestions", "open_required_changes"):
        count = item["finding_counts"].get(key)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            _fail(f"independent_review.finding_counts.{key} is invalid")
    for key in ("total", "satisfied", "unsatisfied"):
        count = item["criteria_counts"].get(key)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            _fail(f"independent_review.criteria_counts.{key} is invalid")


def _validate_repair_contract(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "repair_contract_id",
            "review_id",
            "review_digest",
            "generation",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "repair_contract_digest",
            "repair_contract_blob_sha256",
            "finding_ids",
            "source_attempt_id",
            "source_evidence_digest",
        },
        "repair_contract",
    )
    if item.get("version") != REPAIR_VERSION:
        _fail("repair_contract version is not supported")
    _require_id(item.get("repair_contract_id"), "repair_contract.repair_contract_id")
    _require_id(item.get("review_id"), "repair_contract.review_id")
    for key in (
        "review_digest",
        "candidate_sha256",
        "contract_digest",
        "repair_contract_digest",
        "repair_contract_blob_sha256",
        "source_attempt_id",
        "source_evidence_digest",
    ):
        _require_digest(item.get(key), f"repair_contract.{key}")
    generation = item.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 1 <= generation <= FORMAL_REPAIR_LIMIT
    ):
        _fail("repair_contract.generation is invalid")
    ids = item.get("finding_ids")
    if not isinstance(ids, list) or len(ids) > MAX_FINDINGS or not all(
        isinstance(value, str) and value for value in ids
    ):
        _fail("repair_contract.finding_ids is invalid")


def _validate_allocation(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "allocation_id",
            "generation",
            "cycle",
            "candidate_sha256",
            "contract_digest",
            "review_id",
            "review_digest",
            "repair_contract_digest",
            "repair_contract_blob_sha256",
            "source_attempt_id",
            "source_job_id",
            "source_evidence_digest",
            "source_final_snapshot_digest",
            "idempotency_key",
        },
        "repair_allocation",
    )
    if item.get("version") != REPAIR_VERSION:
        _fail("repair_allocation version is not supported")
    _require_id(item.get("allocation_id"), "repair_allocation.allocation_id")
    _require_id(item.get("review_id"), "repair_allocation.review_id")
    _require_id(item.get("source_job_id"), "repair_allocation.source_job_id")
    for key in (
        "candidate_sha256",
        "contract_digest",
        "review_digest",
        "repair_contract_digest",
        "repair_contract_blob_sha256",
        "source_attempt_id",
        "source_evidence_digest",
        "source_final_snapshot_digest",
        "idempotency_key",
    ):
        _require_digest(item.get(key), f"repair_allocation.{key}")
    generation = item.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 1 <= generation <= FORMAL_REPAIR_LIMIT
    ):
        _fail("repair_allocation.generation is invalid")


def _validate_setup(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "allocation_id",
            "ordinal",
            "outcome",
            "issuer",
            "detail",
        },
        "repair_setup_attempt",
    )
    if item.get("version") != REPAIR_VERSION:
        _fail("repair_setup_attempt version is not supported")
    _require_id(item.get("allocation_id"), "repair_setup_attempt.allocation_id")
    ordinal = item.get("ordinal")
    if (
        not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or not 1 <= ordinal <= SETUP_ATTEMPT_LIMIT
    ):
        _fail("repair_setup_attempt.ordinal is invalid")
    if item.get("outcome") not in {
        "attempted",
        "failed_pre_claim",
        "claimed",
    }:
        _fail("repair_setup_attempt.outcome is invalid")
    _validate_process(item.get("issuer"), "repair_setup_attempt.issuer")
    if not isinstance(item.get("detail"), str) or len(item["detail"]) > 2_000:
        _fail("repair_setup_attempt.detail is invalid")


def _validate_design_link(payload: dict[str, Any]) -> None:
    item = _exact_keys(
        payload,
        {
            "version",
            "previous_candidate_sha256",
            "new_candidate_sha256",
            "previous_contract_digest",
            "new_contract_digest",
            "previous_cycle",
            "new_cycle",
            "source_attempt_id",
            "source_evidence_digest",
            "source_final_snapshot_digest",
            "original_base_snapshot_digest",
            "user_baseline_digest",
            "finding_dispositions",
            "evidence_digest",
        },
        "design_link",
    )
    if item.get("version") != DESIGN_LINK_VERSION:
        _fail("design_link version is not supported")
    for key in (
        "previous_candidate_sha256",
        "new_candidate_sha256",
        "previous_contract_digest",
        "new_contract_digest",
        "source_attempt_id",
        "source_evidence_digest",
        "source_final_snapshot_digest",
        "original_base_snapshot_digest",
        "user_baseline_digest",
        "evidence_digest",
    ):
        _require_digest(item.get(key), f"design_link.{key}")
    for key in ("previous_cycle", "new_cycle"):
        value = item.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            _fail(f"design_link.{key} is invalid")
    dispositions = item.get("finding_dispositions")
    if not isinstance(dispositions, list) or len(dispositions) > MAX_FINDINGS:
        _fail("design_link.finding_dispositions is invalid")
    for index, value in enumerate(dispositions):
        entry = _exact_keys(
            value,
            {"finding_id", "disposition", "evidence"},
            f"design_link.finding_dispositions[{index}]",
        )
        if not isinstance(entry.get("finding_id"), str):
            _fail("design_link finding_id is invalid")
        if entry.get("disposition") not in {"resolved", "carried", "obsolete"}:
            _fail("design_link disposition is invalid")
        _require_text(entry.get("evidence"), "design_link evidence", minimum=3)


D2_EVENT_VALIDATORS = {
    "validation_intent": _validate_validation_intent,
    "validation_claim": _validate_validation_claim,
    "validation_result": _validate_validation_result,
    "validation_preflight": _validate_preflight,
    "review_session": _validate_session,
    "independent_review": _validate_review,
    "repair_contract": _validate_repair_contract,
    "repair_allocation": _validate_allocation,
    "repair_setup_attempt": _validate_setup,
    "design_link": _validate_design_link,
}


def validate_event_payload(event_type: str, payload: Any) -> None:
    """Fail-closed D2 schema hook used by the shared journal validator."""
    validator = D2_EVENT_VALIDATORS.get(event_type)
    if validator is None:
        _fail(f"D2 journal event type {event_type!r} has no registered schema")
    if not isinstance(payload, dict):
        _fail(f"{event_type} payload must be a JSON object")
    validator(payload)
    if "attempt_id" in payload:
        _fail(
            f"{event_type} must not carry a top-level writer attempt_id; D2 "
            "facts use their own namespace"
        )
    version = payload.get("version")
    if version != (REPAIR_VERSION if event_type in {
        "repair_contract", "repair_allocation", "repair_setup_attempt"
    } else DESIGN_LINK_VERSION if event_type == "design_link" else VALIDATION_BATCH_VERSION):
        _fail(f"{event_type} event version is unsupported")


# ---------------------------------------------------------------------------
# Plan/journal helpers
# ---------------------------------------------------------------------------


def _contract_for_current(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    cycle: int,
    candidate_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    d = _d()
    event = d._contract_event_for(journal, step_id, cycle, candidate_sha256)
    if event is None:
        _fail("No D2 execution contract is frozen for the current candidate")
    contract = d._load_contract(plan_id, journal, event)
    if contract.get("version") != d.CONTRACT_VERSION_D2:
        _fail(
            "D2 operations require an explicitly frozen version 2 contract; "
            "version 1 contracts never acquire validation/review authority"
        )
    return contract, event


def _policy_from_contract(contract: dict[str, Any]) -> dict[str, Any]:
    policy = contract.get("validation_policy")
    if not isinstance(policy, dict):
        _fail("The frozen D2 contract has no validation policy")
    entries = policy.get("entries")
    if not isinstance(entries, list) or not entries:
        _fail("The frozen validation policy has no entries")
    return policy


def _policy_digest(policy: dict[str, Any]) -> str:
    return _digest(policy)


def _latest_writer_intents_locked(
    journal: dict[str, Any],
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract_digest: str,
) -> list[dict[str, Any]]:
    return [
        event
        for event in journal["intents"]
        if event["step_id"] == step_id
        and event["cycle"] == cycle
        and event["payload"].get("candidate_sha256") == candidate_sha256
        and event["payload"].get("contract_digest") == contract_digest
    ]


def _unsettled_writer_reason(
    journal: dict[str, Any],
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract_digest: str,
    *,
    exclude_allocation: str | None = None,
) -> str | None:
    d = _d()
    intents = _latest_writer_intents_locked(
        journal, step_id, cycle, candidate_sha256, contract_digest
    )
    for intent in intents:
        if (
            exclude_allocation is not None
            and intent["payload"].get("repair_allocation_id")
            == exclude_allocation
        ):
            continue
        state = d._attempt_state(journal, intent["payload"]["attempt_id"])["state"]
        if state in {"pending", "claimed"}:
            return (
                f"managed writer attempt {intent['payload']['attempt_id']} is "
                f"{state}; D2 requires a fully drained source"
            )
        if state in {"uncertain", "blocked"}:
            return (
                f"managed writer attempt {intent['payload']['attempt_id']} is "
                f"{state}; its ownership cannot be proven"
            )
    return None


def _latest_writer_source_locked(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract_digest: str,
) -> dict[str, Any]:
    """Return the latest settled source and its immutable author/result proof.

    Pending or provably aborted intents are not sources: they never produced
    owned bytes. A pending/claimed/uncertain attempt is rejected separately by
    ``_unsettled_writer_reason`` before validation or review can start.
    """
    d = _d()
    intents = _latest_writer_intents_locked(
        journal, step_id, cycle, candidate_sha256, contract_digest
    )
    if not intents:
        _fail("No managed writer invocation exists for this candidate")
    for intent in reversed(intents):
        state = d._attempt_state(journal, intent["payload"]["attempt_id"])["state"]
        if state in {"pending", "aborted", "pre_invocation_abort"}:
            continue
        return _writer_source_from_intent(plan_id, journal, intent)
    _fail("No settled managed writer source exists for this candidate")


def _writer_source_from_intent(
    plan_id: str,
    journal: dict[str, Any],
    latest_intent: dict[str, Any],
) -> dict[str, Any]:
    d = _d()
    intent_payload = latest_intent["payload"]
    attempt_id = intent_payload["attempt_id"]
    job_id = intent_payload["job_id"]
    state = d._attempt_state(journal, attempt_id)
    if state["state"] in {"pending", "claimed"}:
        _fail(
            f"The managed writer attempt is {state['state']}; validation/review "
            "requires a fully drained source"
        )
    if state["state"] in {"uncertain", "blocked"}:
        _fail(
            f"The managed writer attempt is {state['state']}; its ownership "
            "cannot be proven"
        )
    completion = d._latest(
        journal["events"], d.TYPE_COMPLETE, attempt_id=attempt_id
    )
    result_event = d._latest(
        journal["events"], d.TYPE_RESULT, attempt_id=attempt_id
    )
    result = result_event
    if completion is not None:
        source_kind = "complete"
        if result is None or result["payload"].get("classification") != "drained_success":
            _fail("Completion evidence disagrees with the recorded writer result")
        evidence = d._load_evidence_blob(
            plan_id,
            result["payload"]["evidence_blob_sha256"],
            result["payload"]["evidence_digest"],
            "D2 source evidence",
        )
        delta = evidence.get("delta")
        if not isinstance(delta, dict):
            _fail("Completion evidence has no cumulative owned delta")
        report = completion["payload"].get("report")
        if not isinstance(report, dict) or not report:
            _fail("Completion evidence has no valid author report")
        return {
            "source_kind": source_kind,
            "attempt_id": attempt_id,
            "job_id": job_id,
            "intent": intent_payload,
            "generation": (
                int(intent_payload.get("repair_generation") or 0)
                if intent_payload.get("repair_allocation_id")
                else 0
            ),
            "evidence_digest": result["payload"]["evidence_digest"],
            "evidence_blob_sha256": result["payload"]["evidence_blob_sha256"],
            "final_snapshot_digest": completion["payload"][
                "final_snapshot_digest"
            ],
            "cumulative_changed_paths": list(
                completion["payload"]["cumulative_changed_paths"]
            ),
            "cumulative_changed_digest": completion["payload"][
                "cumulative_changed_digest"
            ],
            "original_base_snapshot_digest": completion["payload"][
                "original_base_snapshot_digest"
            ],
            "user_baseline_digest": intent_payload["user_baseline_digest"],
            "author_report": report,
            "result_event": result,
            "completion_event": completion,
            "delta": delta,
        }
    if result is not None and result["payload"].get("classification") == "drained_failure":
        residue = result["payload"].get("residue")
        if not isinstance(residue, dict) or not _is_digest(
            residue.get("final_snapshot_digest")
        ):
            _fail("A drained failure has no attributable partial source residue")
        return {
            "source_kind": "drained_failure",
            "attempt_id": attempt_id,
            "job_id": job_id,
            "intent": intent_payload,
            "generation": (
                int(intent_payload.get("repair_generation") or 0)
                if intent_payload.get("repair_allocation_id")
                else 0
            ),
            "evidence_digest": result["payload"]["evidence_digest"],
            "evidence_blob_sha256": result["payload"]["evidence_blob_sha256"],
            "final_snapshot_digest": residue["final_snapshot_digest"],
            "cumulative_changed_paths": list(residue.get("cumulative_changed_paths") or []),
            "cumulative_changed_digest": residue.get("cumulative_changed_digest"),
            "original_base_snapshot_digest": intent_payload[
                "original_base_snapshot_digest"
            ],
            "user_baseline_digest": intent_payload["user_baseline_digest"],
            "author_report": {},
            "result_event": result,
            "completion_event": None,
            "delta": None,
        }
    _fail(
        "The latest managed writer attempt is not a complete implementation or "
        "an attributable drained failure"
    )
    raise AssertionError("unreachable")


def _require_source_current(
    plan_id: str,
    source: dict[str, Any],
    snapshot: dict[str, Any],
    label: str,
) -> None:
    d = _d()
    if d._snapshot_digest(snapshot) != source["final_snapshot_digest"]:
        _fail(
            f"{label} source no longer matches the exact attributed writer "
            "source; unknown or user-edited residue blocks D2"
        )
    original_base = json.loads(
        d._read_blob(
            plan_id,
            source["intent"]["original_base_blob_sha256"],
            f"{label} original base",
        ).decode("utf-8")
    )
    if (
        d._snapshot_digest(original_base)
        != source["intent"]["original_base_snapshot_digest"]
    ):
        _fail(f"{label} original base evidence is inconsistent")
    if (
        d._user_baseline_digest(original_base)
        != source["intent"]["user_baseline_digest"]
    ):
        _fail(f"{label} original user baseline evidence is inconsistent")
    try:
        d._require_unchanged_user_baseline(original_base, snapshot, label)
    except Exception as exc:
        _fail(f"{label} original user baseline changed: {exc}")


def _require_no_live_writer(identity: dict[str, Any]) -> None:
    d = _d()
    live = d._live_reservations(identity)
    if live:
        _fail(
            "A repository job is still active or draining: "
            + ", ".join(sorted(str(record.get("job_id")) for record in live))
        )


def _latest_validation(
    journal: dict[str, Any],
    step_id: str,
    candidate_sha256: str | None = None,
    contract_digest: str | None = None,
) -> dict[str, Any] | None:
    for event in reversed(journal["validation_results"]):
        if event["step_id"] != step_id:
            continue
        payload = event["payload"]
        if candidate_sha256 is not None and payload.get("candidate_sha256") != candidate_sha256:
            continue
        if contract_digest is not None and payload.get("contract_digest") != contract_digest:
            continue
        return event
    return None


def _latest_review(
    journal: dict[str, Any],
    step_id: str,
    candidate_sha256: str | None = None,
    contract_digest: str | None = None,
) -> dict[str, Any] | None:
    for event in reversed(journal["reviews"]):
        if event["step_id"] != step_id:
            continue
        payload = event["payload"]
        if candidate_sha256 is not None and payload.get("candidate_sha256") != candidate_sha256:
            continue
        if contract_digest is not None and payload.get("contract_digest") != contract_digest:
            continue
        return event
    return None


def _latest_allocation(journal: dict[str, Any], step_id: str) -> dict[str, Any] | None:
    for event in reversed(journal["repair_allocations"]):
        if event["step_id"] == step_id:
            return event
    return None


def _allocations_for_step(
    journal: dict[str, Any], step_id: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in journal["repair_allocations"]
        if event["step_id"] == step_id
    ]


def _review_by_id(
    plan_id: str, journal: dict[str, Any], step_id: str, review_id: str
) -> dict[str, Any]:
    matches = [
        event
        for event in journal["reviews"]
        if event["step_id"] == step_id
        and event["payload"]["review_id"] == review_id
    ]
    if len(matches) != 1:
        _fail(f"Unknown or ambiguous D2 review {review_id!r}")
    return matches[0]


def _load_review_document(
    plan_id: str, journal: dict[str, Any], event: dict[str, Any]
) -> dict[str, Any]:
    d = _d()
    payload = event["payload"]
    data = d._read_blob(plan_id, payload["review_blob_sha256"], "D2 review document")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"D2 review blob is not valid JSON: {exc}")
    if not isinstance(document, dict) or _digest(document) != payload["review_digest"]:
        _fail("D2 review bytes do not match their recorded digest")
    return document


def _repair_contract_by_id(
    plan_id: str, journal: dict[str, Any], step_id: str, contract_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    d = _d()
    matches = [
        event
        for event in journal["repair_contracts"]
        if event["step_id"] == step_id
        and event["payload"]["repair_contract_id"] == contract_id
    ]
    if len(matches) != 1:
        _fail(f"Unknown or ambiguous repair contract {contract_id!r}")
    event = matches[0]
    data = d._read_blob(
        plan_id,
        event["payload"]["repair_contract_blob_sha256"],
        "repair contract",
    )
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Repair contract blob is not valid JSON: {exc}")
    if (
        not isinstance(document, dict)
        or _digest(document) != event["payload"]["repair_contract_digest"]
    ):
        _fail("Repair contract bytes do not match their recorded digest")
    return event, document


def _fresh_intent_preflight_locked(
    plan_id: str,
    journal: dict[str, Any],
    contract: dict[str, Any],
    contract_event: dict[str, Any],
    policy: dict[str, Any],
    source: dict[str, Any],
    snapshot: dict[str, Any],
) -> None:
    """Require a current active-Codex preflight for every systems invocation."""
    policy_sha = _policy_digest(policy)
    snapshot_sha = _d()._snapshot_digest(snapshot)
    for entry in policy["entries"]:
        if entry["context"] != "systems_trusted":
            continue
        argv_sha = _digest(list(entry["argv"]))
        match = None
        for event in reversed(journal["validation_preflights"]):
            payload = event["payload"]
            if (
                payload.get("invocation_id") == entry["invocation_id"]
                and payload.get("policy_digest") == policy_sha
                and payload.get("argv_sha256") == argv_sha
                and payload.get("cwd") == entry["cwd"]
                and payload.get("purpose_sha256")
                == _sha256_bytes(entry["purpose"].encode("utf-8"))
                and payload.get("contract_digest")
                == contract_event["payload"]["contract_digest"]
                and payload.get("source_attempt_id") == source["attempt_id"]
                and payload.get("source_final_snapshot_digest") == snapshot_sha
                and payload.get("user_baseline_digest")
                == source["user_baseline_digest"]
                and payload.get("privilege_subset")
                == list(SYSTEMS_PRIVILEGE_SUBSET)
                and event["sequence"] > contract_event["sequence"]
            ):
                match = event
                break
        if match is None:
            _fail(
                "Systems-trusted invocation "
                f"{entry['invocation_id']} has no current active-Codex preflight "
                "bound to the exact source, contract, argv, cwd and privilege "
                "subset; no automatic fallback is available"
            )


def prepare_validation(*, plan_id: str, step_id: str) -> dict[str, Any]:
    """Publish a deterministic validation intent and return a launch descriptor.

    The intent binds the exact current writer source, contract version 2 and
    voted policy. The B2 lease is acquired only by the existing nonblocking
    launch admission after this function releases the plan lock.
    """
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(
            b1_state, step_id
        )
        if constraints.get("version") != d.CONTRACT_VERSION_D2:
            _fail(
                "Independent validation requires an approved version 2 candidate "
                "with an explicit validation_policy"
            )
        journal = d._replay_journal(plan_id)
        contract, contract_event = _contract_for_current(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
        )
        policy = _policy_from_contract(contract)
        policy_sha = _policy_digest(policy)
        identity = d._repo_identity(static)
        _require_no_live_writer(identity)
        unsettled = _unsettled_writer_reason(
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if unsettled:
            _fail(unsettled)
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        workspace = Path(static["canonical_workspace"])
        snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
        _require_source_current(plan_id, source, snapshot, "validation intent")
        _fresh_intent_preflight_locked(
            plan_id,
            journal,
            contract,
            contract_event,
            policy,
            source,
            snapshot,
        )
        pending = [
            event
            for event in journal["validation_intents"]
            if event["step_id"] == step_id
            and event["payload"].get("candidate_sha256") == candidate_sha256
            and event["payload"].get("contract_digest")
            == contract_event["payload"]["contract_digest"]
        ]
        latest_result = _latest_validation(
            journal, step_id, candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if pending:
            latest_intent = pending[-1]
            payload = latest_intent["payload"]
            result_exists = any(
                event["payload"].get("validation_id")
                == payload["validation_id"]
                for event in journal["validation_results"]
            )
            claim_exists = any(
                event["payload"].get("validation_id")
                == payload["validation_id"]
                for event in journal["validation_claims"]
            )
            if not result_exists and not claim_exists:
                job_dir = _jobs_dir() / payload["job_id"]
                issuer = payload["issuer"]
                issuer_probe = d._process_probe(issuer)
                same_issuer = (
                    issuer.get("pid") == os.getpid()
                    and issuer.get("start") == _b2().process_start_identity(os.getpid())
                )
                if job_dir.exists() and not same_issuer:
                    _fail(
                        "A validation batch is pending with an existing job "
                        "directory; finalize it before another validator"
                    )
                if issuer_probe != "dead" and not same_issuer:
                    _fail(
                        "The pending validation intent is still owned by a live "
                        "issuer process"
                    )
                if (
                    payload["base_snapshot_digest"]
                    != d._snapshot_digest(snapshot)
                    or payload["source_evidence_digest"]
                    != source["evidence_digest"]
                    or payload["policy_digest"] != policy_sha
                ):
                    _fail(
                        "A different validation intent is already pending for this "
                        "source; it cannot be reinterpreted"
                    )
                return _validation_descriptor(
                    plan_id,
                    step_id,
                    current["cycle"],
                    candidate_sha256,
                    contract,
                    contract_event,
                    policy_sha,
                    source,
                    latest_intent,
                    static,
                    workspace,
                )
            if not result_exists:
                _fail(
                    "The validation batch is claimed; wait for it to settle and "
                    "finalize its immutable evidence"
                )
            # A completed previous batch and a new pending intent: allow the new
            # invocation; the pending batch invalidates any older approval.
        if (
            latest_result is not None
            and latest_result["payload"].get("classification") in {"passed"}
            and not any(
                event["payload"].get("source_evidence_digest")
                != source["evidence_digest"]
                for event in journal["validation_results"]
                if event["step_id"] == step_id
            )
        ):
            # Re-validation remains bounded and explicit; it is never automatic.
            pass
        index = snapshot.get("index") or {}
        next_sequence = len(journal["events"]) + 1
        validation_id = "v" + _digest(
            {
                "step_id": step_id,
                "cycle": current["cycle"],
                "candidate_sha256": candidate_sha256,
                "contract_digest": contract_event["payload"]["contract_digest"],
                "source_evidence_digest": source["evidence_digest"],
                "policy_digest": policy_sha,
                "sequence": next_sequence,
            }
        )[:40]
        job_id = "val-" + _digest(
            {
                "validation_id": validation_id,
                "base_snapshot_digest": d._snapshot_digest(snapshot),
                "sequence": next_sequence,
            }
        )[:48]
        task_dir = _plan_dir(plan_id) / "execution" / "validation-tasks"
        task_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        task_file = task_dir / f"{validation_id}.md"
        task_text = (
            "# D2 independent validation\n\n"
            f"- Validation: `{validation_id}`\n"
            f"- Plan: `{plan_id}`\n"
            f"- Step: `{step_id}`\n"
            f"- Candidate: `{candidate_sha256}`\n"
            f"- Contract: `{contract_event['payload']['contract_digest']}`\n"
            f"- Source attempt: `{source['attempt_id']}`\n"
            f"- Source evidence: `{source['evidence_digest']}`\n"
            f"- Policy digest: `{policy_sha}`\n\n"
            "The validator executes the frozen literal invocations in order. "
            "It is not a model, provider or writer.\n"
        )
        task_file.write_text(task_text, encoding="utf-8")
        os.chmod(task_file, 0o600)
        task_sha = _sha256_bytes(task_file.read_bytes())
        base_digest = d._snapshot_digest(snapshot)
        base_blob, _ = d._publish_json_blob(
            plan_id, snapshot, "validation invocation base snapshot"
        )
        original_base_blob = source["intent"]["original_base_blob_sha256"]
        payload = {
            "version": VALIDATION_BATCH_VERSION,
            "validation_id": validation_id,
            "batch_id": validation_id,
            "job_id": job_id,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "policy_digest": policy_sha,
            "plan_sha256": static["plan_sha256"],
            "manifest_digest": static["manifest_digest"],
            "source_attempt_id": source["attempt_id"],
            "source_job_id": source["job_id"],
            "source_evidence_digest": source["evidence_digest"],
            "source_final_snapshot_digest": source["final_snapshot_digest"],
            "source_kind": source["source_kind"],
            "generation": source["generation"],
            "issuer": _process_identity(),
            "base_snapshot_digest": base_digest,
            "base_snapshot_blob_sha256": base_blob,
            "original_base_snapshot_digest": source[
                "original_base_snapshot_digest"
            ],
            "original_base_blob_sha256": original_base_blob,
            "user_baseline_digest": source["user_baseline_digest"],
            "task_source_sha256": task_sha,
        }
        if payload["issuer"]["start"] is None:
            _fail("Cannot record the validation issuer process identity")
        events = _append(
            plan_id,
            [
                _event_spec(
                    d.TYPE_VALIDATION_INTENT,
                    step_id,
                    current["cycle"],
                    payload,
                )
            ],
            "validation_intent",
            plan_id=plan_id,
            step_id=step_id,
            validation_id=validation_id,
        )
        return _validation_descriptor(
            plan_id,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract,
            contract_event,
            policy_sha,
            source,
            events[0],
            static,
            workspace,
        )


def _validation_descriptor(
    plan_id: str,
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract: dict[str, Any],
    contract_event: dict[str, Any],
    policy_sha: str,
    source: dict[str, Any],
    intent_event: dict[str, Any],
    static: dict[str, Any],
    workspace: Path,
) -> dict[str, Any]:
    payload = intent_event["payload"]
    task_file = (
        _plan_dir(plan_id)
        / "execution"
        / "validation-tasks"
        / f"{payload['validation_id']}.md"
    )
    return {
        "version": _d().EXECUTION_VERSION,
        "kind": "validation",
        "plan_id": plan_id,
        "step_id": step_id,
        "cycle": cycle,
        "round": None,
        "role": "validator",
        "provider": "validator",
        "operation": "validation",
        "job_id": payload["job_id"],
        "validation_id": payload["validation_id"],
        "batch_id": payload["batch_id"],
        "candidate_sha256": candidate_sha256,
        "contract_digest": contract_event["payload"]["contract_digest"],
        "policy_digest": policy_sha,
        "intent_digest": intent_event["digest"],
        "intent_event_id": intent_event["event_id"],
        "assignment_digest": intent_event["digest"],
        "assignment_event_id": intent_event["event_id"],
        "task_source_sha256": payload["task_source_sha256"],
        "base_snapshot_digest": payload["base_snapshot_digest"],
        "source_attempt_id": source["attempt_id"],
        "source_evidence_digest": source["evidence_digest"],
        "source_kind": source["source_kind"],
        "generation": source["generation"],
        "constraints": (source["intent"].get("_unused") or None),
        "allowed_paths": list(contract["allowed_paths"]),
        "denied_paths": list(contract["denied_paths"]),
        "max_changed_files": None,
        "target_branch": contract["target_branch"],
        "protected_branches": list(contract["protected_branches"]),
        "task_file": str(task_file),
        "workspace": str(workspace),
    }


def claim_validation(
    descriptor: dict[str, Any],
    identity: dict[str, Any],
    lease: Any,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Publish the post-lease validation claim under the same plan lock."""
    d = _d()
    plan_id = descriptor.get("plan_id")
    job_id = descriptor.get("job_id")
    _require_id(plan_id, "managed plan_id")
    _require_id(job_id, "managed job_id")
    if not isinstance(getattr(lease, "epoch", None), str):
        _fail("Validation claim requires the actual B2 lease")
    if lease.owner.get("job_id") != job_id:
        _fail("Repository lease belongs to another validation job")
    if lease.owner.get("epoch") != lease.epoch:
        _fail("Validation lease epoch is inconsistent")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        if identity.get("root") != static.get("canonical_workspace"):
            _fail("Validation claim is in another canonical workspace")
        current = d._require_consensus(b1_state, descriptor.get("step_id"))
        constraints, candidate_sha256 = d._candidate_constraints(
            b1_state, descriptor.get("step_id")
        )
        journal = d._replay_journal(plan_id)
        intent = next(
            (
                event
                for event in journal["validation_intents"]
                if event["payload"].get("job_id") == job_id
            ),
            None,
        )
        if intent is None:
            _fail(f"Validation job {job_id} has no protected intent")
        if intent["digest"] != descriptor.get("intent_digest"):
            _fail("Validation claim does not match its protected intent")
        payload = intent["payload"]
        existing = next(
            (
                event
                for event in journal["validation_claims"]
                if event["payload"].get("job_id") == job_id
            ),
            None,
        )
        if existing is not None:
            if existing["payload"]["lease"]["epoch"] != lease.epoch:
                _fail("Validation job already claimed another lease")
            return existing["payload"]
        if payload["candidate_sha256"] != candidate_sha256:
            _fail("Validation intent is stale against the frozen candidate")
        if payload["cycle"] != current["cycle"] or intent["step_id"] != descriptor.get("step_id"):
            _fail("Validation intent moved out of its current binding")
        if _d()._snapshot_digest(snapshot) != payload["base_snapshot_digest"]:
            _fail(
                "Workspace content changed between the validation intent and the "
                "authoritative post-lease claim"
            )
        _require_no_live_writer(identity)
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
        facts = {
            "validation_id": payload["validation_id"],
            "batch_id": payload["batch_id"],
            "job_id": job_id,
            "cycle": payload["cycle"],
            "candidate_sha256": payload["candidate_sha256"],
            "contract_digest": payload["contract_digest"],
            "policy_digest": payload["policy_digest"],
            "lease": lease_meta,
            "base_snapshot_digest": payload["base_snapshot_digest"],
            "head": snapshot.get("head"),
            "branch": snapshot.get("branch"),
            "index_sha256": (snapshot.get("index") or {}).get("sha256"),
        }
        claim_payload = {
            "version": VALIDATION_BATCH_VERSION,
            **facts,
            "claim_digest": _digest(facts),
        }
        events = _append(
            plan_id,
            [
                _event_spec(
                    d.TYPE_VALIDATION_CLAIM,
                    intent["step_id"],
                    payload["cycle"],
                    claim_payload,
                )
            ],
            "validation_claim",
            plan_id=plan_id,
            step_id=intent["step_id"],
            claim_digest=claim_payload["claim_digest"],
        )
        return events[0]["payload"]


def validate_validation_launch(
    descriptor: dict[str, Any], identity: dict[str, Any]
) -> None:
    """Pre-spawn validation admission against the pending protected intent."""
    d = _d()
    plan_id = descriptor.get("plan_id")
    job_id = descriptor.get("job_id")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        if identity.get("root") != static.get("canonical_workspace"):
            _fail("Validation launch is in another canonical workspace")
        current = d._require_consensus(b1_state, descriptor.get("step_id"))
        constraints, candidate_sha256 = d._candidate_constraints(
            b1_state, descriptor.get("step_id")
        )
        journal = d._replay_journal(plan_id)
        intent = next(
            (
                event
                for event in journal["validation_intents"]
                if event["payload"].get("job_id") == job_id
            ),
            None,
        )
        if intent is None or intent["digest"] != descriptor.get("intent_digest"):
            _fail("Validation launch does not match a protected intent")
        payload = intent["payload"]
        if payload["candidate_sha256"] != candidate_sha256:
            _fail("Validation intent is stale against the candidate")
        if payload["cycle"] != current["cycle"]:
            _fail("Validation intent belongs to another cycle")
        claim = next(
            (
                event
                for event in journal["validation_claims"]
                if event["payload"].get("job_id") == job_id
            ),
            None,
        )
        if claim is not None:
            _fail("Validation job is already claimed; refusing a second launch")
        _require_no_live_writer(identity)
        workspace = Path(static["canonical_workspace"])
        contract, contract_event = _contract_for_current(
            plan_id, journal, descriptor["step_id"], current["cycle"], candidate_sha256
        )
        if payload["policy_digest"] != _policy_digest(_policy_from_contract(contract)):
            _fail("Validation policy changed after the intent")
        snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
        if d._snapshot_digest(snapshot) != payload["base_snapshot_digest"]:
            _fail(
                "Workspace source changed between the validation intent and launch"
            )
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            descriptor["step_id"],
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if source["evidence_digest"] != payload["source_evidence_digest"]:
            _fail("The validated writer source changed before launch")
        _require_source_current(plan_id, source, snapshot, "validation launch")


def validate_validation_worker(meta: dict[str, Any]) -> str | None:
    """Worker-side fail-closed revalidation before any command execution."""
    d = _d()
    descriptor = meta.get("managed_execution")
    if not isinstance(descriptor, dict) or descriptor.get("kind") != "validation":
        return "Validation worker metadata is malformed; failing closed"
    plan_id = descriptor.get("plan_id")
    job_id = descriptor.get("job_id")
    try:
        with _b1().plan_lock(plan_id):
            b1_state = _b1().replay_plan_state_locked(plan_id)
            static = d._require_strict_plan(b1_state)
            current = d._require_consensus(b1_state, descriptor.get("step_id"))
            constraints, candidate_sha256 = d._candidate_constraints(
                b1_state, descriptor.get("step_id")
            )
            journal = d._replay_journal(plan_id)
            intent = next(
                (
                    event
                    for event in journal["validation_intents"]
                    if event["payload"].get("job_id") == job_id
                ),
                None,
            )
            if intent is None or intent["digest"] != descriptor.get("intent_digest"):
                return "Validation intent does not match the worker job"
            payload = intent["payload"]
            claim = next(
                (
                    event
                    for event in journal["validation_claims"]
                    if event["payload"].get("job_id") == job_id
                ),
                None,
            )
            if claim is None:
                return "Validation job has no protected post-lease claim"
            lease = meta.get("workspace_lease")
            if not isinstance(lease, dict):
                return "Validation job has no workspace lease record"
            owner = _b2().read_owner(d._repo_identity(static))
            if not isinstance(owner, dict):
                return "Validation job has no durable B2 owner record"
            if (
                owner.get("job_id") != job_id
                or owner.get("epoch") != lease.get("epoch")
                or owner.get("state") not in {"admission", "supervising"}
            ):
                return "Validation job does not own the actual B2 lease"
            if claim["payload"]["lease"]["epoch"] != lease.get("epoch"):
                return "Validation claim names another lease epoch"
            if claim["payload"]["claim_digest"] != descriptor.get("claim_digest"):
                return "Validation claim digest changed"
            if payload["candidate_sha256"] != candidate_sha256:
                return "Validation intent is stale against the candidate"
            contract, contract_event = _contract_for_current(
                plan_id, journal, descriptor["step_id"], current["cycle"], candidate_sha256
            )
            policy = _policy_from_contract(contract)
            if claim["payload"]["policy_digest"] != _policy_digest(policy):
                return "Validation policy changed after the claim"
            workspace = Path(str(meta.get("workspace") or ""))
            if not workspace.is_absolute():
                return "Validation workspace is not absolute"
            snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
            if d._snapshot_digest(snapshot) != claim["payload"]["base_snapshot_digest"]:
                return "Workspace source drifted after the validation claim"
            if (
                snapshot.get("head") != claim["payload"]["head"]
                or snapshot.get("branch") != claim["payload"]["branch"]
            ):
                return "Repository HEAD or branch drifted after the validation claim"
            baseline = meta.get("git_baseline")
            if d._snapshot_digest(baseline or {}) != claim["payload"][
                "base_snapshot_digest"
            ]:
                return "The job baseline does not match the protected validation claim"
            source = _latest_writer_source_locked(
                plan_id,
                journal,
                descriptor["step_id"],
                current["cycle"],
                candidate_sha256,
                contract_event["payload"]["contract_digest"],
            )
            if source["evidence_digest"] != payload["source_evidence_digest"]:
                return "The validated writer source changed before execution"
            _fresh_intent_preflight_locked(
                plan_id,
                journal,
                contract,
                contract_event,
                policy,
                source,
                snapshot,
            )
            return None
    except Exception as exc:
        return f"Validation worker validation failed; failing closed: {exc}"


# ---------------------------------------------------------------------------
# Actual validation execution (ordinary_ro / systems_trusted)
# ---------------------------------------------------------------------------


def _coordinator_state_root() -> Path | None:
    """Return the coordinator state root as seen by the parent only.

    The validation child masks this whole root; the parent keeps its metadata
    and evidence access. The value is never written into child argv or env.
    """
    try:
        value = _hook("state_home")()
    except Exception:
        return None
    if value is None:
        return None
    try:
        text = os.fspath(value)
    except TypeError:
        return None
    return Path(text) if text else None


# Credential-value redaction and child-environment isolation are distinct
# decisions. The deny list above deliberately covers benign metadata and
# startup-control variables (``GITHUB_JOB=test``, ``GITHUB_RUN_ATTEMPT=1``,
# ``CI=true``, provider config, ...) in addition to credential holders. Its
# values must never seed the redactor: a short metadata value such as ``test``
# or ``1`` would then corrupt trusted adapter/run identities, timestamps and
# captures during mandatory structure sanitization.
#
# Only names that actually hold credential values seed the redactor. C's
# existing provider-credential classifier is the authority (the same classifier
# the provider capture path uses); the bounded supplement below adds credential
# values its lexical segments cannot name. Short real credential values stay
# classified - there is deliberately no minimum-length shortcut here.
CREDENTIAL_VALUE_ENV_NAMES = frozenset(
    {
        # JSON registry-auth blob holding base64 user/password entries; the
        # name contains no TOKEN/PASSWORD/SECRET/CREDENTIAL segment.
        "DOCKER_AUTH_CONFIG",
    }
)

# A real configured environment may spell the compact key marker without the
# separator (``DEEPSEEK_APIKEY``). C's compound classifier matches only
# ``API_KEY``, so such a value would otherwise never seed the redactor. This
# is a bounded terminal-segment rule on exactly ``_APIKEY``; it never infers
# credentials from a provider prefix or an arbitrary substring.
CREDENTIAL_VALUE_ENV_SUFFIXES = ("_APIKEY",)


def _denied_child_env_name(name: str) -> bool:
    """Broad ambient-environment isolation list for validation children."""
    upper = name.upper()
    if upper in DENIED_ENV_NAMES:
        return True
    return any(upper.startswith(prefix) for prefix in DENIED_ENV_PREFIXES)


def _credential_env_name(name: str, c: Any | None = None) -> bool:
    """Classify a variable name as holding an actual credential value."""
    upper = name.upper()
    if upper in CREDENTIAL_VALUE_ENV_NAMES:
        return True
    if upper.endswith(CREDENTIAL_VALUE_ENV_SUFFIXES):
        return True
    module = c if c is not None else _hook("c_module")()
    return bool(module.is_sensitive_name(name))


def _review_redactor() -> Any:
    """Collect known credential env values in memory, never on disk.

    The resulting redactor is used before any framework-managed capture file,
    blob, head text or structured diagnostic is persisted. Values and their
    definitions are never serialized; only redacted bytes are.

    Only genuine credential values are collected; the broader child-environment
    deny list is applied separately by ``_validation_env`` and never becomes a
    redaction pattern.
    """
    c = _hook("c_module")()
    secrets: list[bytes] = []
    for name, value in os.environ.items():
        if not value or len(value) > 65_536:
            continue
        if _credential_env_name(name, c):
            secrets.append(value.encode("utf-8", "surrogatepass"))
    return c.Redactor(secrets)


def _sanitize_capture(data: bytes, *, overflow: bool, redactor: Any) -> bytes:
    """Redact a complete captured buffer before it reaches any persistent view."""
    sanitized = redactor.sanitize(bytes(data))
    if overflow:
        cut = min(len(sanitized), redactor.holdback())
        if cut:
            sanitized = sanitized[:-cut]
        sanitized = redactor.strip_partial_suffix(sanitized)
        sanitized += b"\n[d2 validation capture truncated]\n"
    verifier = getattr(_hook("c_module")(), "sanitize_persisted_stream", None)
    if verifier is not None:
        sanitized = verifier(redactor, sanitized)
    return sanitized


def _credential_mask_paths() -> list[tuple[Path, str]]:
    """Known coordinator, GitHub, SSH and provider credential roots.

    This is a bounded known-root mask, not a whole-host secret closure. The
    parent alone retains access; the validation child sees an empty directory
    or /dev/null at each existing known root.
    """
    home = Path(os.path.expanduser("~"))
    candidates: list[Path] = []
    state = _coordinator_state_root()
    if state is not None:
        candidates.append(state)
    candidates.extend(
        [
            home / ".ssh",
            home / ".config" / "gh",
            home / ".git-credentials",
            home / ".netrc",
            home / ".claude",
            home / ".claude.json",
            home / ".config" / "claude",
            home / ".config" / "anthropic",
            home / ".deepseek",
            home / ".config" / "deepseek",
            home / ".config" / "glm",
            home / ".zhipu",
            home / ".config" / "zhipu",
            home / ".aws",
            home / ".azure",
            home / ".config" / "gcloud",
            home / ".kube",
            home / ".docker",
        ]
    )
    masks: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            resolved = candidate
        text = str(resolved)
        if not text or text == "/" or text in seen:
            continue
        seen.add(text)
        try:
            info = os.lstat(resolved)
        except OSError:
            continue
        masks.append(
            (resolved, "directory" if stat.S_ISDIR(info.st_mode) else "file")
        )
    masks.sort(key=lambda item: (len(str(item[0])), str(item[0])))
    return masks


def _append_rebind(command: list[str], target: Path, roots: list[Path]) -> None:
    """Create mount points after masks/private tmp, then bind target read-only."""
    text = str(target)
    for root in roots:
        root_text = str(root)
        if text == root_text:
            command.extend(["--dir", root_text])
            break
        if text.startswith(root_text.rstrip("/") + "/"):
            current = Path(root_text)
            command.extend(["--dir", str(current)])
            relative = Path(text).relative_to(current)
            for part in relative.parts[:-1]:
                current = current / part
                command.extend(["--dir", str(current)])
            break
    command.extend(["--ro-bind", text, text])


def _sandbox_prefix(
    entry: dict[str, Any],
    *,
    workspace: Path,
    scratch: Path,
    extra_ro_paths: list[Path],
) -> tuple[list[str] | None, dict[str, Any], str]:
    """Build the measured mount order for one validation invocation.

    Order: root read-only bind, known credential/state masks, private /tmp,
    explicit canonical-source read-only rebind, exact literal adapter exposure,
    then the private scratch mount. Later mounts intentionally override masks
    only for the exact approved source and adapter paths. The scratch mount
    point lives inside the already-private /tmp tmpfs because the read-only
    root bind cannot create a new top-level directory.
    """
    executable = shutil.which("bwrap")
    if not executable:
        return None, {}, "bubblewrap executable is unavailable"
    command = [
        executable,
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
    ]
    context = entry["context"]
    if context == "ordinary_ro":
        command.extend(["--unshare-pid", "--proc", "/proc", "--cap-drop", "ALL"])
    elif context == "systems_trusted":
        # Host /proc is already exposed by the read-only root bind. No cap-add,
        # setuid path or privilege widening is used.
        pass
    else:  # pragma: no cover - schema rejects other contexts
        return None, {}, f"unsupported validation context {context!r}"
    masks = _credential_mask_paths()
    for path, kind in masks:
        if kind == "directory":
            command.extend(["--tmpfs", str(path)])
        else:
            command.extend(["--ro-bind", "/dev/null", str(path)])
    command.extend(["--tmpfs", "/tmp"])
    roots = [Path("/tmp"), *(path for path, _kind in masks)]
    _append_rebind(command, workspace, roots)
    for extra in extra_ro_paths:
        _append_rebind(command, Path(extra), roots)
    command.extend(["--bind", str(scratch), SANDBOX_SCRATCH_PATH])
    metadata = {
        "context": context,
        "cap_drop": "ALL" if context == "ordinary_ro" else "none",
        "unshare_pid": context == "ordinary_ro",
        "private_tmp": True,
        "mount_order": [
            "root_ro",
            "known_credential_masks",
            "private_tmp",
            "canonical_source_ro",
            "literal_adapter_ro",
            "private_scratch",
        ],
        "masks": [
            {"path": str(path), "kind": kind, "scope": "known_credential_root"}
            for path, kind in masks
        ],
        "canonical_source_ro": str(workspace),
        "literal_adapter_ro": [str(Path(path)) for path in extra_ro_paths],
        "private_scratch": SANDBOX_SCRATCH_PATH,
        "host_network": "shared",
        "credential_file_absence": False,
    }
    return command, metadata, ""


def _hex_capability(value: Any) -> int | None:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def _process_cap_eff(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return _hex_capability(line.split()[1])
    except OSError:
        return None
    return None


def _probe_sandbox(
    prefix: list[str],
    *,
    workspace: Path,
    cwd: Path,
    env: dict[str, str],
    cancel_marker: Path,
    overall_deadline: float,
    context: str,
) -> dict[str, Any]:
    """Prove actual EROFS and record the concrete child context."""
    marker = Path(workspace) / f".d2-ro-probe-{secrets.token_hex(8)}"
    remaining = overall_deadline - time.monotonic()
    if remaining <= 0:
        return {"ok": False, "reason": "the validation deadline expired before the probe"}
    command = [
        *prefix,
        "--chdir",
        str(cwd),
        "--",
        sys.executable,
        "-I",
        "-B",
        "-c",
        _SANDBOX_PROBE_SCRIPT,
        str(marker),
    ]
    try:
        result = _run_bounded(
            command,
            cwd=Path(workspace),
            env=env,
            timeout_seconds=max(1, min(20, int(remaining))),
            capture_limit=128 * 1024,
            cancel_marker=cancel_marker,
            overall_deadline=overall_deadline,
        )
    except Exception as exc:
        return {
            "ok": False,
            "reason": "the read-only sandbox probe could not start: "
            + type(exc).__name__,
        }
    finally:
        try:
            if marker.exists():
                marker.unlink()
        except OSError:
            pass
    if result["timed_out"] or result["cancelled"]:
        return {"ok": False, "reason": "the read-only sandbox probe did not complete"}
    if result["overflow"]:
        return {"ok": False, "reason": "the read-only sandbox probe overflowed"}
    observation: dict[str, Any] | None = None
    for line in reversed(
        result["stdout"].decode("utf-8", "replace").splitlines()
    ):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and "write_errno" in candidate:
            observation = candidate
            break
    if observation is None:
        return {
            "ok": False,
            "reason": (
                "the sandbox did not report a concrete read-only refusal "
                f"(exit {result['exit_code']})"
            ),
        }
    errno_name = observation.get("write_errno")
    if observation.get("wrote") or errno_name != "EROFS":
        return {
            "ok": False,
            "reason": (
                "the sandbox write probe was not refused by a read-only "
                f"filesystem (errno {errno_name!r}); a missing path or EACCES is "
                "not read-only proof"
            ),
            "observation": observation,
        }
    if context == "ordinary_ro":
        capabilities = _hex_capability(observation.get("cap_eff"))
        if capabilities != 0:
            return {
                "ok": False,
                "reason": (
                    "ordinary_ro did not actually run with all capabilities "
                    "dropped"
                ),
                "observation": observation,
            }
        if observation.get("pid") == os.getpid():
            return {
                "ok": False,
                "reason": "ordinary_ro did not run in its own PID namespace",
                "observation": observation,
            }
    elif context == "systems_trusted":
        # The trusted context retains host access for nested systems tests, but
        # it must never hold a capability the coordinator itself does not have.
        child_capabilities = _hex_capability(observation.get("cap_eff"))
        parent_capabilities = _process_cap_eff(os.getpid())
        if child_capabilities is None or parent_capabilities is None:
            return {
                "ok": False,
                "reason": (
                    "systems_trusted did not report measurable child and "
                    "coordinator capabilities"
                ),
                "observation": observation,
            }
        if child_capabilities & ~parent_capabilities:
            return {
                "ok": False,
                "reason": (
                    "systems_trusted retained capabilities beyond the current "
                    "coordinator's capability set"
                ),
                "observation": observation,
            }
        observation = dict(observation)
        observation["parent_cap_eff"] = f"{parent_capabilities:016x}"
    return {"ok": True, "reason": "", "observation": observation}


def _private_scratch(job_dir: Path) -> Path:
    root = Path(job_dir) / "validation-scratch"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("home", "tmp", "cache", "ruff", "mpl", "report", "captures"):
        path = root / name
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def _validation_env(
    scratch: Path,
    report_env: str | None,
    report_path: Path | None,
    run_id: str,
    sandboxed: bool,
) -> tuple[dict[str, str], dict[str, Any]]:
    env: dict[str, str] = {}
    for key in CALLER_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            env[key] = value
    if not env.get("PATH"):
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    prefix = SANDBOX_SCRATCH_PATH if sandboxed else str(scratch)
    env.update(
        {
            "HOME": f"{prefix}/home",
            "TMPDIR": f"{prefix}/tmp",
            "TMP": f"{prefix}/tmp",
            "TEMP": f"{prefix}/tmp",
            "XDG_CACHE_HOME": f"{prefix}/cache",
            "PYTHONPYCACHEPREFIX": f"{prefix}/cache/pycache",
            "RUFF_CACHE_DIR": f"{prefix}/ruff",
            "MPLCONFIGDIR": f"{prefix}/mpl",
            "PYTHONDONTWRITEBYTECODE": "1",
            RUN_ID_ENV: run_id,
        }
    )
    if report_env and report_path is not None:
        env[report_env] = (
            f"{prefix}/report/{report_path.name}"
            if sandboxed
            else str(report_path)
        )
    for name in list(env):
        if _denied_child_env_name(name):
            env.pop(name, None)
    identity = {
        "keys": sorted(env),
        "sha256": _digest(env),
        "profile": "minimal_private",
        "stripped_prefixes": list(DENIED_ENV_PREFIXES),
        "stripped_names": sorted(DENIED_ENV_NAMES),
        "network": "shared",
        "credential_file_absence": False,
    }
    return env, identity


def _executable_identity(
    argv0: str, env: dict[str, str], *, cwd: Path
) -> dict[str, Any]:
    """Resolve the literal argv0 exactly as the child will see it.

    The validation child runs with ``--chdir`` into the approved entry cwd, so
    a relative argv0 (``./tool``) and relative PATH entries must resolve
    against that cwd, never against the coordinator/worker cwd. The recorded
    identity therefore reflects the bytes the kernel would execute. The literal
    argv itself is never rewritten.
    """
    cwd = Path(cwd)
    if "/" in argv0:
        candidate = Path(argv0)
        resolved = (
            str(candidate if candidate.is_absolute() else cwd / candidate)
        )
    else:
        resolved = None
        for entry in env.get("PATH", "").split(os.pathsep):
            base = Path(entry) if entry else Path(".")
            if not base.is_absolute():
                base = cwd / base
            candidate = base / argv0
            try:
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    resolved = str(candidate)
                    break
            except OSError:
                continue
    if not resolved:
        return {
            "argv0": argv0,
            "path": None,
            "realpath": None,
            "sha256": None,
            "size": None,
            "mode": None,
            "available": False,
        }
    path = Path(resolved)
    try:
        real = path.resolve(strict=True)
        info = real.stat()
    except OSError as exc:
        return {
            "argv0": argv0,
            "path": str(path),
            "realpath": None,
            "sha256": None,
            "size": None,
            "mode": None,
            "available": False,
            "error": str(exc),
        }
    digest = None
    if stat.S_ISREG(info.st_mode) and info.st_size <= 64 * 1024 * 1024:
        try:
            digest = _sha256_bytes(real.read_bytes())
        except OSError:
            digest = None
    return {
        "argv0": argv0,
        "path": str(path),
        "realpath": str(real),
        "sha256": digest,
        "size": info.st_size,
        "mode": stat.S_IMODE(info.st_mode),
        "available": True,
    }


def _run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    capture_limit: int,
    cancel_marker: Path,
    overall_deadline: float,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    buffers = [bytearray(), bytearray()]
    overflow = {"value": False}

    def reader(stream, buffer: bytearray) -> None:
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                if len(buffer) + len(chunk) > capture_limit:
                    overflow["value"] = True
                    buffer.extend(chunk[: capture_limit + 1 - len(buffer)])
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    break
                buffer.extend(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=reader, args=(process.stdout, buffers[0]), daemon=True),
        threading.Thread(target=reader, args=(process.stderr, buffers[1]), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    cancelled = False
    deadline = min(time.monotonic() + timeout_seconds, overall_deadline)
    while process.poll() is None:
        if cancel_marker.exists():
            cancelled = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            break
        if time.monotonic() >= deadline:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            break
        time.sleep(0.02)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    for thread in threads:
        thread.join(timeout=5)
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "overflow": overflow["value"],
        "stdout": bytes(buffers[0]),
        "stderr": bytes(buffers[1]),
        "duration_seconds": round(time.monotonic() - started, 6),
    }


def _structured_report(
    report_path: Path,
    *,
    entry: dict[str, Any],
    run_id: str,
    argv: list[str],
    cwd: Path,
    actual_exit: int | None,
    redactor: Any,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Read and validate the pinned adapter's machine-readable report."""
    reasons: list[str] = []
    try:
        info = os.lstat(report_path)
    except OSError as exc:
        return None, [f"structured evidence is missing: {exc}"]
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None, ["structured evidence is not a regular file"]
    if info.st_size > MAX_STRUCTURED_REPORT_BYTES:
        return None, ["structured evidence exceeds its size bound"]
    try:
        data = report_path.read_bytes()
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [f"structured evidence is unreadable: {exc}"]
    if not isinstance(document, dict):
        return None, ["structured evidence is not a JSON object"]
    required = {
        "version",
        "adapter_id",
        "adapter_version",
        "run_id",
        "argv",
        "argv_sha256",
        "cwd",
        "python",
        "started_at",
        "finished_at",
        "counts",
        "identities",
        "adapter_error",
    }
    if set(document) != required:
        return None, ["structured evidence has an invalid schema"]
    evidence = entry["evidence"]
    expected_adapter = evidence["adapter"]
    if (
        document.get("version") != 1
        or document.get("adapter_id") != expected_adapter["id"]
        or document.get("adapter_version") != expected_adapter["version"]
    ):
        reasons.append("structured evidence adapter identity does not match the policy")
    if document.get("run_id") != run_id:
        reasons.append("structured evidence belongs to another process run")
    if document.get("argv") != argv:
        reasons.append("structured evidence argv does not match the executed argv")
    if document.get("argv_sha256") != _digest(argv):
        reasons.append("structured evidence argv digest does not match")
    if document.get("cwd") != str(cwd):
        reasons.append("structured evidence cwd does not match the executed cwd")
    counts = document.get("counts")
    try:
        counts = _validate_counts(counts, "structured counts")
    except Exception as exc:
        return None, reasons + [str(exc)]
    identities = document.get("identities")
    if not isinstance(identities, dict):
        return None, reasons + ["structured identities are malformed"]
    for key in (
        "failures",
        "errors",
        "skips",
        "expected_failures",
        "unexpected_successes",
    ):
        value = identities.get(key)
        if not isinstance(value, list) or len(value) > 10_000:
            reasons.append(f"structured identities.{key} is malformed")
    if set(identities) != {
        "failures",
        "errors",
        "skips",
        "expected_failures",
        "unexpected_successes",
    }:
        reasons.append("structured identities has an invalid schema")
    if counts["collected"] < evidence["min_collected"]:
        reasons.append(
            "structured evidence collected fewer tests than the approved floor"
        )
    if counts["run"] < evidence["min_run"]:
        reasons.append("structured evidence ran fewer tests than the approved floor")
    if counts["run"] != counts["collected"]:
        reasons.append("structured evidence did not run every collected test")
    if counts["failures"] or counts["errors"]:
        reasons.append("structured evidence records failing or erroring tests")
    if counts["skips"]:
        reasons.append("mandatory structured invocation recorded skipped tests")
    expected_failures = identities.get("expected_failures") or []
    unexpected_successes = identities.get("unexpected_successes") or []
    for name in ("failures", "errors", "skips"):
        values = identities.get(name) or []
        if isinstance(values, list) and len(values) != counts[name]:
            reasons.append(
                f"structured identities.{name} does not match the reported count"
            )
    if expected_failures:
        reasons.append("structured evidence records expected failures")
    if unexpected_successes:
        reasons.append("structured evidence records unexpected successes")
    if counts["passed"] != max(
        0, counts["run"] - counts["failures"] - counts["errors"] - counts["skips"]
    ):
        reasons.append("structured evidence pass count is internally inconsistent")
    if actual_exit is not None:
        if counts["failures"] or counts["errors"]:
            if actual_exit == 0:
                reasons.append(
                    "structured evidence reports failures but the process exited 0"
                )
        elif actual_exit != 0:
            reasons.append(
                "structured evidence reports no failures but the process exit "
                "code disagrees"
            )
    payload = {
        **{
            key: document.get(key)
            for key in (
                "adapter_id",
                "adapter_version",
                "run_id",
                "python",
                "started_at",
                "finished_at",
                "adapter_error",
            )
        },
        "counts": counts,
        "identities": identities,
        "raw_sha256": _sha256_bytes(data),
        "raw_bytes": len(data),
    }
    # Structured identities and diagnostics are sanitized before they can be
    # persisted in evidence, logs or blobs. The report file itself is replaced
    # with the sanitized document so no raw credential echo remains in scratch.
    try:
        c = _hook("c_module")()
        sanitized_document = c.sanitize_structure(redactor, document)
        payload = c.sanitize_structure(redactor, payload)
        _write_adapter_report(str(report_path), sanitized_document)
    except Exception:
        # Sanitization is mandatory; if the helpers are unavailable the caller
        # fails closed rather than persisting an unverified structured view.
        reasons.append("structured evidence could not be sanitized before persistence")
        return None, reasons
    if document.get("adapter_error"):
        reasons.append("the structured adapter recorded an execution error")
    return payload, reasons


def _structured_adapter_problem(
    entry: dict[str, Any], adapter_path: Path, workspace: Path
) -> str:
    """Reject any structured source that is not the trusted coordinator adapter.

    The voted policy may name this exact module or a byte-identical installed
    copy outside the candidate workspace. An arbitrary JSON emitter with a
    self-supplied digest/ID, a candidate-owned file, an unused adapter argument,
    a different interpreter or an unsupported invocation shape all fail closed
    before any command runs.
    """
    adapter = entry["evidence"]["adapter"]
    argv = list(entry["argv"])
    trusted_path = Path(__file__).resolve()
    try:
        trusted_bytes = trusted_path.read_bytes()
    except OSError as exc:
        return f"the trusted coordinator adapter is unavailable: {exc}"
    trusted_sha = _sha256_bytes(trusted_bytes)
    if adapter.get("sha256") != trusted_sha:
        return (
            "the declared adapter sha256 is not the trusted coordinator "
            "adapter's actual digest"
        )
    try:
        actual_bytes = adapter_path.read_bytes()
    except OSError as exc:
        return f"the pinned adapter is unavailable: {exc}"
    if _sha256_bytes(actual_bytes) != trusted_sha:
        return (
            "the pinned adapter bytes are not the trusted coordinator adapter "
            "implementation"
        )
    try:
        resolved = adapter_path.resolve()
    except (OSError, RuntimeError):
        resolved = adapter_path
    workspace_root = Path(workspace).resolve()
    try:
        resolved.relative_to(workspace_root)
    except ValueError:
        pass
    else:
        return "the structured adapter resolves inside the candidate workspace"
    support = adapter_path.with_name("c_providers.py")
    try:
        support_exists = support.is_file()
    except OSError:
        support_exists = False
    if support_exists:
        trusted_support = trusted_path.with_name("c_providers.py")
        try:
            support_bytes = support.read_bytes()
            trusted_support_bytes = trusted_support.read_bytes()
        except OSError as exc:
            return f"the adapter support file is unreadable: {exc}"
        if _sha256_bytes(support_bytes) != _sha256_bytes(trusted_support_bytes):
            return (
                "the adapter support file is not the trusted coordinator "
                "implementation"
            )
    if not argv:
        return "the structured invocation has no argv"
    if os.path.realpath(argv[0]) != os.path.realpath(sys.executable):
        return (
            "the structured invocation does not execute the trusted coordinator "
            "interpreter"
        )
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        if argv[index] not in SUPPORTED_ADAPTER_INTERPRETER_FLAGS:
            return (
                "the structured invocation uses an unsupported interpreter "
                f"option {argv[index]!r}"
            )
        index += 1
    if index >= len(argv) or argv[index] != adapter["path"]:
        return (
            "the structured invocation does not execute the pinned adapter as "
            "its literal script argument"
        )
    if index + 1 >= len(argv) or argv[index + 1] != "_unittest-adapter":
        return (
            "the structured invocation does not use the pinned adapter's "
            "supported entry point"
        )
    if index + 2 >= len(argv) or argv[index + 2] != "discover":
        return (
            "the structured invocation does not use the supported stdlib "
            "unittest discover entry"
        )
    return ""


def _execute_validation_entry(
    entry: dict[str, Any],
    *,
    workspace: Path,
    contract: dict[str, Any],
    scratch: Path,
    cancel_marker: Path,
    overall_deadline: float,
    job_dir: Path,
    redactor: Any,
) -> dict[str, Any]:
    reasons: list[str] = []
    argv = list(entry["argv"])
    cwd = (workspace / entry["cwd"]).resolve()
    try:
        cwd.relative_to(workspace.resolve())
    except ValueError:
        return _blocked_entry(
            entry, "cwd escapes the canonical workspace", reasons, cwd=str(cwd)
        )
    if not cwd.is_dir():
        return _blocked_entry(
            entry, "cwd does not exist", reasons, cwd=str(cwd)
        )
    evidence_kind = entry["evidence"]["kind"]
    report_env = None
    report_path = None
    adapter_path: Path | None = None
    extra_ro_paths: list[Path] = []
    if evidence_kind == "structured_unittest":
        report_env = entry["evidence"]["report_env"]
        run_id = secrets.token_hex(16)
        report_path = scratch / "report" / f"{entry['invocation_id']}-{run_id}.json"
        adapter = entry["evidence"]["adapter"]
        adapter_path = Path(adapter["path"])
        if adapter["path"] not in argv:
            return _blocked_entry(
                entry,
                "the executed argv does not name the pinned adapter path",
                reasons,
                cwd=str(cwd),
            )
        try:
            adapter_bytes = adapter_path.read_bytes()
        except OSError as exc:
            return _blocked_entry(
                entry,
                f"the pinned adapter is unavailable: {exc}",
                reasons,
                cwd=str(cwd),
            )
        if _sha256_bytes(adapter_bytes) != adapter["sha256"]:
            return _blocked_entry(
                entry,
                "the pinned adapter bytes changed after the ballot",
                reasons,
                cwd=str(cwd),
            )
        trust_problem = _structured_adapter_problem(
            entry, adapter_path, workspace
        )
        if trust_problem:
            return _blocked_entry(
                entry, trust_problem, reasons, cwd=str(cwd)
            )
        extra_ro_paths.append(adapter_path)
        # The pinned adapter reuses the C sanitizer helpers. Expose only that
        # exact sibling file when present; never the whole coordinator state.
        support = adapter_path.with_name("c_providers.py")
        try:
            if support.is_file():
                extra_ro_paths.append(support)
        except OSError:
            pass
    else:
        run_id = secrets.token_hex(16)
    env, env_identity = _validation_env(
        scratch, report_env, report_path, run_id, True
    )
    executable = _executable_identity(argv[0], env, cwd=cwd)
    if not executable.get("available"):
        return _blocked_entry(
            entry,
            f"the literal executable is unavailable: {argv[0]}",
            reasons,
            cwd=str(cwd),
        )
    prefix, layout, prefix_reason = _sandbox_prefix(
        entry,
        workspace=workspace,
        scratch=scratch,
        extra_ro_paths=extra_ro_paths,
    )
    if not prefix:
        return _blocked_entry(
            entry,
            "real read-only execution enforcement is unavailable: "
            + (prefix_reason or "unknown"),
            reasons,
            enforcement=layout,
            cwd=str(cwd),
        )
    probe = _probe_sandbox(
        prefix,
        workspace=workspace,
        cwd=cwd,
        env=env,
        cancel_marker=cancel_marker,
        overall_deadline=overall_deadline,
        context=entry["context"],
    )
    if not probe["ok"]:
        return _blocked_entry(
            entry,
            probe["reason"],
            reasons,
            observation=probe.get("observation"),
            enforcement=layout,
            cwd=str(cwd),
        )
    command = [*prefix, "--chdir", str(cwd), "--", *argv]
    result = _run_bounded(
        command,
        cwd=workspace,
        env=env,
        timeout_seconds=entry["timeout_seconds"],
        capture_limit=entry["capture_limit_bytes"],
        cancel_marker=cancel_marker,
        overall_deadline=overall_deadline,
    )
    raw_stdout = result.pop("stdout")
    raw_stderr = result.pop("stderr")
    stdout = _sanitize_capture(
        raw_stdout, overflow=bool(result["overflow"]), redactor=redactor
    )
    stderr = _sanitize_capture(
        raw_stderr, overflow=bool(result["overflow"]), redactor=redactor
    )
    capture_dir = scratch / "captures"
    stdout_path = capture_dir / f"{entry['invocation_id']}-{run_id}.stdout"
    stderr_path = capture_dir / f"{entry['invocation_id']}-{run_id}.stderr"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    os.chmod(stdout_path, 0o600)
    os.chmod(stderr_path, 0o600)
    counts = None
    structured = None
    passed = False
    if result["timed_out"]:
        reasons.append("the invocation exceeded its approved timeout")
    if result["cancelled"]:
        reasons.append("the invocation was cancelled")
    if result["overflow"]:
        reasons.append("captured output exceeded the approved capture bound")
    if evidence_kind == "structured_unittest":
        structured, report_reasons = _structured_report(
            report_path,
            entry=entry,
            run_id=run_id,
            argv=argv,
            cwd=cwd,
            actual_exit=result["exit_code"],
            redactor=redactor,
        )
        reasons.extend(report_reasons)
        if structured is not None:
            counts = structured["counts"]
    else:
        if result["exit_code"] != entry["expected_exit"]:
            reasons.append(
                f"exit code {result['exit_code']} does not match the approved "
                f"expected exit {entry['expected_exit']}"
            )
    if not result["timed_out"] and not result["cancelled"] and not result["overflow"]:
        if evidence_kind == "structured_unittest":
            passed = structured is not None and not reasons
        else:
            passed = result["exit_code"] == entry["expected_exit"] and not reasons
    return {
        "invocation_id": entry["invocation_id"],
        "label": entry["label"],
        "purpose": entry["purpose"],
        "masked_argv_sha256": _digest(argv),
        "argv": argv,
        "cwd": str(cwd),
        "context": entry["context"],
        "ro_enforcement": entry["ro_enforcement"],
        "ro_mode": "kernel_ro",
        "environment_policy": entry["environment_policy"],
        "environment": env_identity,
        "executable": executable,
        "sandbox": layout,
        "context_observation": probe["observation"],
        "evidence_kind": evidence_kind,
        "run_id": run_id,
        "exit_code": result["exit_code"],
        "expected_exit": entry["expected_exit"],
        "timed_out": result["timed_out"],
        "cancelled": result["cancelled"],
        "overflow": result["overflow"],
        "duration_seconds": result["duration_seconds"],
        "stdout": {
            "path": str(stdout_path),
            "sha256": _sha256_bytes(stdout),
            "bytes": len(stdout),
        },
        "stderr": {
            "path": str(stderr_path),
            "sha256": _sha256_bytes(stderr),
            "bytes": len(stderr),
        },
        "counts": counts,
        "structured": structured,
        "passed": passed and not reasons,
        "reasons": reasons[:MAX_ENTRY_REASONS],
        "executed_at": _now(),
    }


def _blocked_entry(
    entry: dict[str, Any],
    reason: str,
    reasons: list[str],
    *,
    observation: dict[str, Any] | None = None,
    enforcement: dict[str, Any] | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    combined = (reasons + [reason])[:MAX_ENTRY_REASONS]
    return {
        "invocation_id": entry["invocation_id"],
        "label": entry["label"],
        "purpose": entry["purpose"],
        "masked_argv_sha256": _digest(list(entry["argv"])),
        "argv": list(entry["argv"]),
        "cwd": cwd or entry["cwd"],
        "context": entry["context"],
        "ro_enforcement": entry["ro_enforcement"],
        "ro_mode": "not_started",
        "environment_policy": entry["environment_policy"],
        "environment": None,
        "executable": None,
        "sandbox": enforcement,
        "context_observation": observation,
        "evidence_kind": entry["evidence"]["kind"],
        "run_id": None,
        "exit_code": None,
        "expected_exit": entry["expected_exit"],
        "timed_out": False,
        "cancelled": False,
        "overflow": False,
        "duration_seconds": 0.0,
        "stdout": None,
        "stderr": None,
        "counts": None,
        "structured": None,
        "passed": False,
        "reasons": combined,
        "executed_at": _now(),
    }


def execute_validation_worker(
    meta_path: Path, job_dir: Path, meta: dict[str, Any]
) -> int:
    """Run the frozen literal validation policy, then publish durable evidence."""
    d = _d()
    job_dir = Path(job_dir)
    descriptor = meta.get("managed_execution") or {}
    started_at = _now()
    start_monotonic = time.monotonic()
    timeout_seconds = int(meta.get("timeout_seconds") or 3600)
    overall_deadline = start_monotonic + timeout_seconds
    cancel_marker = job_dir / "cancel-requested"
    scratch = _private_scratch(job_dir)
    entries: list[dict[str, Any]] = []
    reasons: list[str] = []
    cancelled = False
    blocked = False
    try:
        with _b1().plan_lock(descriptor["plan_id"]):
            b1_state = _b1().replay_plan_state_locked(descriptor["plan_id"])
            static = d._require_strict_plan(b1_state)
            current = d._require_consensus(b1_state, descriptor["step_id"])
            constraints, candidate_sha256 = d._candidate_constraints(
                b1_state, descriptor["step_id"]
            )
            journal = d._replay_journal(descriptor["plan_id"])
            intent = next(
                (
                    event
                    for event in journal["validation_intents"]
                    if event["payload"].get("job_id") == descriptor["job_id"]
                ),
                None,
            )
            if intent is None:
                raise _error("Validation intent disappeared before execution")
            claim = next(
                (
                    event
                    for event in journal["validation_claims"]
                    if event["payload"].get("job_id") == descriptor["job_id"]
                ),
                None,
            )
            if claim is None:
                raise _error("Validation claim disappeared before execution")
            contract, contract_event = _contract_for_current(
                descriptor["plan_id"],
                journal,
                descriptor["step_id"],
                current["cycle"],
                candidate_sha256,
            )
            policy = _policy_from_contract(contract)
            workspace = Path(meta["workspace"])
            source = _latest_writer_source_locked(
                descriptor["plan_id"],
                journal,
                descriptor["step_id"],
                current["cycle"],
                candidate_sha256,
                contract_event["payload"]["contract_digest"],
            )
            source_binding = {
                "source_attempt_id": source["attempt_id"],
                "source_job_id": source["job_id"],
                "source_evidence_digest": source["evidence_digest"],
                "source_final_snapshot_digest": source["final_snapshot_digest"],
                "source_kind": source["source_kind"],
                "generation": source["generation"],
                "candidate_sha256": candidate_sha256,
                "contract_digest": contract_event["payload"]["contract_digest"],
                "policy_digest": _policy_digest(policy),
                "validation_id": descriptor["validation_id"],
                "batch_id": descriptor["batch_id"],
                "claim_digest": claim["payload"]["claim_digest"],
                "base_snapshot_digest": claim["payload"]["base_snapshot_digest"],
            }
    except Exception as exc:
        reasons.append(f"validation preflight failed closed: {exc}")
        evidence = {
            "version": VALIDATION_BATCH_VERSION,
            "kind": "d2_validation_evidence",
            "validation_id": descriptor.get("validation_id"),
            "batch_id": descriptor.get("batch_id"),
            "job_id": descriptor.get("job_id"),
            "binding": None,
            "entries": entries,
            "cancelled": False,
            "blocked": True,
            "reasons": reasons,
            "started_at": started_at,
            "finished_at": _now(),
            "post_snapshot_digest": None,
            "enforcement": {"available": False, "reason": str(exc)},
        }
        _write_json(job_dir / "validation-evidence.json", evidence)
        _write_json(
            job_dir / "result.json",
            {
                "state": "failed",
                "started_at": started_at,
                "finished_at": _now(),
                "duration_seconds": round(time.monotonic() - start_monotonic, 6),
                "exit_code": 2,
                "timed_out": False,
                "scope_violations": [],
                "usage_summary": None,
                "validation_outcome": "blocked",
            },
        )
        return 1
    redactor = _review_redactor()
    bwrap_path = shutil.which("bwrap") or ""
    enforcement_reason = (
        ""
        if bwrap_path
        else "bubblewrap executable is unavailable; unsupported isolation is blocked"
    )
    for entry in policy["entries"]:
        if cancel_marker.exists():
            cancelled = True
            reasons.append("validation cancellation was requested")
            break
        if time.monotonic() >= overall_deadline:
            reasons.append("the validation job exceeded its overall timeout")
            cancelled = False
            break
        result = _execute_validation_entry(
            entry,
            workspace=workspace,
            contract=contract,
            scratch=scratch,
            cancel_marker=cancel_marker,
            overall_deadline=overall_deadline,
            job_dir=job_dir,
            redactor=redactor,
        )
        entries.append(result)
        if not result["passed"] and entry["mandatory"]:
            if result["ro_mode"] == "not_started":
                blocked = True
            reasons.extend(
                f"{entry['invocation_id']}: {reason}" for reason in result["reasons"]
            )
        if result["cancelled"]:
            # Cancellation is a global batch gate even for optional entries.
            cancelled = True
            break
        if result["timed_out"] and entry["mandatory"]:
            break
    try:
        with _b1().plan_lock(descriptor["plan_id"]):
            current_snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
            post_digest = d._snapshot_digest(current_snapshot)
    except Exception as exc:
        post_digest = None
        reasons.append(f"post-validation source observation failed closed: {exc}")
        blocked = True
    drift = post_digest != claim["payload"]["base_snapshot_digest"]
    if drift:
        reasons.append(
            "the canonical source changed during validation; a validator may "
            "not mutate the repository"
        )
    evidence = {
        "version": VALIDATION_BATCH_VERSION,
        "kind": "d2_validation_evidence",
        "validation_id": descriptor["validation_id"],
        "batch_id": descriptor["batch_id"],
        "job_id": descriptor["job_id"],
        "binding": source_binding,
        "entries": entries,
        "cancelled": cancelled,
        "blocked": blocked,
        "reasons": reasons[:50],
        "started_at": started_at,
        "finished_at": _now(),
        "post_snapshot_digest": post_digest,
        "source_drift": drift,
        "enforcement": {
            "available": bool(entries)
            and all(entry.get("ro_mode") == "kernel_ro" for entry in entries),
            "reason": enforcement_reason,
            "bwrap": bwrap_path,
            "contexts": sorted({entry["context"] for entry in policy["entries"]}),
            "masks": (entries[0].get("sandbox") or {}).get("masks", [])
            if entries
            else [],
            "mount_order": (entries[0].get("sandbox") or {}).get("mount_order", [])
            if entries
            else [],
            "cap_drop": (entries[0].get("sandbox") or {}).get("cap_drop")
            if entries
            else None,
            "observed_contexts": [
                {
                    "invocation_id": entry["invocation_id"],
                    "context": entry["context"],
                    "observation": entry.get("context_observation"),
                }
                for entry in entries
            ],
            "credential_file_absence": False,
            "honest_limits": [
                "privileged wrappers can reach host /proc, parent process and "
                "network state",
                "read-only enforcement is an accidental-write guard, not "
                "adversarial confinement",
                "known credential-root masks are not a whole-host secret closure; "
                "environment filtering is not credential-file absence",
            ],
        },
    }
    encoded = _canonical_bytes(evidence)
    if len(encoded) > MAX_VALIDATION_EVIDENCE_BYTES:
        reasons.append("validation evidence exceeds its bounded size")
        evidence["reasons"] = reasons[:50]
    _write_json(job_dir / "validation-evidence.json", evidence)
    state = "cancelled" if cancelled else "succeeded"
    _write_json(
        job_dir / "result.json",
        {
            "state": state,
            "started_at": started_at,
            "finished_at": _now(),
            "duration_seconds": round(time.monotonic() - start_monotonic, 6),
            "exit_code": 0 if state == "succeeded" else 130,
            "timed_out": False,
            "cancelled": cancelled,
            "scope_violations": [],
            "usage_summary": None,
            "validation_outcome": (
                "passed"
                if entries
                and all(entry["passed"] for entry in entries)
                and not reasons
                else "failed"
            ),
        },
    )
    return 0 if state == "succeeded" else 1


# ---------------------------------------------------------------------------
# Validation finalization and durable batch results
# ---------------------------------------------------------------------------


def _capture_evidence(
    plan_id: str, record: Any, label: str
) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    path_value = record.get("path")
    if not isinstance(path_value, str) or not path_value:
        _fail(f"{label} has no capture path")
    path = Path(path_value)
    d = _d()
    try:
        info = os.lstat(path)
    except OSError as exc:
        _fail(f"{label} capture is missing: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail(f"{label} capture is not a stable regular file")
    if info.st_size > MAX_CAPTURE_BYTES:
        _fail(f"{label} capture exceeds the approved capture bound")
    data = path.read_bytes()
    if _sha256_bytes(data) != record.get("sha256"):
        _fail(f"{label} capture bytes do not match their recorded digest")
    if len(data) != record.get("bytes"):
        _fail(f"{label} capture size does not match its record")
    # Defence in depth: the worker already sanitized the capture before writing
    # it. Re-apply the shared C redactor and persist only redacted bytes; a raw
    # credential echo must never reach a blob or head_text surface even if the
    # earlier sanitization missed a token-shaped value.
    redactor = _review_redactor()
    sanitized = _sanitize_capture(
        data, overflow=False, redactor=redactor
    )
    if sanitized != data:
        temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        temp.write_bytes(sanitized)
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    blob_sha = d._publish_blob(plan_id, sanitized, f"{label} capture")
    return {
        "sha256": _sha256_bytes(sanitized),
        "bytes": len(sanitized),
        "blob_sha256": blob_sha,
        "head_text": sanitized[:4_096].decode("utf-8", "replace"),
        "redacted_on_persist": sanitized != data,
    }


def _verify_validation_evidence(
    plan_id: str,
    evidence: dict[str, Any],
    *,
    intent: dict[str, Any],
    claim: dict[str, Any],
    policy: dict[str, Any],
    final_check: dict[str, Any],
    meta: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Re-validate worker evidence against policy, claim, process and receipt."""
    d = _d()
    reasons: list[str] = []
    payload = intent["payload"]
    if evidence.get("version") != VALIDATION_BATCH_VERSION:
        _fail("validation evidence version is unsupported")
    if evidence.get("validation_id") != payload["validation_id"]:
        _fail("validation evidence names another validation")
    if evidence.get("batch_id") != payload["batch_id"]:
        _fail("validation evidence names another batch")
    if evidence.get("job_id") != payload["job_id"]:
        _fail("validation evidence names another job")
    binding = evidence.get("binding")
    if not isinstance(binding, dict):
        _fail("validation evidence has no source binding")
    expected_binding = {
        "source_attempt_id": payload["source_attempt_id"],
        "source_job_id": payload["source_job_id"],
        "source_evidence_digest": payload["source_evidence_digest"],
        "source_final_snapshot_digest": payload["source_final_snapshot_digest"],
        "source_kind": payload["source_kind"],
        "generation": payload["generation"],
        "candidate_sha256": payload["candidate_sha256"],
        "contract_digest": payload["contract_digest"],
        "policy_digest": payload["policy_digest"],
        "validation_id": payload["validation_id"],
        "batch_id": payload["batch_id"],
        "claim_digest": claim["payload"]["claim_digest"],
        "base_snapshot_digest": claim["payload"]["base_snapshot_digest"],
    }
    if binding != expected_binding:
        _fail("validation evidence source/claim binding changed")
    entries = evidence.get("entries")
    if not isinstance(entries, list):
        _fail("validation evidence has no entry list")
    known = {
        entry["invocation_id"]: entry for entry in policy["entries"]
    }
    seen: list[str] = []
    normalized_entries: list[dict[str, Any]] = []
    total = {"collected": 0, "run": 0, "passed": 0, "failures": 0, "errors": 0, "skips": 0}
    for index, entry in enumerate(entries):
        label = f"validation evidence entry {index}"
        if not isinstance(entry, dict):
            _fail(f"{label} is not an object")
        invocation_id = entry.get("invocation_id")
        if invocation_id not in known:
            _fail(f"{label} names an invocation outside the frozen policy")
        if invocation_id in seen:
            _fail(f"{label} duplicates invocation {invocation_id}")
        seen.append(invocation_id)
        policy_entry = known[invocation_id]
        if entry.get("argv") != policy_entry["argv"]:
            _fail(f"{label} argv changed after the ballot")
        if entry.get("masked_argv_sha256") != _digest(policy_entry["argv"]):
            _fail(f"{label} argv digest changed")
        if entry.get("context") != policy_entry["context"]:
            _fail(f"{label} context changed after the ballot")
        if entry.get("ro_enforcement") != policy_entry["ro_enforcement"]:
            _fail(f"{label} RO enforcement changed after the ballot")
        if entry.get("cwd") != str(
            (Path(meta["workspace"]) / policy_entry["cwd"]).resolve()
        ):
            reasons.append(f"{invocation_id}: contained cwd changed after the ballot")
        if entry.get("environment_policy") != policy_entry["environment_policy"]:
            _fail(f"{label} environment policy changed")
        if entry.get("evidence_kind") != policy_entry["evidence"]["kind"]:
            _fail(f"{label} evidence kind changed")
        if entry.get("expected_exit") != policy_entry["expected_exit"]:
            _fail(f"{label} expected exit changed")
        counts = entry.get("counts")
        if counts is not None and policy_entry["evidence"]["kind"] == "command_check":
            reasons.append(
                f"{invocation_id}: command_check evidence cannot claim test counts"
            )
        mandatory_entry = bool(policy_entry["mandatory"])
        if counts is not None:
            _validate_counts(counts, f"{label}.counts")
            if mandatory_entry:
                # Required coverage floors and totals count only mandatory
                # entries; an optional probe never satisfies or inflates them.
                for key in total:
                    total[key] += counts[key]
        structured = entry.get("structured")
        if policy_entry["evidence"]["kind"] == "structured_unittest":
            if not isinstance(structured, dict):
                reasons.append(
                    f"{invocation_id}: structured evidence is missing"
                )
            else:
                if structured.get("counts") != counts:
                    reasons.append(
                        f"{invocation_id}: structured counts are contradictory"
                    )
                if structured.get("adapter_id") != DEFAULT_ADAPTER_ID:
                    reasons.append(
                        f"{invocation_id}: structured adapter identity is wrong"
                    )
                if structured.get("run_id") != entry.get("run_id"):
                    reasons.append(
                        f"{invocation_id}: structured run identity is missing"
                    )
                if mandatory_entry and not entry.get("passed"):
                    reasons.append(
                        f"{invocation_id}: mandatory structured invocation did "
                        "not pass"
                    )
            if counts is None:
                reasons.append(
                    f"{invocation_id}: structured counts are missing"
                )
            elif mandatory_entry:
                evidence_policy = policy_entry["evidence"]
                if counts["collected"] < evidence_policy["min_collected"]:
                    reasons.append(
                        f"{invocation_id}: collected count is below the floor"
                    )
                if counts["run"] < evidence_policy["min_run"]:
                    reasons.append(
                        f"{invocation_id}: run count is below the floor"
                    )
                if counts["skips"]:
                    reasons.append(
                        f"{invocation_id}: mandatory invocation recorded skips"
                    )
                if counts["failures"] or counts["errors"]:
                    reasons.append(
                        f"{invocation_id}: mandatory invocation recorded failures "
                        "or errors"
                    )
        elif mandatory_entry and not entry.get("passed"):
            reasons.append(
                f"{invocation_id}: command_check invocation did not pass"
            )
        expected_exit = policy_entry["expected_exit"]
        actual_exit = entry.get("exit_code")
        if entry.get("passed") is True:
            # A strict checker never trusts a pass echo that contradicts the
            # actual process/RO evidence, for mandatory or optional entries.
            if entry.get("timed_out") or entry.get("cancelled") or entry.get(
                "overflow"
            ):
                reasons.append(
                    f"{invocation_id}: a pass claim contradicts "
                    "timeout/cancellation/overflow evidence"
                )
            if (
                policy_entry["evidence"]["kind"] == "command_check"
                and actual_exit != expected_exit
            ):
                reasons.append(
                    f"{invocation_id}: a pass claim contradicts the actual exit "
                    f"code {actual_exit!r}"
                )
            if entry.get("ro_mode") != "kernel_ro":
                reasons.append(
                    f"{invocation_id}: a pass claim contradicts the non-kernel "
                    "read-only mode"
                )
        if mandatory_entry:
            # Mandatory entries must have actually run under kernel read-only
            # enforcement and satisfy the frozen expected exit. Optional probes
            # may be skipped/not-started and remain visible without satisfying
            # mandatory coverage.
            if entry.get("ro_mode") != "kernel_ro":
                reasons.append(
                    f"{invocation_id}: mandatory invocation did not run under "
                    "actual kernel read-only enforcement"
                )
            if (
                policy_entry["evidence"]["kind"] == "command_check"
                and actual_exit != expected_exit
            ):
                reasons.append(
                    f"{invocation_id}: actual exit code {actual_exit!r} does "
                    f"not match the frozen expected exit {expected_exit!r}"
                )
            if entry.get("timed_out"):
                reasons.append(f"{invocation_id}: invocation timed out")
        if entry.get("cancelled"):
            reasons.append(f"{invocation_id}: invocation was cancelled")
        if entry.get("overflow"):
            reasons.append(f"{invocation_id}: capture overflowed")
        stdout = _capture_evidence(
            plan_id, entry.get("stdout"), f"{invocation_id} stdout"
        )
        stderr = _capture_evidence(
            plan_id, entry.get("stderr"), f"{invocation_id} stderr"
        )
        normalized_entries.append(
            {
                "invocation_id": invocation_id,
                "label": policy_entry["label"],
                "purpose": policy_entry["purpose"],
                "argv": list(policy_entry["argv"]),
                "argv_sha256": _digest(list(policy_entry["argv"])),
                "cwd": entry.get("cwd"),
                "context": policy_entry["context"],
                "ro_enforcement": policy_entry["ro_enforcement"],
                "ro_mode": entry.get("ro_mode"),
                "environment_policy": policy_entry["environment_policy"],
                "environment": entry.get("environment"),
                "executable": entry.get("executable"),
                "evidence_kind": policy_entry["evidence"]["kind"],
                "exit_code": entry.get("exit_code"),
                "expected_exit": policy_entry["expected_exit"],
                "timed_out": bool(entry.get("timed_out")),
                "cancelled": bool(entry.get("cancelled")),
                "overflow": bool(entry.get("overflow")),
                "duration_seconds": entry.get("duration_seconds"),
                "stdout": stdout,
                "stderr": stderr,
                "counts": counts,
                "structured": structured,
                "passed": bool(entry.get("passed")) and not any(
                    reason.startswith(invocation_id + ":")
                    for reason in reasons
                ),
                "reasons": list(entry.get("reasons") or [])[:MAX_ENTRY_REASONS],
            }
        )
    mandatory = [
        entry for entry in policy["entries"] if entry["mandatory"]
    ]
    mandatory_ids = [entry["invocation_id"] for entry in mandatory]
    declared_ids = [entry["invocation_id"] for entry in policy["entries"]]
    if seen != declared_ids:
        reasons.append(
            "the executed invocation order or coverage does not match the "
            "frozen policy; every declared entry, mandatory and optional, must "
            "be recorded exactly once in order"
        )
    if evidence.get("cancelled"):
        reasons.append("the validation batch was cancelled")
    if evidence.get("blocked"):
        reasons.append("the validation batch hit an unsupported context")
    if evidence.get("source_drift"):
        reasons.append("the canonical source changed during validation")
    if evidence.get("post_snapshot_digest") != claim["payload"]["base_snapshot_digest"]:
        reasons.append("the post-validation source does not match the claim base")
    if final_check.get("state") != "clean":
        reasons.append(
            f"the supervisor final check is {final_check.get('state')!r}, not clean"
        )
    report = final_check.get("report")
    if not isinstance(report, dict) or not report.get("supported"):
        reasons.append("the supervisor final check is unsupported")
    else:
        if report.get("head_changed") or report.get("branch_changed"):
            reasons.append("repository HEAD or branch changed during validation")
        if report.get("index_changed"):
            reasons.append("the Git index changed during validation")
        if report.get("count"):
            reasons.append(
                f"validation changed {report.get('count')} observed paths; "
                "validators may not mutate the repository"
            )
    if meta.get("git_baseline") is not None:
        if d._snapshot_digest(meta.get("git_baseline") or {}) != claim["payload"][
            "base_snapshot_digest"
        ]:
            reasons.append("the B2 job baseline does not match the validation claim")
    return {
        "entries": normalized_entries,
        "counts": total,
        "reasons": reasons,
        "mandatory_ids": mandatory_ids,
    }


def finalize_validation(
    *, plan_id: str, step_id: str, job_id: str | None = None
) -> dict[str, Any]:
    """Freeze one complete validation batch from actual B2/process evidence."""
    d = _d()
    selected_job = job_id
    if selected_job is None:
        journal = d._replay_journal(plan_id)
        intents = [
            event
            for event in journal["validation_intents"]
            if event["step_id"] == step_id
        ]
        if not intents:
            _fail("No D2 validation intent exists to finalize")
        selected_job = intents[-1]["payload"]["job_id"]
    job_path = _jobs_dir() / selected_job
    if (job_path / "meta.json").is_file():
        d.wait_for_job_evidence_settled(selected_job)
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        journal = d._replay_journal(plan_id)
        intent = next(
            (
                event
                for event in journal["validation_intents"]
                if event["payload"].get("job_id") == selected_job
            ),
            None,
        )
        if intent is None or intent["step_id"] != step_id:
            _fail(f"No D2 validation intent exists for job {selected_job}")
        payload = intent["payload"]
        if payload["candidate_sha256"] != candidate_sha256:
            _fail("Validation intent is stale against the current candidate")
        if payload["cycle"] != current["cycle"]:
            _fail("Validation intent belongs to another B1 cycle")
        existing = next(
            (
                event
                for event in journal["validation_results"]
                if event["payload"].get("job_id") == selected_job
            ),
            None,
        )
        if existing is not None:
            d._read_blob(
                plan_id,
                existing["payload"]["evidence_blob_sha256"],
                "validation evidence",
            )
            return {
                "plan_id": plan_id,
                "step_id": step_id,
                "validation_id": existing["payload"]["validation_id"],
                "job_id": selected_job,
                "classification": existing["payload"]["classification"],
                "counts": existing["payload"]["counts"],
                "reasons": existing["payload"]["reasons"],
                "idempotent": True,
            }
        claim = next(
            (
                event
                for event in journal["validation_claims"]
                if event["payload"].get("job_id") == selected_job
            ),
            None,
        )
        if claim is None:
            _fail(
                "The validation job has no protected post-lease claim; ownership "
                "cannot be proven"
            )
        contract, contract_event = _contract_for_current(
            plan_id, journal, step_id, current["cycle"], candidate_sha256
        )
        policy = _policy_from_contract(contract)
        if payload["policy_digest"] != _policy_digest(policy):
            _fail("Validation policy changed after the intent")
        if not job_path.is_dir():
            _fail("The validation job directory is absent")
        meta = _read_json(job_path / "meta.json")
        try:
            completion = d._b2_completion(meta, job_path)
        except Exception as exc:
            _fail(f"Validation B2 completion evidence is unavailable: {exc}")
        if completion.get("kind") == "failed_admission":
            evidence = {
                "version": VALIDATION_BATCH_VERSION,
                "kind": "d2_validation_evidence",
                "validation_id": payload["validation_id"],
                "batch_id": payload["batch_id"],
                "job_id": selected_job,
                "binding": None,
                "entries": [],
                "cancelled": False,
                "blocked": True,
                "reasons": ["B2 recorded a failed admission before any validator ran"],
                "post_snapshot_digest": None,
                "source_drift": False,
                "enforcement": {"available": False, "reason": "failed admission"},
            }
            evidence_digest = _digest(evidence)
            evidence_blob, _ = d._publish_json_blob(
                plan_id, evidence, "failed-admission validation evidence"
            )
            return _record_validation_result(
                plan_id,
                static,
                current,
                step_id,
                intent,
                claim,
                {
                    "classification": "blocked",
                    "state": "missing",
                    "entries": [],
                    "counts": {
                        "collected": 0,
                        "run": 0,
                        "passed": 0,
                        "failures": 0,
                        "errors": 0,
                        "skips": 0,
                    },
                    "reasons": list(evidence["reasons"]),
                    "evidence_digest": evidence_digest,
                    "evidence_blob_sha256": evidence_blob,
                    "job_meta_sha256": None,
                    "job_result_sha256": None,
                    "final_check_sha256": None,
                    "receipt_sha256": None,
                },
            )
        if completion.get("kind") != "finalized":
            _fail(
                "The validation job is not durably finalized ("
                + str(completion.get("kind"))
                + "): "
                + str(completion.get("reason"))
            )
        final_check = completion.get("final_check")
        if not isinstance(final_check, dict):
            _fail("The validation B2 completion receipt has no final check")
        declared_evidence = final_check.get("evidence_files")
        if not isinstance(declared_evidence, dict):
            _fail(
                "The B2 completion receipt does not bind the validation evidence "
                "file; tampering cannot be excluded"
            )
        proofs: dict[str, Any] = {}
        missing: list[str] = []
        for name in VALIDATION_PROOF_FILES:
            path = job_path / name
            if not path.is_file():
                missing.append(name)
                continue
            data = path.read_bytes()
            proofs[name] = {
                "sha256": _sha256_bytes(data),
                "bytes": len(data),
            }
        bound = declared_evidence.get("validation-evidence.json")
        if bound is not None and "validation-evidence.json" in missing:
            # The completed receipt itself bound the evidence file; a later
            # deletion is tampering, not a torn publication.
            _fail(
                "The B2 completion receipt binds validation-evidence.json but the "
                "file is now missing; the proof was removed after finalization"
            )
        if "validation-evidence.json" not in missing and (
            not isinstance(bound, dict)
            or bound.get("sha256")
            != proofs["validation-evidence.json"]["sha256"]
            or bound.get("bytes") != proofs["validation-evidence.json"]["bytes"]
        ):
            _fail(
                "The validation evidence file does not match the digest bound by "
                "the B2 completion receipt"
            )
        job_result = (
            None
            if "result.json" in missing
            else _read_json(job_path / "result.json")
        )
        if missing or job_result is None:
            # The lease is fully drained and can never publish more proof, but
            # one or more proof files were never written. This is a real dead
            # batch, not a live validator: record a durable negative result so
            # the projection cannot stay VALIDATING forever. No positive
            # evidence is recreated and no old approval is reused.
            reasons = []
            if missing:
                reasons.append(
                    "the fully drained validation batch is missing proof files: "
                    + ", ".join(missing)
                )
            if job_result is None:
                reasons.append(
                    "the validation result record was never published"
                )
            elif job_result.get("state") not in {"succeeded", "cancelled"}:
                reasons.append(
                    "the validator process did not complete: "
                    f"{job_result.get('state')!r}"
                )
            reasons.append(
                "the dead batch can only be recorded as a failed/blocked result; "
                "a fresh validation batch against the unchanged source is the "
                "only supported retry"
            )
            cancelled = (
                isinstance(job_result, dict)
                and job_result.get("state") == "cancelled"
            )
            failure_evidence = {
                "version": VALIDATION_BATCH_VERSION,
                "kind": "d2_validation_failure",
                "validation_id": payload["validation_id"],
                "batch_id": payload["batch_id"],
                "job_id": selected_job,
                "binding": None,
                "entries": [],
                "cancelled": cancelled,
                "blocked": True,
                "reasons": reasons[:50],
                "missing_proofs": list(missing),
                "proofs": proofs,
                "job_result": job_result,
                "evaluated_at": _now(),
            }
            failure_blob, _ = d._publish_json_blob(
                plan_id, failure_evidence, "dead validation batch evidence"
            )
            return _record_validation_result(
                plan_id,
                static,
                current,
                step_id,
                intent,
                claim,
                {
                    "classification": "cancelled" if cancelled else "blocked",
                    "state": "missing",
                    "entries": [],
                    "counts": {
                        "collected": 0,
                        "run": 0,
                        "passed": 0,
                        "failures": 0,
                        "errors": 0,
                        "skips": 0,
                    },
                    "reasons": reasons[:50],
                    "evidence_digest": _digest(failure_evidence),
                    "evidence_blob_sha256": failure_blob,
                    "job_meta_sha256": (proofs.get("meta.json") or {}).get(
                        "sha256"
                    ),
                    "job_result_sha256": (proofs.get("result.json") or {}).get(
                        "sha256"
                    ),
                    "final_check_sha256": (
                        proofs.get("final-check.json") or {}
                    ).get("sha256"),
                    "receipt_sha256": (
                        proofs.get("lease-completion.json") or {}
                    ).get("sha256"),
                },
            )
        evidence = _read_json(job_path / "validation-evidence.json")
        if job_result.get("state") not in {"succeeded", "cancelled"}:
            failed_record = {
                "classification": "cancelled"
                if job_result.get("state") == "cancelled"
                else "failed",
                "state": "missing",
                "entries": [],
                "counts": {
                    "collected": 0,
                    "run": 0,
                    "passed": 0,
                    "failures": 0,
                    "errors": 0,
                    "skips": 0,
                },
                "reasons": [
                    "the validator process did not complete: "
                    f"{job_result.get('state')!r}"
                ],
                "evidence_digest": _digest(evidence),
                "evidence_blob_sha256": d._publish_json_blob(
                    plan_id, evidence, "invalid validator evidence"
                )[0],
                "job_meta_sha256": proofs["meta.json"]["sha256"],
                "job_result_sha256": proofs["result.json"]["sha256"],
                "final_check_sha256": proofs["final-check.json"]["sha256"],
                "receipt_sha256": proofs["lease-completion.json"]["sha256"],
            }
            return _record_validation_result(
                plan_id, static, current, step_id, intent, claim, failed_record
            )
        normalized = _verify_validation_evidence(
            plan_id,
            evidence,
            intent=intent,
            claim=claim,
            policy=policy,
            final_check=final_check,
            meta=meta,
        )
        reasons = list(normalized["reasons"])
        cancelled = bool(evidence.get("cancelled")) or job_result.get("state") == "cancelled"
        blocked = bool(evidence.get("blocked"))
        overflow = any(entry.get("overflow") for entry in normalized["entries"])
        source_drift = bool(evidence.get("source_drift"))
        policy_by_id = {
            entry["invocation_id"]: entry for entry in policy["entries"]
        }
        mandatory_passed = all(
            entry["passed"]
            for entry in normalized["entries"]
            if policy_by_id[entry["invocation_id"]]["mandatory"]
        )
        passed = (
            not reasons
            and not cancelled
            and not blocked
            and not overflow
            and not source_drift
            and mandatory_passed
        )
        classification = (
            "passed"
            if passed
            else "cancelled"
            if cancelled
            else "blocked"
            if blocked
            else "overflow"
            if overflow
            else "failed"
        )
        full_evidence = {
            "version": VALIDATION_BATCH_VERSION,
            "kind": "d2_validation_result",
            "validation_id": payload["validation_id"],
            "batch_id": payload["batch_id"],
            "job_id": selected_job,
            "policy": policy,
            "policy_digest": payload["policy_digest"],
            "source": {
                key: payload[key]
                for key in (
                    "source_attempt_id",
                    "source_job_id",
                    "source_evidence_digest",
                    "source_final_snapshot_digest",
                    "source_kind",
                    "generation",
                )
            },
            "claim": claim["payload"],
            "job_meta": meta,
            "job_result": job_result,
            "final_check": final_check,
            "validation_evidence": normalized,
            "proofs": proofs,
            "classification": classification,
            "reasons": (reasons + list(evidence.get("reasons") or []))[:50],
            "evaluated_at": _now(),
        }
        evidence_digest = _digest(full_evidence)
        evidence_blob, _ = d._publish_json_blob(
            plan_id, full_evidence, "D2 validation batch evidence"
        )
        return _record_validation_result(
            plan_id,
            static,
            current,
            step_id,
            intent,
            claim,
            {
                "classification": classification,
                "state": (
                    "clean"
                    if final_check.get("state") == "clean"
                    else "violations"
                    if final_check.get("state") == "violations"
                    else "error"
                ),
                "entries": [
                    {
                        "invocation_id": entry["invocation_id"],
                        "evidence_kind": entry["evidence_kind"],
                        "exit_code": entry["exit_code"],
                        "timed_out": entry["timed_out"],
                        "cancelled": entry["cancelled"],
                        "overflow": entry["overflow"],
                        "passed": entry["passed"],
                        "stdout_sha256": (
                            (entry["stdout"] or {}).get("sha256") or ZERO_DIGEST
                        ),
                        "stderr_sha256": (
                            (entry["stderr"] or {}).get("sha256") or ZERO_DIGEST
                        ),
                        "stdout_bytes": (entry["stdout"] or {}).get("bytes") or 0,
                        "stderr_bytes": (entry["stderr"] or {}).get("bytes") or 0,
                        "counts": entry["counts"],
                        "context": entry["context"],
                        "ro_enforcement": entry["ro_enforcement"],
                        "reasons": entry["reasons"][:MAX_ENTRY_REASONS],
                    }
                    for entry in normalized["entries"]
                ],
                "counts": normalized["counts"],
                "reasons": (reasons + list(evidence.get("reasons") or []))[:50],
                "evidence_digest": evidence_digest,
                "evidence_blob_sha256": evidence_blob,
                "job_meta_sha256": proofs["meta.json"]["sha256"],
                "job_result_sha256": proofs["result.json"]["sha256"],
                "final_check_sha256": proofs["final-check.json"]["sha256"],
                "receipt_sha256": proofs["lease-completion.json"]["sha256"],
            },
        )


def _record_validation_result(
    plan_id: str,
    static: dict[str, Any],
    current: dict[str, Any],
    step_id: str,
    intent: dict[str, Any],
    claim: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    d = _d()
    payload = intent["payload"]
    state = result.get("state")
    result_payload = {
        "version": VALIDATION_BATCH_VERSION,
        "validation_id": payload["validation_id"],
        "batch_id": payload["batch_id"],
        "job_id": payload["job_id"],
        "cycle": payload["cycle"],
        "candidate_sha256": payload["candidate_sha256"],
        "contract_digest": payload["contract_digest"],
        "policy_digest": payload["policy_digest"],
        "classification": result["classification"],
        "state": state,
        "entries": result["entries"],
        "counts": result["counts"],
        "reasons": result["reasons"],
        "evidence_digest": result["evidence_digest"],
        "evidence_blob_sha256": result["evidence_blob_sha256"],
        "job_meta_sha256": result["job_meta_sha256"],
        "job_result_sha256": result["job_result_sha256"],
        "final_check_sha256": result["final_check_sha256"],
        "receipt_sha256": result["receipt_sha256"],
        "source_attempt_id": payload["source_attempt_id"],
        "source_evidence_digest": payload["source_evidence_digest"],
        "source_final_snapshot_digest": payload["source_final_snapshot_digest"],
        "generation": payload["generation"],
    }
    events = _append(
        plan_id,
        [
            _event_spec(
                d.TYPE_VALIDATION_RESULT,
                step_id,
                payload["cycle"],
                result_payload,
            )
        ],
        "validation_result",
        plan_id=plan_id,
        step_id=step_id,
        validation_id=payload["validation_id"],
        evidence_digest=result["evidence_digest"],
    )
    return {
        "plan_id": plan_id,
        "step_id": step_id,
        "validation_id": payload["validation_id"],
        "job_id": payload["job_id"],
        "classification": result["classification"],
        "counts": result["counts"],
        "reasons": result["reasons"],
        "event_id": events[0]["event_id"],
        "evidence_digest": result["evidence_digest"],
        "evidence_blob_sha256": result["evidence_blob_sha256"],
        "idempotent": False,
        "closed_routes": dict(CLOSED_D2_ROUTES),
    }


# ---------------------------------------------------------------------------
# Active-Codex preflight and review sessions
# ---------------------------------------------------------------------------


def authorize_validation_preflight(
    *,
    plan_id: str,
    step_id: str,
    invocation_id: str,
    leader: str,
) -> dict[str, Any]:
    """Record the active leader's confirmation of one voted systems invocation."""
    leader = _require_text(leader, "leader identity", minimum=2)
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        if constraints.get("version") != d.CONTRACT_VERSION_D2:
            _fail("Preflight requires an approved version 2 candidate policy")
        journal = d._replay_journal(plan_id)
        contract, contract_event = _contract_for_current(
            plan_id, journal, step_id, current["cycle"], candidate_sha256
        )
        policy = _policy_from_contract(contract)
        entry = next(
            (
                item
                for item in policy["entries"]
                if item["invocation_id"] == invocation_id
            ),
            None,
        )
        if entry is None:
            _fail(f"Invocation {invocation_id!r} is not in the voted policy")
        if entry["context"] != "systems_trusted":
            _fail(
                "Preflight is only valid for an already voted systems_trusted "
                "invocation; it can never add or widen an invocation"
            )
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        workspace = Path(static["canonical_workspace"])
        snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
        _require_source_current(plan_id, source, snapshot, "preflight")
        _require_no_live_writer(d._repo_identity(static))
        payload = {
            "version": VALIDATION_BATCH_VERSION,
            "invocation_id": invocation_id,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "policy_digest": _policy_digest(policy),
            "argv_sha256": _digest(list(entry["argv"])),
            "cwd": entry["cwd"],
            "purpose_sha256": _sha256_bytes(entry["purpose"].encode("utf-8")),
            "source_attempt_id": source["attempt_id"],
            "source_final_snapshot_digest": d._snapshot_digest(snapshot),
            "user_baseline_digest": source["user_baseline_digest"],
            "privilege_subset": list(SYSTEMS_PRIVILEGE_SUBSET),
            "leader": leader,
            "issuer": _process_identity(),
            "contract_sequence": contract_event["sequence"],
        }
        existing = next(
            (
                event
                for event in reversed(journal["validation_preflights"])
                if event["payload"] == payload
            ),
            None,
        )
        if existing is not None:
            return {
                "plan_id": plan_id,
                "step_id": step_id,
                "invocation_id": invocation_id,
                "preflight_event_id": existing["event_id"],
                "idempotent": True,
            }
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_VALIDATION_PREFLIGHT, step_id, current["cycle"], payload)],
            "validation_preflight",
            plan_id=plan_id,
            step_id=step_id,
            invocation_id=invocation_id,
            leader=leader,
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "invocation_id": invocation_id,
            "preflight_event_id": events[0]["event_id"],
            "idempotent": False,
        }


def _review_bundle(
    plan_id: str,
    b1_state: dict[str, Any],
    journal: dict[str, Any],
    step_id: str,
    current: dict[str, Any],
    candidate_sha256: str,
    contract: dict[str, Any],
    contract_event: dict[str, Any],
    source: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    """Deterministic author-review input bundle derived from immutable facts."""
    d = _d()
    step_b1 = b1_state["steps"][step_id]
    candidate_doc = (step_b1.get("candidate") or {}).get("candidate") or {}
    evidence = d._load_evidence_blob(
        plan_id,
        source["evidence_blob_sha256"],
        source["evidence_digest"],
        "review source evidence",
    )
    delta = evidence.get("delta") if isinstance(evidence, dict) else None
    diff_blob = delta.get("diff_blob_sha256") if isinstance(delta, dict) else None
    diff_bytes = (
        d._read_blob(plan_id, diff_blob, "review cumulative diff")
        if diff_blob
        else b""
    )
    return {
        "version": 1,
        "kind": "d2_review_input_bundle",
        "plan_id": plan_id,
        "step_id": step_id,
        "cycle": current["cycle"],
        "candidate_sha256": candidate_sha256,
        "contract_digest": contract_event["payload"]["contract_digest"],
        "objective": contract["objective"],
        "why": contract["why"],
        "final_design": candidate_doc.get("final_design"),
        "important_decisions": list(candidate_doc.get("important_decisions") or []),
        "completion_contract": contract,
        "validation_policy": _policy_from_contract(contract),
        "source": {
            key: source[key]
            for key in (
                "source_kind",
                "attempt_id",
                "job_id",
                "generation",
                "evidence_digest",
                "evidence_blob_sha256",
                "final_snapshot_digest",
                "cumulative_changed_paths",
                "cumulative_changed_digest",
                "original_base_snapshot_digest",
                "user_baseline_digest",
            )
        },
        "author_report": source["author_report"],
        "cumulative_diff": {
            "sha256": _sha256_bytes(diff_bytes),
            "bytes": len(diff_bytes),
            "blob_sha256": diff_blob,
            "changed_paths": list(source["cumulative_changed_paths"]),
            "new_paths": list((delta or {}).get("new_paths") or []),
            "deleted_paths": list((delta or {}).get("deleted_paths") or []),
            "binary_paths": list((delta or {}).get("binary_paths") or []),
        },
        "tests": {
            "declared": list(contract.get("tests") or []),
            "validation_id": validation["payload"]["validation_id"],
            "validation_digest": validation["digest"],
            "classification": validation["payload"]["classification"],
            "counts": validation["payload"]["counts"],
            "entries": list(validation["payload"]["entries"]),
        },
        "acceptance_criteria": list(contract["acceptance_criteria"]),
        "prior_findings": _prior_actionable_findings(
            plan_id, journal, step_id, source
        ),
    }


def _lineage_events(
    journal: dict[str, Any], step_id: str
) -> list[dict[str, Any]]:
    """Return every review/design-link fact that can change finding state."""
    events = [
        event for event in journal["reviews"] if event["step_id"] == step_id
    ] + [
        event
        for event in journal["design_links"]
        if event["step_id"] == step_id
    ]
    events.sort(key=lambda event: event["sequence"])
    return events


def _open_actionable_findings(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    *,
    through_sequence: int | None = None,
) -> list[dict[str, Any]]:
    """Derive every still-open actionable finding from the actual lineage.

    A review opens its own actionable defect findings (nonempty required
    change). ``resolved``/``obsolete`` dispositions with evidence close a
    finding; ``carried`` keeps it open across review generations and design
    links. Every disposition must name a finding that is open at that exact
    point, so renaming or reallocating a finding can never silently drop an
    earlier actionable defect. The derivation is pure journal replay; it never
    rewrites historical review documents.
    """
    d = _d()
    open_findings: dict[str, dict[str, Any]] = {}
    for event in _lineage_events(journal, step_id):
        if through_sequence is not None and event["sequence"] > through_sequence:
            break
        if event["type"] == d.TYPE_DESIGN_LINK:
            dispositions = list(
                event["payload"].get("finding_dispositions") or []
            )
            label = f"design link {event['event_id']} disposition"
            document = None
        else:
            document = _load_review_document(plan_id, journal, event)
            dispositions = list(document.get("prior_findings") or [])
            label = f"review {event['payload']['review_id']} disposition"
        for disposition in dispositions:
            finding_id = disposition.get("finding_id")
            if finding_id not in open_findings:
                _fail(
                    f"{label} {finding_id!r} does not name a currently open "
                    "actionable finding"
                )
            if disposition.get("disposition") in {"resolved", "obsolete"}:
                del open_findings[finding_id]
            elif disposition.get("disposition") != "carried":
                _fail(
                    f"{label} {finding_id!r} has an unsupported disposition"
                )
        if document is not None:
            for finding in document.get("findings") or []:
                if finding.get("kind") == "defect" and finding.get(
                    "required_change"
                ):
                    open_findings[finding["finding_id"]] = finding
    return list(open_findings.values())


def _prior_actionable_findings(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    source: dict[str, Any],
) -> list[dict[str, Any]]:
    """Every open actionable finding, including carried and same-source ones."""
    return _open_actionable_findings(plan_id, journal, step_id)


def _validation_binding_current(
    journal: dict[str, Any],
    step_id: str,
    candidate_sha256: str,
    contract_digest: str,
    source: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Return the latest durable batch and why it can or cannot be reviewed."""
    latest = _latest_validation(journal, step_id, candidate_sha256, contract_digest)
    reasons: list[str] = []
    if latest is None:
        return None, ["no durable validation batch exists"]
    intents = [
        event
        for event in journal["validation_intents"]
        if event["step_id"] == step_id
        and event["payload"].get("candidate_sha256") == candidate_sha256
        and event["payload"].get("contract_digest") == contract_digest
    ]
    result_ids = {
        event["payload"].get("validation_id")
        for event in journal["validation_results"]
        if event["step_id"] == step_id
    }
    pending = [
        event
        for event in intents
        if event["payload"].get("validation_id") not in result_ids
    ]
    if pending and pending[-1]["sequence"] > latest["sequence"]:
        reasons.append(
            "a newer validation batch is pending or failed to publish; it "
            "invalidates the older durable approval evidence"
        )
    if latest["payload"].get("source_evidence_digest") != source["evidence_digest"]:
        reasons.append("the latest validation batch belongs to another source")
    if latest["payload"].get("source_final_snapshot_digest") != source[
        "final_snapshot_digest"
    ]:
        reasons.append("the latest validation batch observed another source snapshot")
    return latest, reasons


def begin_review(
    *,
    plan_id: str,
    step_id: str,
    purpose: str,
    leader: str,
    session_file: Path,
) -> dict[str, Any]:
    """Issue one single-use review session token to the active Codex leader."""
    purpose = _require_text(purpose, "review purpose", minimum=3)
    leader = _require_text(leader, "leader identity", minimum=2)
    session_file = Path(session_file).expanduser()
    if session_file.exists():
        _fail(f"Review session file already exists: {session_file}")
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        if constraints.get("version") != d.CONTRACT_VERSION_D2:
            _fail("Review requires an approved version 2 candidate policy")
        journal = d._replay_journal(plan_id)
        contract, contract_event = _contract_for_current(
            plan_id, journal, step_id, current["cycle"], candidate_sha256
        )
        unsettled = _unsettled_writer_reason(
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if unsettled:
            _fail(unsettled)
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        workspace = Path(static["canonical_workspace"])
        snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
        _require_source_current(plan_id, source, snapshot, "review")
        _require_no_live_writer(d._repo_identity(static))
        validation, validation_reasons = _validation_binding_current(
            journal,
            step_id,
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
            source,
        )
        if validation is None or validation_reasons:
            _fail(
                "A current durable validation batch is required before review: "
                + "; ".join(validation_reasons or ["missing"])
            )
        bundle = _review_bundle(
            plan_id,
            b1_state,
            journal,
            step_id,
            current,
            candidate_sha256,
            contract,
            contract_event,
            source,
            validation,
        )
        bundle_digest = _digest(bundle)
        bundle_blob, _ = d._publish_json_blob(
            plan_id, bundle, "D2 review input bundle"
        )
        review_id = "r" + _digest(
            {
                "step_id": step_id,
                "candidate_sha256": candidate_sha256,
                "contract_digest": contract_event["payload"]["contract_digest"],
                "validation_id": validation["payload"]["validation_id"],
                "validation_digest": validation["digest"],
                "source_evidence_digest": source["evidence_digest"],
                "sequence": len(journal["events"]) + 1,
            }
        )[:40]
        token = secrets.token_hex(32)
        payload = {
            "version": SESSION_VERSION,
            "review_id": review_id,
            "purpose": purpose,
            "leader": leader,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "policy_digest": _policy_digest(_policy_from_contract(contract)),
            "source_attempt_id": source["attempt_id"],
            "source_kind": source["source_kind"],
            "source_evidence_digest": source["evidence_digest"],
            "source_final_snapshot_digest": source["final_snapshot_digest"],
            "generation": source["generation"],
            "validation_id": validation["payload"]["validation_id"],
            "validation_digest": validation["digest"],
            "input_bundle_digest": bundle_digest,
            "input_bundle_blob_sha256": bundle_blob,
            "token_sha256": _sha256_bytes(token.encode("utf-8")),
            "issuer": _process_identity(),
        }
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_REVIEW_SESSION, step_id, current["cycle"], payload)],
            "review_session",
            plan_id=plan_id,
            step_id=step_id,
            review_id=review_id,
            input_bundle_digest=bundle_digest,
        )
        session = {
            "version": 1,
            "plan_id": plan_id,
            "step_id": step_id,
            "review_id": review_id,
            "token": token,
        }
        session_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(session_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(session, handle)
            handle.flush()
            os.fsync(handle.fileno())
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "review_id": review_id,
            "purpose": purpose,
            "leader": leader,
            "validation_id": validation["payload"]["validation_id"],
            "validation_classification": validation["payload"]["classification"],
            "input_bundle_digest": bundle_digest,
            "session_event_id": events[0]["event_id"],
            "session_file": str(session_file),
            "next_action": (
                "inspect the immutable input bundle, then record the actual "
                "leader review with execution-review"
            ),
        }


def _normalize_review_finding(raw: Any, index: int) -> dict[str, Any]:
    label = f"review.findings[{index}]"
    required = {
        "finding_id",
        "kind",
        "severity",
        "files",
        "summary",
        "evidence",
        "required_change",
        "test_recommendation",
    }
    if not isinstance(raw, dict):
        _fail(f"{label} must be a JSON object")
    missing = sorted(required - set(raw))
    extra = sorted(set(raw) - required - {"affected_lines"})
    if missing:
        _fail(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        _fail(f"{label} has unknown fields: {', '.join(extra)}")
    item = raw
    finding_id = item.get("finding_id")
    if not isinstance(finding_id, str) or not re.fullmatch(r"F[0-9]{3}", finding_id):
        _fail(f"{label}.finding_id must match FNNN")
    if item.get("kind") not in {"defect", "suggestion"}:
        _fail(f"{label}.kind must be defect or suggestion")
    if item.get("severity") not in {"critical", "high", "medium", "low"}:
        _fail(f"{label}.severity is invalid")
    files = _require_text_list(item.get("files"), f"{label}.files", maximum_items=64)
    for path in files:
        if path.startswith("/") or ".." in Path(path).parts:
            _fail(f"{label}.files must be repository-relative")
    affected_lines: list[dict[str, Any]] = []
    raw_lines = item.get("affected_lines")
    if raw_lines is not None:
        if not isinstance(raw_lines, list) or len(raw_lines) > 64:
            _fail(f"{label}.affected_lines must be a bounded JSON array")
        for line_index, entry in enumerate(raw_lines):
            line_label = f"{label}.affected_lines[{line_index}]"
            line = _exact_keys(entry, {"path", "start", "end"}, line_label)
            path = line.get("path")
            if not isinstance(path, str) or not path:
                _fail(f"{line_label}.path is invalid")
            if path.startswith("/") or ".." in Path(path).parts:
                _fail(f"{line_label}.path must be repository-relative")
            if path not in files:
                _fail(
                    f"{line_label}.path must name one of the finding's affected "
                    "files"
                )
            start = line.get("start")
            end = line.get("end")
            for key, value in (("start", start), ("end", end)):
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value <= 0
                    or value > 10_000_000
                ):
                    _fail(f"{line_label}.{key} is invalid")
            if start > end:
                _fail(f"{line_label}.start must not exceed end")
            affected_lines.append({"path": path, "start": start, "end": end})
    required_change = _require_text(
        item.get("required_change"), f"{label}.required_change", minimum=3
    )
    if item.get("kind") == "suggestion" and required_change:
        # A suggestion can describe a preference but it is never actionable.
        required_change = required_change
    return {
        "finding_id": finding_id,
        "kind": item["kind"],
        "severity": item["severity"],
        "files": files,
        "affected_lines": affected_lines,
        "summary": _require_text(item.get("summary"), f"{label}.summary", minimum=3),
        "evidence": _require_text(
            item.get("evidence"), f"{label}.evidence", minimum=3
        ),
        "required_change": required_change,
        "test_recommendation": _require_text(
            item.get("test_recommendation"),
            f"{label}.test_recommendation",
            minimum=1,
        ),
    }


def _normalize_review_document(
    raw: Any,
    *,
    review_id: str,
    contract: dict[str, Any],
    prior_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(_canonical_bytes(raw)) > MAX_REVIEW_BYTES:
        _fail(f"Review document exceeds {MAX_REVIEW_BYTES} bytes")
    item = _exact_keys(
        raw,
        {
            "version",
            "review_id",
            "verdict",
            "leader",
            "summary",
            "findings",
            "criteria",
            "prior_findings",
        },
        "review",
    )
    if item.get("version") != REVIEW_VERSION:
        _fail("Review document version is not supported")
    if item.get("review_id") != review_id:
        _fail("Review document names another review ID")
    if item.get("verdict") not in {VERDICT_APPROVE, VERDICT_REQUEST_CHANGES}:
        _fail("Review verdict must be APPROVE or REQUEST_CHANGES")
    leader = _require_text(item.get("leader"), "review.leader", minimum=2)
    findings_raw = item.get("findings")
    if not isinstance(findings_raw, list) or len(findings_raw) > MAX_FINDINGS:
        _fail("Review findings must be a bounded JSON array")
    findings = [
        _normalize_review_finding(entry, index)
        for index, entry in enumerate(findings_raw)
    ]
    finding_ids = [finding["finding_id"] for finding in findings]
    if len(set(finding_ids)) != len(finding_ids):
        _fail("Review findings repeat a stable finding ID")
    criteria_raw = item.get("criteria")
    if not isinstance(criteria_raw, list):
        _fail("Review criteria must be a JSON array")
    expected_criteria = {
        criterion["id"]: criterion["text"]
        for criterion in contract["acceptance_criteria"]
    }
    if len(criteria_raw) != len(expected_criteria):
        _fail("Review must dispose every acceptance criterion exactly once")
    criteria: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, entry in enumerate(criteria_raw):
        label = f"review.criteria[{index}]"
        criterion = _exact_keys(entry, {"id", "disposition", "evidence"}, label)
        criterion_id = criterion.get("id")
        if criterion_id not in expected_criteria:
            _fail(f"{label}.id is not an approved criterion")
        if criterion_id in seen:
            _fail(f"{label} repeats criterion {criterion_id}")
        seen.add(criterion_id)
        if criterion.get("disposition") not in {"satisfied", "unsatisfied"}:
            _fail(f"{label}.disposition is invalid")
        criteria.append(
            {
                "id": criterion_id,
                "text": expected_criteria[criterion_id],
                "disposition": criterion["disposition"],
                "evidence": _require_text(
                    criterion.get("evidence"), f"{label}.evidence", minimum=3
                ),
            }
        )
    prior = item.get("prior_findings")
    if not isinstance(prior, list):
        _fail("Review prior_findings must be a JSON array")
    prior_ids = [finding["finding_id"] for finding in prior_findings]
    dispositions: list[dict[str, str]] = []
    disposed: set[str] = set()
    for index, entry in enumerate(prior):
        label = f"review.prior_findings[{index}]"
        record = _exact_keys(
            entry, {"finding_id", "disposition", "evidence"}, label
        )
        finding_id = record.get("finding_id")
        if finding_id not in prior_ids:
            _fail(f"{label}.finding_id is not a prior actionable finding")
        if finding_id in disposed:
            _fail(f"{label} disposes finding {finding_id} twice")
        disposed.add(finding_id)
        if record.get("disposition") not in {"resolved", "carried", "obsolete"}:
            _fail(f"{label}.disposition is invalid")
        dispositions.append(
            {
                "finding_id": finding_id,
                "disposition": record["disposition"],
                "evidence": _require_text(
                    record.get("evidence"), f"{label}.evidence", minimum=3
                ),
            }
        )
    if set(prior_ids) - disposed:
        _fail(
            "Review must explicitly dispose every prior actionable finding; "
            "missing: " + ", ".join(sorted(set(prior_ids) - disposed))
        )
    return {
        "version": REVIEW_VERSION,
        "review_id": review_id,
        "verdict": item["verdict"],
        "leader": leader,
        "summary": _require_text(item.get("summary"), "review.summary", minimum=10),
        "findings": findings,
        "criteria": criteria,
        "prior_findings": dispositions,
    }


def record_review(
    *,
    plan_id: str,
    step_id: str,
    review_file: Path,
    session_file: Path,
    leader: str,
) -> dict[str, Any]:
    """Record the active Codex leader's actual review after a single-use session."""
    leader = _require_text(leader, "leader identity", minimum=2)
    d = _d()
    review_path = Path(review_file).expanduser().resolve()
    if not review_path.is_file():
        _fail(f"Review file does not exist: {review_path}")
    if review_path.stat().st_size > MAX_REVIEW_BYTES:
        _fail("Review file exceeds its bounded size")
    try:
        raw_review = json.loads(review_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Review file is not valid JSON: {exc}")
    session_path = Path(session_file).expanduser()
    try:
        info = os.lstat(session_path)
    except OSError as exc:
        _fail(f"Review session file is unreadable: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        _fail("Review session file is not a stable regular file")
    if info.st_size > 8_192:
        _fail("Review session file exceeds its bounded size")
    session = _read_json(session_path)
    token = session.get("token")
    if not isinstance(token, str) or len(token) < 32:
        _fail("Review session token is invalid")
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        journal = d._replay_journal(plan_id)
        contract, contract_event = _contract_for_current(
            plan_id, journal, step_id, current["cycle"], candidate_sha256
        )
        session_event = next(
            (
                event
                for event in journal["review_sessions"]
                if event["payload"]["review_id"] == session.get("review_id")
                and event["step_id"] == step_id
            ),
            None,
        )
        if session_event is None:
            _fail("Review session is unknown or belongs to another step")
        payload = session_event["payload"]
        if _sha256_bytes(token.encode("utf-8")) != payload["token_sha256"]:
            _fail("Review session token does not match its issued hash")
        if leader != payload["leader"]:
            _fail("Review leader does not match the issued session")
        if any(
            event["payload"].get("review_id") == payload["review_id"]
            for event in journal["reviews"]
        ):
            _fail("Review session is single-use and was already consumed")
        issuer = payload["issuer"]
        probe = d._process_probe(issuer)
        if probe == "unknown":
            _fail("Review session issuer process identity is unverifiable")
        if probe == "alive":
            _require_process_cmdline(issuer, "review session issuer")
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        workspace = Path(static["canonical_workspace"])
        snapshot = d._observe_workspace(workspace, contract, extra_paths=[])
        _require_source_current(plan_id, source, snapshot, "review")
        validation, validation_reasons = _validation_binding_current(
            journal,
            step_id,
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
            source,
        )
        if validation is None or validation_reasons:
            _fail(
                "Review no longer has a current durable validation batch: "
                + "; ".join(validation_reasons or ["missing"])
            )
        if (
            payload["validation_id"] != validation["payload"]["validation_id"]
            or payload["validation_digest"] != validation["digest"]
        ):
            _fail("Review session was invalidated by a newer validation batch")
        if (
            payload["source_attempt_id"] != source["attempt_id"]
            or payload["source_evidence_digest"] != source["evidence_digest"]
            or payload["source_final_snapshot_digest"]
            != source["final_snapshot_digest"]
        ):
            _fail("Review session source binding changed")
        bundle = _review_bundle(
            plan_id,
            b1_state,
            journal,
            step_id,
            current,
            candidate_sha256,
            contract,
            contract_event,
            source,
            validation,
        )
        if _digest(bundle) != payload["input_bundle_digest"]:
            _fail("Review input bundle changed after the session was issued")
        document = _normalize_review_document(
            raw_review,
            review_id=payload["review_id"],
            contract=contract,
            prior_findings=[
                finding
                for finding in bundle["prior_findings"]
                if finding.get("kind") == "defect"
            ],
        )
        if document["leader"] != payload["leader"]:
            _fail("Review document leader identity differs from the session")
        defects = [f for f in document["findings"] if f["kind"] == "defect"]
        suggestions = [
            f for f in document["findings"] if f["kind"] == "suggestion"
        ]
        unsatisfied = [
            criterion
            for criterion in document["criteria"]
            if criterion["disposition"] == "unsatisfied"
        ]
        open_required = [
            finding
            for finding in defects
            if finding["required_change"]
        ]
        if document["verdict"] == VERDICT_APPROVE:
            if source["source_kind"] != "complete":
                _fail(
                    "APPROVE requires a complete implementation or repair; a "
                    "drained failure partial is failure evidence only"
                )
            if not source["author_report"]:
                _fail("APPROVE requires a valid original author report")
            if validation["payload"]["classification"] != "passed":
                _fail("APPROVE requires the latest durable validation to pass")
            if unsatisfied:
                _fail("APPROVE requires every acceptance criterion to be satisfied")
            if defects:
                _fail("APPROVE cannot coexist with unresolved defect findings")
            if any(
                disposition["disposition"] == "carried"
                for disposition in document["prior_findings"]
            ):
                _fail("APPROVE cannot carry a prior actionable finding")
            if not document["summary"]:
                _fail("APPROVE requires an actual reviewer summary")
        else:
            if not defects and validation["payload"]["classification"] == "passed":
                _fail(
                    "Style preference alone cannot REQUEST_CHANGES; record an "
                    "actionable defect or failed required validation"
                )
            if not unsatisfied:
                _fail(
                    "REQUEST_CHANGES requires explicit unsatisfied acceptance "
                    "criteria"
                )
        review_digest = _digest(document)
        blob_sha, _ = d._publish_json_blob(
            plan_id, document, "D2 independent review"
        )
        review_payload = {
            "version": REVIEW_VERSION,
            "review_id": payload["review_id"],
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "policy_digest": _policy_digest(_policy_from_contract(contract)),
            "source_attempt_id": source["attempt_id"],
            "source_job_id": source["job_id"],
            "source_kind": source["source_kind"],
            "source_evidence_digest": source["evidence_digest"],
            "generation": source["generation"],
            "validation_id": validation["payload"]["validation_id"],
            "validation_digest": validation["digest"],
            "input_bundle_digest": payload["input_bundle_digest"],
            "review_digest": review_digest,
            "review_blob_sha256": blob_sha,
            "verdict": document["verdict"],
            "finding_counts": {
                "defects": len(defects),
                "suggestions": len(suggestions),
                "open_required_changes": len(open_required),
            },
            "criteria_counts": {
                "total": len(document["criteria"]),
                "satisfied": len(document["criteria"]) - len(unsatisfied),
                "unsatisfied": len(unsatisfied),
            },
            "leader": leader,
            "recorder": _process_identity(),
        }
        # Recheck the same ownership guards as begin_review immediately before
        # the append: a pending writer intent or a live repository job means
        # the source/approval could change underneath the review.
        unsettled = _unsettled_writer_reason(
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if unsettled:
            _fail(unsettled)
        _require_no_live_writer(d._repo_identity(static))
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_REVIEW, step_id, current["cycle"], review_payload)],
            "independent_review",
            plan_id=plan_id,
            step_id=step_id,
            review_id=payload["review_id"],
            verdict=document["verdict"],
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "review_id": payload["review_id"],
            "verdict": document["verdict"],
            "generation": source["generation"],
            "validation_id": validation["payload"]["validation_id"],
            "review_digest": review_digest,
            "event_id": events[0]["event_id"],
            "closed_routes": dict(CLOSED_D2_ROUTES),
        }


# ---------------------------------------------------------------------------
# Repair contract, durable allocation, bounded setup attempts and admission
# ---------------------------------------------------------------------------


def _render_finding(finding: dict[str, Any]) -> str:
    lines = ", ".join(
        f"{line['path']}:{line['start']}-{line['end']}"
        for line in finding.get("affected_lines") or []
        if isinstance(line, dict)
    )
    suffix = f" Affected lines: {lines}." if lines else ""
    return (
        f"- `{finding['finding_id']}` [{finding['severity']}]: "
        f"{finding['summary']}{suffix} Required change: {finding['required_change']}"
    )


def _rejection_review_locked(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    candidate_sha256: str,
    contract_digest: str,
    review_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    review = _latest_review(journal, step_id, candidate_sha256, contract_digest)
    if review is None:
        _fail("No independent review exists for this source")
    if review_id is not None and review["payload"]["review_id"] != review_id:
        _fail(
            f"Review {review_id!r} is not the current review; a newer review "
            "supersedes it"
        )
    if review["payload"]["verdict"] != VERDICT_REQUEST_CHANGES:
        _fail("A formal repair requires a current REQUEST_CHANGES review")
    document = _load_review_document(plan_id, journal, review)
    return review, document


def freeze_repair_contract(
    *,
    plan_id: str,
    step_id: str,
    review_id: str,
    contract_raw: Any,
) -> dict[str, Any]:
    """Freeze an immutable, mechanically restricted repair contract."""
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        if constraints.get("version") != d.CONTRACT_VERSION_D2:
            _fail("Repair requires an approved version 2 candidate policy")
        journal = d._replay_journal(plan_id)
        contract, contract_event = _contract_for_current(
            plan_id, journal, step_id, current["cycle"], candidate_sha256
        )
        policy = _policy_from_contract(contract)
        review, review_document = _rejection_review_locked(
            plan_id,
            journal,
            step_id,
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
            review_id,
        )
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if (
            review["payload"]["source_attempt_id"] != source["attempt_id"]
            or review["payload"]["source_evidence_digest"]
            != source["evidence_digest"]
        ):
            _fail("The rejection review does not bind the current source")
        generation = len(_allocations_for_step(journal, step_id)) + 1
        if generation > FORMAL_REPAIR_LIMIT:
            _fail(
                "The formal repair budget for this step is exhausted; no fourth "
                "contract can be frozen"
            )
        value = _exact_keys(
            contract_raw,
            {
                "version",
                "objective",
                "why",
                "relevant_modules",
                "allowed_paths",
                "denied_paths",
                "finding_ids",
                "required_behavior",
                "required_interfaces",
                "tests",
                "acceptance_criteria",
                "required_validation",
                "target_branch",
                "protected_branches",
                "reporting",
            },
            "repair_contract",
        )
        if value.get("version") != REPAIR_VERSION:
            _fail("repair_contract version is not supported")
        approved_allowed = set(constraints["allowed_paths"])
        allowed = d._contract_patterns(
            value.get("allowed_paths"), "repair_contract.allowed_paths", minimum_items=1
        )
        for pattern in allowed:
            if pattern not in approved_allowed:
                _fail(
                    "repair_contract.allowed_paths must be an exact subset of the "
                    f"approved patterns; {pattern!r} is not approved"
                )
        denied = d._contract_patterns(
            value.get("denied_paths"), "repair_contract.denied_paths"
        )
        missing_denied = sorted(set(constraints["denied_paths"]) - set(denied))
        if missing_denied:
            _fail(
                "repair_contract drops approved denials: "
                + ", ".join(missing_denied)
            )
        expected_criteria = contract["acceptance_criteria"]
        criteria_raw = value.get("acceptance_criteria")
        if not isinstance(criteria_raw, list) or len(criteria_raw) != len(
            expected_criteria
        ):
            _fail("repair_contract must carry every approved acceptance criterion")
        criteria: list[dict[str, str]] = []
        for index, entry in enumerate(criteria_raw):
            item = _exact_keys(
                entry,
                {"id", "text"},
                f"repair_contract.acceptance_criteria[{index}]",
            )
            criteria.append(
                {
                    "id": _require_text(
                        item.get("id"),
                        f"repair_contract.acceptance_criteria[{index}].id",
                    ),
                    "text": _require_text(
                        item.get("text"),
                        f"repair_contract.acceptance_criteria[{index}].text",
                        minimum=3,
                    ),
                }
            )
        if criteria != expected_criteria:
            _fail(
                "repair_contract acceptance criteria must exactly equal the frozen "
                "execution contract criteria"
            )
        mandatory_mirror = [
            {"argv": list(entry["argv"]), "label": entry["label"]}
            for entry in policy["entries"]
            if entry["mandatory"]
        ]
        if value.get("required_validation") != mandatory_mirror:
            _fail(
                "repair_contract.required_validation must exactly mirror the voted "
                "mandatory validation invocations"
            )
        open_findings = _open_actionable_findings(
            plan_id, journal, step_id, through_sequence=review["sequence"]
        )
        expected_findings = sorted(
            finding["finding_id"] for finding in open_findings
        )
        finding_ids = value.get("finding_ids")
        if not isinstance(finding_ids, list) or sorted(
            str(item) for item in finding_ids
        ) != expected_findings:
            _fail(
                "repair_contract.finding_ids must exactly cover every open "
                "actionable finding after the current rejection, including "
                "carried findings"
            )
        if not open_findings and review["payload"]["criteria_counts"]["unsatisfied"] == 0:
            _fail(
                "A repair contract requires an actionable defect or an explicit "
                "unsatisfied criterion in the rejection"
            )
        if value.get("target_branch") != contract["target_branch"]:
            _fail("repair_contract target branch changed")
        if list(value.get("protected_branches") or []) != list(
            contract["protected_branches"]
        ):
            _fail("repair_contract protected branches changed")
        document = {
            "version": REPAIR_VERSION,
            "objective": _require_text(
                value.get("objective"), "repair_contract.objective", minimum=20
            ),
            "why": _require_text(
                value.get("why"), "repair_contract.why", minimum=20
            ),
            "relevant_modules": _require_text_list(
                value.get("relevant_modules"),
                "repair_contract.relevant_modules",
                minimum_chars=2,
            ),
            "allowed_paths": allowed,
            "denied_paths": denied,
            "finding_ids": expected_findings,
            "required_behavior": _require_text_list(
                value.get("required_behavior"),
                "repair_contract.required_behavior",
                minimum_chars=3,
            ),
            "required_interfaces": _require_text_list(
                value.get("required_interfaces"),
                "repair_contract.required_interfaces",
                minimum_chars=3,
            ),
            "tests": _require_text_list(
                value.get("tests"), "repair_contract.tests", minimum_chars=3
            ),
            "acceptance_criteria": criteria,
            "required_validation": mandatory_mirror,
            "target_branch": contract["target_branch"],
            "protected_branches": list(contract["protected_branches"]),
            "reporting": _require_text_list(
                value.get("reporting"),
                "repair_contract.reporting",
                minimum_chars=3,
            ),
        }
        contract_digest = _digest(document)
        contract_id = "rc" + _digest(
            {
                "review_id": review["payload"]["review_id"],
                "review_digest": review["payload"]["review_digest"],
                "contract_digest": contract_digest,
                "generation": generation,
            }
        )[:24]
        existing = next(
            (
                event
                for event in journal["repair_contracts"]
                if event["step_id"] == step_id
                and event["payload"]["review_id"] == review_id
            ),
            None,
        )
        if existing is not None:
            if existing["payload"]["repair_contract_digest"] == contract_digest:
                return {
                    "plan_id": plan_id,
                    "step_id": step_id,
                    "repair_contract_id": existing["payload"][
                        "repair_contract_id"
                    ],
                    "repair_contract_digest": contract_digest,
                    "generation": existing["payload"]["generation"],
                    "idempotent": True,
                }
            _fail("A different repair contract is already frozen for this rejection")
        blob_sha, _ = d._publish_json_blob(
            plan_id, document, "D2 repair contract"
        )
        payload = {
            "version": REPAIR_VERSION,
            "repair_contract_id": contract_id,
            "review_id": review["payload"]["review_id"],
            "review_digest": review["payload"]["review_digest"],
            "generation": generation,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "repair_contract_digest": contract_digest,
            "repair_contract_blob_sha256": blob_sha,
            "finding_ids": expected_findings,
            "source_attempt_id": source["attempt_id"],
            "source_evidence_digest": source["evidence_digest"],
        }
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_REPAIR_CONTRACT, step_id, current["cycle"], payload)],
            "repair_contract",
            plan_id=plan_id,
            step_id=step_id,
            review_id=review_id,
            contract_digest=contract_digest,
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "repair_contract_id": contract_id,
            "repair_contract_digest": contract_digest,
            "generation": generation,
            "finding_ids": expected_findings,
            "event_id": events[0]["event_id"],
            "idempotent": False,
        }


def allocate_repair(
    *, plan_id: str, step_id: str, review_id: str
) -> dict[str, Any]:
    """Consume one formal repair slot at durable allocation time."""
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        if constraints.get("version") != d.CONTRACT_VERSION_D2:
            _fail("Repair allocation requires an approved version 2 policy")
        journal = d._replay_journal(plan_id)
        contract, contract_event = _contract_for_current(
            plan_id, journal, step_id, current["cycle"], candidate_sha256
        )
        review, _review_document = _rejection_review_locked(
            plan_id,
            journal,
            step_id,
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
            review_id,
        )
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            current["cycle"],
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
        if review["payload"]["source_evidence_digest"] != source["evidence_digest"]:
            _fail("The rejection review does not bind the current source")
        repair_contracts = [
            event
            for event in journal["repair_contracts"]
            if event["step_id"] == step_id
            and event["payload"]["review_id"] == review_id
        ]
        if not repair_contracts:
            _fail("No repair contract is frozen for the current rejection")
        repair_contract_event = repair_contracts[-1]
        allocations = _allocations_for_step(journal, step_id)
        for existing in allocations:
            existing_payload = existing["payload"]
            if (
                existing_payload.get("review_id") == review_id
                and existing_payload.get("repair_contract_digest")
                == repair_contract_event["payload"]["repair_contract_digest"]
                and existing_payload.get("source_evidence_digest")
                == source["evidence_digest"]
                and existing_payload.get("source_final_snapshot_digest")
                == source["final_snapshot_digest"]
                and existing_payload.get("candidate_sha256")
                == candidate_sha256
                and existing_payload.get("contract_digest")
                == contract_event["payload"]["contract_digest"]
            ):
                slot = int(existing_payload["generation"])
                return {
                    "plan_id": plan_id,
                    "step_id": step_id,
                    "allocation_id": existing_payload["allocation_id"],
                    "generation": slot,
                    "remaining": FORMAL_REPAIR_LIMIT - len(allocations),
                    "idempotent": True,
                }
        generation = len(allocations) + 1
        if generation > FORMAL_REPAIR_LIMIT:
            _fail(
                "The formal repair budget for this step is exhausted (used="
                f"{len(allocations)} of {FORMAL_REPAIR_LIMIT}); guidance is required"
            )
        idempotency_key = _digest(
            {
                "step_id": step_id,
                "generation": generation,
                "review_id": review_id,
                "review_digest": review["payload"]["review_digest"],
                "repair_contract_digest": repair_contract_event["payload"][
                    "repair_contract_digest"
                ],
                "source_evidence_digest": source["evidence_digest"],
                "source_final_snapshot_digest": source["final_snapshot_digest"],
                "candidate_sha256": candidate_sha256,
                "contract_digest": contract_event["payload"]["contract_digest"],
            }
        )
        for existing in allocations:
            if existing["payload"]["generation"] == generation:
                if existing["payload"]["idempotency_key"] == idempotency_key:
                    return {
                        "plan_id": plan_id,
                        "step_id": step_id,
                        "allocation_id": existing["payload"]["allocation_id"],
                        "generation": generation,
                        "remaining": FORMAL_REPAIR_LIMIT - len(allocations),
                        "idempotent": True,
                    }
                _fail(
                    "The current repair generation was already allocated for "
                    "different inputs; no refund or replacement slot exists"
                )
        _require_no_live_writer(d._repo_identity(static))
        allocation_id = "ra" + _digest(
            {"idempotency_key": idempotency_key, "sequence": len(journal["events"]) + 1}
        )[:24]
        payload = {
            "version": REPAIR_VERSION,
            "allocation_id": allocation_id,
            "generation": generation,
            "cycle": current["cycle"],
            "candidate_sha256": candidate_sha256,
            "contract_digest": contract_event["payload"]["contract_digest"],
            "review_id": review_id,
            "review_digest": review["payload"]["review_digest"],
            "repair_contract_digest": repair_contract_event["payload"][
                "repair_contract_digest"
            ],
            "repair_contract_blob_sha256": repair_contract_event["payload"][
                "repair_contract_blob_sha256"
            ],
            "source_attempt_id": source["attempt_id"],
            "source_job_id": source["job_id"],
            "source_evidence_digest": source["evidence_digest"],
            "source_final_snapshot_digest": source["final_snapshot_digest"],
            "idempotency_key": idempotency_key,
        }
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_REPAIR_ALLOCATION, step_id, current["cycle"], payload)],
            "repair_allocation",
            plan_id=plan_id,
            step_id=step_id,
            generation=generation,
            idempotency_key=idempotency_key,
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "allocation_id": allocation_id,
            "generation": generation,
            "remaining": FORMAL_REPAIR_LIMIT - generation,
            "source_attempt_id": source["attempt_id"],
            "source_evidence_digest": source["evidence_digest"],
            "event_id": events[0]["event_id"],
            "idempotent": False,
            "closed_routes": dict(CLOSED_D2_ROUTES),
        }


def _repair_intents_for(
    journal: dict[str, Any], allocation_id: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in journal["intents"]
        if event["payload"].get("repair_allocation_id") == allocation_id
    ]


def _repair_claims_for(
    journal: dict[str, Any], allocation_id: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in journal["claims"]
        if event["payload"].get("repair_allocation_id") == allocation_id
    ]


def record_setup_failure(
    *,
    plan_id: str,
    step_id: str,
    allocation_id: str,
    ordinal: int,
    detail: str,
) -> dict[str, Any]:
    detail = _require_text(detail, "setup failure detail", minimum=3)[:2_000]
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        current = d._require_consensus(b1_state, step_id)
        payload = {
            "version": REPAIR_VERSION,
            "allocation_id": allocation_id,
            "ordinal": ordinal,
            "outcome": "failed_pre_claim",
            "issuer": _process_identity(),
            "detail": detail,
        }
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_REPAIR_SETUP, step_id, current["cycle"], payload)],
            "repair_setup_failure",
            plan_id=plan_id,
            step_id=step_id,
            allocation_id=allocation_id,
            ordinal=ordinal,
        )
        return {"event_id": events[0]["event_id"], "ordinal": ordinal}


def _next_setup_ordinal_locked(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    allocation_id: str,
) -> int:
    d = _d()
    attempts = [
        event
        for event in journal["repair_setups"]
        if event["step_id"] == step_id
        and event["payload"]["allocation_id"] == allocation_id
    ]
    intents = _repair_intents_for(journal, allocation_id)
    claims = _repair_claims_for(journal, allocation_id)
    if claims:
        _fail(
            "This formal repair slot already has a durable claim; its fully "
            "drained result is final and cannot be retried in the same slot"
        )
    ordinals = sorted({int(event["payload"]["ordinal"]) for event in attempts})
    if len(ordinals) >= SETUP_ATTEMPT_LIMIT:
        _fail(
            "This formal repair slot exhausted its "
            f"{SETUP_ATTEMPT_LIMIT} pre-claim setup attempts; guidance is required"
        )
    if intents:
        latest = intents[-1]["payload"]
        state = d._attempt_state(journal, latest["attempt_id"])
        if state["state"] in {"claimed", "complete", "drained_success"}:
            _fail(
                "This formal repair slot already produced a claimed result; a "
                "fresh actual Codex rejection and a new slot are required"
            )
        if state["state"] in {"uncertain", "blocked"}:
            _fail(
                "The previous repair setup is uncertain; its ownership must be "
                "reconciled before another setup attempt"
            )
        if state["state"] == "pending":
            issuer = latest["issuer"]
            job_dir = _jobs_dir() / latest["job_id"]
            probe = d._process_probe(issuer)
            same_issuer = (
                issuer.get("pid") == os.getpid()
                and issuer.get("start") == _b2().process_start_identity(os.getpid())
            )
            if job_dir.exists() and not same_issuer:
                _fail(
                    "The pending repair intent has an existing job directory; "
                    "ambiguity blocks another setup attempt"
                )
            if probe != "dead" and not same_issuer:
                _fail("The pending repair intent is owned by a live issuer process")
            if job_dir.exists():
                _fail(
                    "A repair job directory exists for a pending intent; the "
                    "no-start proof is ambiguous"
                )
        if state["state"] in {"drained_failure", "aborted", "pre_invocation_abort"}:
            _fail(
                "The previous repair intent is closed; a new Codex rejection and "
                "allocation are required"
            )
    return (max(ordinals) if ordinals else 0) + 1


def prepare_repair(
    *, plan_id: str, step_id: str, allocation_id: str
) -> dict[str, Any]:
    """Record one bounded pre-claim setup attempt, then prepare the writer."""
    d = _d()
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        journal = d._replay_journal(plan_id)
        allocation = next(
            (
                event
                for event in journal["repair_allocations"]
                if event["payload"].get("allocation_id") == allocation_id
                and event["step_id"] == step_id
            ),
            None,
        )
        if allocation is None:
            _fail(f"Unknown repair allocation {allocation_id!r}")
        if allocation["payload"]["cycle"] != current["cycle"]:
            _fail("The repair allocation belongs to another B1 cycle")
        ordinal = _next_setup_ordinal_locked(
            plan_id, journal, step_id, allocation_id
        )
        payload = {
            "version": REPAIR_VERSION,
            "allocation_id": allocation_id,
            "ordinal": ordinal,
            "outcome": "attempted",
            "issuer": _process_identity(),
            "detail": "beginning a bounded pre-claim repair setup attempt",
        }
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_REPAIR_SETUP, step_id, current["cycle"], payload)],
            "repair_setup_attempt",
            plan_id=plan_id,
            step_id=step_id,
            allocation_id=allocation_id,
            ordinal=ordinal,
        )
        setup_event_id = events[0]["event_id"]
    try:
        descriptor = d.prepare_repair_implementation(
            plan_id=plan_id,
            step_id=step_id,
            allocation_id=allocation_id,
        )
    except Exception as exc:
        try:
            record_setup_failure(
                plan_id=plan_id,
                step_id=step_id,
                allocation_id=allocation_id,
                ordinal=ordinal,
                detail=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
        raise
    descriptor["setup_ordinal"] = ordinal
    descriptor["setup_event_id"] = setup_event_id
    return descriptor


def _verify_owned_source(
    plan_id: str,
    journal: dict[str, Any],
    source: dict[str, Any],
    snapshot: dict[str, Any],
    d: Any,
) -> list[str]:
    """Prove the current tree is exactly the prior owned cumulative delta."""
    evidence = d._load_evidence_blob(
        plan_id,
        source["evidence_blob_sha256"],
        source["evidence_digest"],
        "repair source evidence",
    )
    delta = evidence.get("delta")
    if not isinstance(delta, dict):
        _fail("The repair source evidence has no owned delta")
    if sorted(delta.get("paths") or []) != sorted(
        source["cumulative_changed_paths"]
    ):
        _fail("The repair source delta paths disagree with the completion event")
    proof = evidence.get("proofs") or {}
    if not isinstance(proof.get("lease-completion.json"), dict):
        _fail("The repair source has no durable B2 completion receipt proof")
    b2 = evidence.get("b2") or {}
    if b2.get("finalized") is not True:
        _fail("The repair source B2 evidence is not finalized")
    entries = snapshot.get("entries") or {}
    for entry in delta.get("entries") or []:
        path = entry.get("path")
        current = entries.get(path)
        if entry.get("deleted"):
            if isinstance(current, dict) and current.get("kind") != "missing":
                _fail(
                    f"Repair source path {path!r} reappeared outside the owned delta"
                )
            continue
        if not isinstance(current, dict):
            _fail(f"Repair source path {path!r} is missing")
        if current.get("sha256") != entry.get("current_sha256"):
            _fail(
                f"Repair source path {path!r} no longer matches its exact owned "
                "delta"
            )
    return list(delta.get("paths") or [])


def _repair_allocation_by_id_locked(
    journal: dict[str, Any], step_id: str, allocation_id: str
) -> dict[str, Any]:
    matches = [
        event
        for event in _allocations_for_step(journal, step_id)
        if event["payload"].get("allocation_id") == allocation_id
    ]
    if len(matches) != 1:
        _fail(f"Unknown or ambiguous repair allocation {allocation_id!r}")
    return matches[0]


def _repair_intent_for_attempt_locked(
    journal: dict[str, Any],
    step_id: str,
    attempt_id: str,
    job_id: str,
    candidate_sha256: str,
    contract_digest: str,
) -> dict[str, Any]:
    matches = [
        event
        for event in journal["intents"]
        if event["step_id"] == step_id
        and event["payload"].get("attempt_id") == attempt_id
        and event["payload"].get("job_id") == job_id
        and event["payload"].get("candidate_sha256") == candidate_sha256
        and event["payload"].get("contract_digest") == contract_digest
    ]
    if len(matches) != 1:
        _fail("A repair lineage source has no unique attributed writer intent")
    return matches[0]


def _repair_ancestor_attempts_locked(
    plan_id: str,
    journal: dict[str, Any],
    step_id: str,
    cycle: int,
    candidate_sha256: str,
    contract_digest: str,
    allocation: dict[str, Any],
    source: dict[str, Any],
) -> list[str]:
    """Prove the exact fully drained rejection lineage behind one allocation.

    Ownership may transfer only from attempts that are themselves the exact
    attributed source of a durable allocation in the same step, cycle,
    candidate and contract, whose REQUEST_CHANGES review binds that source and
    whose immutable evidence proves a finalized B2 drain. The chain ends at the
    initial implementation intent. Any unrelated, torn, unknown or stale
    residue stays outside this proof and remains blocking.
    """
    d = _d()
    ancestors: list[str] = []
    seen_allocations: set[str] = set()
    seen_attempts: set[str] = set()
    allocation_event = allocation
    current_source = source
    while True:
        payload = allocation_event["payload"]
        if allocation_event["step_id"] != step_id:
            _fail("A repair lineage allocation belongs to another step")
        if allocation_event.get("cycle") != cycle or payload.get("cycle") != cycle:
            _fail("A repair lineage allocation belongs to another cycle")
        if (
            payload.get("candidate_sha256") != candidate_sha256
            or payload.get("contract_digest") != contract_digest
        ):
            _fail("A repair lineage crosses another candidate or contract")
        review = _review_by_id(
            plan_id, journal, step_id, payload["review_id"]
        )
        review_payload = review["payload"]
        if (
            review_payload.get("cycle") != cycle
            or review_payload.get("candidate_sha256") != candidate_sha256
            or review_payload.get("contract_digest") != contract_digest
        ):
            _fail("A repair lineage rejection belongs to another design binding")
        if review_payload.get("verdict") != VERDICT_REQUEST_CHANGES:
            _fail(
                "A repair lineage link does not rest on an actual "
                "REQUEST_CHANGES rejection"
            )
        if (
            review_payload.get("source_attempt_id")
            != payload.get("source_attempt_id")
            or review_payload.get("source_job_id")
            != payload.get("source_job_id")
            or review_payload.get("source_evidence_digest")
            != payload.get("source_evidence_digest")
            or review_payload.get("review_digest") != payload.get("review_digest")
        ):
            _fail("A repair lineage rejection no longer binds its exact source")
        frozen = [
            event
            for event in journal["repair_contracts"]
            if event["step_id"] == step_id
            and event["payload"].get("repair_contract_digest")
            == payload.get("repair_contract_digest")
            and event["payload"].get("review_id") == payload.get("review_id")
        ]
        if not frozen:
            _fail("A repair lineage allocation has no frozen repair contract")
        attempt_id = payload["source_attempt_id"]
        if attempt_id in seen_attempts:
            _fail("A repair lineage contains a cycle")
        seen_attempts.add(attempt_id)
        if (
            current_source.get("attempt_id") != attempt_id
            or current_source.get("job_id") != payload.get("source_job_id")
            or current_source.get("evidence_digest")
            != payload.get("source_evidence_digest")
            or current_source.get("final_snapshot_digest")
            != payload.get("source_final_snapshot_digest")
        ):
            _fail("A repair lineage source no longer matches its allocation")
        evidence = d._load_evidence_blob(
            plan_id,
            current_source["evidence_blob_sha256"],
            current_source["evidence_digest"],
            "repair lineage source evidence",
        )
        if (evidence.get("b2") or {}).get("finalized") is not True:
            _fail("A repair lineage ancestor has no finalized B2 drain")
        if not isinstance(
            (evidence.get("proofs") or {}).get("lease-completion.json"), dict
        ):
            _fail("A repair lineage ancestor has no durable B2 completion receipt")
        ancestors.append(attempt_id)
        intent = _repair_intent_for_attempt_locked(
            journal,
            step_id,
            attempt_id,
            payload["source_job_id"],
            candidate_sha256,
            contract_digest,
        )
        previous_allocation_id = intent["payload"].get("repair_allocation_id")
        if previous_allocation_id is None:
            # The initial managed writer attempt ends the proven lineage.
            break
        previous = _repair_allocation_by_id_locked(
            journal, step_id, previous_allocation_id
        )
        if previous["sequence"] >= allocation_event["sequence"]:
            _fail("A repair lineage allocation is not older than its successor")
        if int(previous["payload"].get("generation") or 0) >= int(
            payload.get("generation") or 0
        ):
            _fail("Repair lineage generations are not strictly monotonic")
        if int(intent["payload"].get("repair_generation") or 0) != int(
            previous["payload"].get("generation") or 0
        ):
            _fail("A repair intent names another formal generation")
        if (
            intent["payload"].get("parent_attempt_id")
            != previous["payload"].get("source_attempt_id")
        ):
            _fail("A repair intent does not descend from its allocation source")
        if previous_allocation_id in seen_allocations:
            _fail("A repair lineage allocation chain contains a cycle")
        seen_allocations.add(previous_allocation_id)
        previous_intent = _repair_intent_for_attempt_locked(
            journal,
            step_id,
            previous["payload"]["source_attempt_id"],
            previous["payload"]["source_job_id"],
            candidate_sha256,
            contract_digest,
        )
        current_source = _writer_source_from_intent(
            plan_id, journal, previous_intent
        )
        allocation_event = previous
    return ancestors


def repair_admission_locked(
    *,
    plan_id: str,
    step_id: str,
    allocation_id: str,
    journal: dict[str, Any],
    b1_state: dict[str, Any],
    contract: dict[str, Any],
    contract_event: dict[str, Any],
    snapshot: dict[str, Any],
    static: dict[str, Any],
    constraints: dict[str, Any],
    current: dict[str, Any],
    candidate_sha256: str,
) -> dict[str, Any]:
    """Narrow D1 hook: prove exact parent, budget and owned lineage."""
    d = _d()
    allocations = _allocations_for_step(journal, step_id)
    allocation = next(
        (
            event
            for event in allocations
            if event["payload"]["allocation_id"] == allocation_id
        ),
        None,
    )
    if allocation is None:
        _fail(f"Unknown repair allocation {allocation_id!r}")
    if allocations[-1]["digest"] != allocation["digest"]:
        _fail("A newer repair allocation supersedes this slot")
    payload = allocation["payload"]
    if payload["candidate_sha256"] != candidate_sha256:
        _fail("The repair allocation binds another candidate")
    if payload["contract_digest"] != contract_event["payload"]["contract_digest"]:
        _fail("The repair allocation binds another execution contract")
    review, _review_document = _rejection_review_locked(
        plan_id,
        journal,
        step_id,
        candidate_sha256,
        contract_event["payload"]["contract_digest"],
        payload["review_id"],
    )
    if review["payload"]["review_digest"] != payload["review_digest"]:
        _fail("The repair allocation review digest changed")
    repair_contracts = [
        event
        for event in journal["repair_contracts"]
        if event["step_id"] == step_id
        and event["payload"]["repair_contract_digest"]
        == payload["repair_contract_digest"]
        and event["payload"]["review_id"] == payload["review_id"]
    ]
    if not repair_contracts:
        _fail("The repair contract is missing")
    repair_contract_digest = payload["repair_contract_digest"]
    repair_contract_blob = d._read_blob(
        plan_id,
        payload["repair_contract_blob_sha256"],
        "repair contract",
    )
    try:
        repair_contract = json.loads(repair_contract_blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Repair contract blob is invalid: {exc}")
    if _digest(repair_contract) != repair_contract_digest:
        _fail("Repair contract blob does not match the allocation digest")
    parent_intent = _repair_intent_for_attempt_locked(
        journal,
        step_id,
        payload["source_attempt_id"],
        payload["source_job_id"],
        candidate_sha256,
        contract_event["payload"]["contract_digest"],
    )
    source = _writer_source_from_intent(plan_id, journal, parent_intent)
    if (
        source["attempt_id"] != payload["source_attempt_id"]
        or source["job_id"] != payload["source_job_id"]
        or source["evidence_digest"] != payload["source_evidence_digest"]
        or source["final_snapshot_digest"]
        != payload["source_final_snapshot_digest"]
    ):
        _fail("The repair allocation no longer binds the exact parent source")
    if d._snapshot_digest(snapshot) != payload["source_final_snapshot_digest"]:
        _fail(
            "The workspace is not the exact rejected source; unknown or user-edited "
            "residue blocks repair"
        )
    owned = _verify_owned_source(plan_id, journal, source, snapshot, d)
    original_base = json.loads(
        d._read_blob(
            plan_id,
            source["intent"]["original_base_blob_sha256"],
            "repair original base",
        ).decode("utf-8")
    )
    if d._snapshot_digest(original_base) != source["original_base_snapshot_digest"]:
        _fail("The repair original base evidence is inconsistent")
    if d._user_baseline_digest(original_base) != source["user_baseline_digest"]:
        _fail("The repair original user baseline evidence is inconsistent")
    d._require_unchanged_user_baseline(original_base, snapshot, "repair admission")
    ancestors = _repair_ancestor_attempts_locked(
        plan_id,
        journal,
        step_id,
        current["cycle"],
        candidate_sha256,
        contract_event["payload"]["contract_digest"],
        allocation,
        source,
    )
    parent_meta_path = _jobs_dir() / source["job_id"] / "meta.json"
    if parent_meta_path.is_file():
        parent_meta = _read_json(parent_meta_path)
        try:
            d._require_processes_dead(parent_meta, "repair parent job")
        except Exception as exc:
            _fail(f"The repair parent job is not fully drained: {exc}")
    attempt_id = _digest(
        {
            "allocation_id": allocation_id,
            "repair_contract_digest": repair_contract_digest,
            "source_attempt_id": source["attempt_id"],
            "source_evidence_digest": source["evidence_digest"],
            "generation": payload["generation"],
        }
    )
    defects = _open_actionable_findings(
        plan_id, journal, step_id, through_sequence=review["sequence"]
    )
    lines = [
        "# D2 formal repair contract",
        "",
        f"- Plan: `{plan_id}`",
        f"- Step: `{step_id}`",
        f"- Allocation: `{allocation_id}` (generation {payload['generation']} of {FORMAL_REPAIR_LIMIT})",
        f"- Rejection review: `{payload['review_id']}`",
        f"- Repair contract: `{repair_contract_digest}`",
        f"- Parent attempt: `{source['attempt_id']}`",
        f"- Parent job: `{source['job_id']}`",
        f"- Original base: `{source['original_base_snapshot_digest']}`",
        "",
        "## Objective",
        "",
        str(repair_contract["objective"]),
        "",
        "## Why",
        "",
        str(repair_contract["why"]),
        "",
        "## Allowed paths",
        "",
        *[f"- `{item}`" for item in repair_contract["allowed_paths"]],
        "",
        "## Denied paths",
        "",
        *[f"- `{item}`" for item in repair_contract["denied_paths"]],
        "",
        "## Actionable findings",
        "",
        *[_render_finding(finding) for finding in defects],
        "",
        "## Required behavior",
        "",
        *[f"- {item}" for item in repair_contract["required_behavior"]],
        "",
        "## Tests",
        "",
        *[f"- {item}" for item in repair_contract["tests"]],
        "",
        "Return the repair provider result. Do not commit, push, branch or change "
        "Git configuration. The frozen contract cannot be widened.",
        "",
    ]
    task_text = "\n".join(lines)
    task_dir = _plan_dir(plan_id) / "execution" / "repair-tasks"
    task_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    task_file = task_dir / f"{attempt_id}.md"
    if not task_file.exists():
        task_file.write_text(task_text, encoding="utf-8")
        os.chmod(task_file, 0o600)
    task_sha = _sha256_bytes(task_file.read_bytes())
    return {
        "attempt_id": attempt_id,
        "generation": payload["generation"],
        "allocation_id": allocation_id,
        "repair_contract": repair_contract,
        "repair_contract_digest": repair_contract_digest,
        "repair_contract_blob_sha256": payload["repair_contract_blob_sha256"],
        "parent_attempt_id": source["attempt_id"],
        "parent_job_id": source["job_id"],
        # Exactly proven settled/drained ancestors of this allocation. Only
        # these attempts may relinquish same-binding residue ownership to the
        # new formal repair; every other residue still blocks.
        "superseded_attempt_ids": ancestors,
        "source_evidence_digest": source["evidence_digest"],
        "source_final_snapshot_digest": source["final_snapshot_digest"],
        "original_base_snapshot_digest": source["original_base_snapshot_digest"],
        "original_base_blob_sha256": source["intent"]["original_base_blob_sha256"],
        "user_baseline_digest": source["user_baseline_digest"],
        "owned_paths": owned,
        "task_file": task_file,
        "task_source_sha256": task_sha,
        "task_text": task_text,
    }


# ---------------------------------------------------------------------------
# Design-cycle lineage link (no budget reset, no fresh-capture adoption)
# ---------------------------------------------------------------------------


def record_design_link(
    *,
    plan_id: str,
    step_id: str,
    previous_candidate_sha256: str,
    finding_dispositions: Any,
) -> dict[str, Any]:
    """Journal a proven new-design lineage link, or fail closed.

    The B1 unanimous cycle remains the design authority. This fact only records
    that the new candidate carries the previous owned delta and dispositions
    every open actionable finding; it never resets the repair budget.
    """
    d = _d()
    previous_candidate_sha256 = _require_digest(
        previous_candidate_sha256, "previous candidate digest"
    )
    with _b1().plan_lock(plan_id):
        b1_state = _b1().replay_plan_state_locked(plan_id)
        static = d._require_strict_plan(b1_state)
        current = d._require_consensus(b1_state, step_id)
        constraints, candidate_sha256 = d._candidate_constraints(b1_state, step_id)
        if candidate_sha256 == previous_candidate_sha256:
            _fail("A design link requires an actual new candidate cycle")
        if constraints.get("version") != d.CONTRACT_VERSION_D2:
            _fail("Design lineage requires an approved version 2 policy")
        journal = d._replay_journal(plan_id)
        previous_contracts = [
            event
            for event in journal["contracts"]
            if event["step_id"] == step_id
            and event["payload"].get("candidate_sha256")
            == previous_candidate_sha256
        ]
        if not previous_contracts:
            _fail("The previous candidate has no frozen execution contract")
        previous_contract_event = previous_contracts[-1]
        previous_cycle = previous_contract_event["cycle"]
        if current["cycle"] <= previous_cycle:
            _fail("The new design cycle is not newer than the previous contract")
        previous_source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            previous_cycle,
            previous_candidate_sha256,
            previous_contract_event["payload"]["contract_digest"],
        )
        workspace = Path(static["canonical_workspace"])
        previous_contract = d._load_contract(
            plan_id, journal, previous_contract_event
        )
        snapshot = d._observe_workspace(
            workspace, previous_contract, extra_paths=[]
        )
        _require_source_current(
            plan_id, previous_source, snapshot, "design lineage"
        )
        owned = _verify_owned_source(
            plan_id, journal, previous_source, snapshot, d
        )
        # Every open actionable finding from the actual review lineage must be
        # disposed by the new design, not merely the latest rejection's own
        # findings. Carried findings stay actionable across design cycles.
        required_findings = [
            finding["finding_id"]
            for finding in _open_actionable_findings(
                plan_id, journal, step_id
            )
        ]
        dispositions = finding_dispositions
        if not isinstance(dispositions, list):
            _fail("design finding_dispositions must be a JSON array")
        normalized: list[dict[str, str]] = []
        seen: set[str] = set()
        for index, entry in enumerate(dispositions):
            item = _exact_keys(
                entry,
                {"finding_id", "disposition", "evidence"},
                f"design_link.finding_dispositions[{index}]",
            )
            finding_id = item.get("finding_id")
            if finding_id in seen:
                _fail(f"design finding disposition {finding_id} is repeated")
            seen.add(finding_id)
            if item.get("disposition") not in {"resolved", "carried", "obsolete"}:
                _fail("design finding disposition is invalid")
            normalized.append(
                {
                    "finding_id": _require_text(
                        finding_id, "design finding_id", minimum=1
                    ),
                    "disposition": item["disposition"],
                    "evidence": _require_text(
                        item.get("evidence"), "design disposition evidence", minimum=3
                    ),
                }
            )
        missing = sorted(set(required_findings) - seen)
        if missing:
            _fail(
                "The new design must dispose every open actionable finding; "
                "missing: " + ", ".join(missing)
            )
        unknown = sorted(seen - set(required_findings))
        if unknown:
            _fail(
                "The new design disposes findings that are not open in the "
                "actual lineage: " + ", ".join(unknown)
            )
        evidence = {
            "previous_source": {
                key: previous_source[key]
                for key in (
                    "source_kind",
                    "attempt_id",
                    "job_id",
                    "evidence_digest",
                    "final_snapshot_digest",
                    "original_base_snapshot_digest",
                    "user_baseline_digest",
                )
            },
            "owned_paths": owned,
            "previous_contract_digest": previous_contract_event["payload"][
                "contract_digest"
            ],
            "previous_cycle": previous_cycle,
            "finding_dispositions": normalized,
        }
        evidence_digest = _digest(evidence)
        payload = {
            "version": DESIGN_LINK_VERSION,
            "previous_candidate_sha256": previous_candidate_sha256,
            "new_candidate_sha256": candidate_sha256,
            "previous_contract_digest": previous_contract_event["payload"][
                "contract_digest"
            ],
            "new_contract_digest": "",
            "previous_cycle": previous_cycle,
            "new_cycle": current["cycle"],
            "source_attempt_id": previous_source["attempt_id"],
            "source_evidence_digest": previous_source["evidence_digest"],
            "source_final_snapshot_digest": previous_source[
                "final_snapshot_digest"
            ],
            "original_base_snapshot_digest": previous_source[
                "original_base_snapshot_digest"
            ],
            "user_baseline_digest": previous_source["user_baseline_digest"],
            "finding_dispositions": normalized,
            "evidence_digest": evidence_digest,
        }
        new_contract = d._contract_event_for(
            journal, step_id, current["cycle"], candidate_sha256
        )
        if new_contract is not None:
            payload["new_contract_digest"] = new_contract["payload"][
                "contract_digest"
            ]
        else:
            _fail(
                "The new design has no frozen execution contract; lineage cannot "
                "be linked to an unfrozen design"
            )
        events = _append(
            plan_id,
            [_event_spec(d.TYPE_DESIGN_LINK, step_id, current["cycle"], payload)],
            "design_link",
            plan_id=plan_id,
            step_id=step_id,
            previous_candidate_sha256=previous_candidate_sha256,
            new_candidate_sha256=candidate_sha256,
        )
        return {
            "plan_id": plan_id,
            "step_id": step_id,
            "event_id": events[0]["event_id"],
            "previous_cycle": previous_cycle,
            "new_cycle": current["cycle"],
            "owned_paths": owned,
            "closed_routes": dict(CLOSED_D2_ROUTES),
        }


# ---------------------------------------------------------------------------
# Derived D2 status view
# ---------------------------------------------------------------------------


def _validation_claim_for(
    journal: dict[str, Any], validation_id: str
) -> dict[str, Any] | None:
    for event in reversed(journal["validation_claims"]):
        if event["payload"].get("validation_id") == validation_id:
            return event
    return None


def _validation_runtime_observation(
    plan_id: str,
    journal: dict[str, Any],
    intent: dict[str, Any],
    claim: dict[str, Any] | None,
) -> dict[str, Any]:
    """Classify a pending validation batch from actual durable/runtime facts.

    ``prepared``: the intent exists but was never claimed by a lease.
    ``running``: B2 can prove active ownership.
    ``drained_finalizable``: the batch is fully drained and every proof exists.
    ``drained_missing_proof``: the batch is fully drained but a proof file was
    never published (for example a SIGKILLed validator), so it can only ever
    become a durable blocked/failed batch.
    ``unreconciled``: ownership or drain cannot be proven; human/evidence
    reconciliation is required before any retry.
    """
    d = _d()
    payload = intent["payload"]
    job_path = _jobs_dir() / payload["job_id"]
    observation: dict[str, Any] = {
        "state": None,
        "live": [],
        "unprobeable": [],
        "reasons": [],
        "completion_kind": None,
        "missing_proofs": [],
    }
    if claim is None:
        observation["state"] = "prepared"
        return observation
    if not (job_path / "meta.json").is_file():
        observation["state"] = "unreconciled"
        observation["reasons"].append(
            "the claimed validation job record is missing; ownership cannot be "
            "proven and the batch must not be reused"
        )
        return observation
    try:
        meta = _read_json(job_path / "meta.json")
    except Exception as exc:
        observation["state"] = "unreconciled"
        observation["reasons"].append(
            "the claimed validation job record is unreadable: " + str(exc)
        )
        return observation
    for pid_key, start_key in (
        ("worker_pid", "worker_start"),
        ("provider_pid", "provider_start"),
        ("child_pid", "provider_start"),
        ("supervisor_pid", "supervisor_start"),
    ):
        try:
            record = d._pid_record(meta, pid_key, start_key)
        except Exception as exc:
            observation["unprobeable"].append(f"{pid_key}: {exc}")
            continue
        if record is None:
            continue
        probe = d._process_probe(record)
        if probe == "alive":
            observation["live"].append(pid_key)
        elif probe != "dead":
            observation["unprobeable"].append(f"{pid_key}: {probe}")
    try:
        completion = d._b2_completion(meta, job_path)
    except Exception as exc:
        observation["state"] = "unreconciled"
        observation["reasons"].append(
            "the actual B2 completion evidence is unavailable: " + str(exc)
        )
        return observation
    kind = completion.get("kind")
    observation["completion_kind"] = kind
    if kind == "failed_admission":
        observation["state"] = "drained_finalizable"
        return observation
    if kind == "finalized":
        missing = [
            name
            for name in VALIDATION_PROOF_FILES
            if not (job_path / name).is_file()
        ]
        observation["missing_proofs"] = missing
        if missing:
            observation["state"] = "drained_missing_proof"
            observation["reasons"].append(
                "the fully drained validation batch is missing proof files: "
                + ", ".join(missing)
            )
        else:
            observation["state"] = "drained_finalizable"
        return observation
    if kind == "pending":
        observation["state"] = "running"
        return observation
    if observation["live"]:
        observation["state"] = "running"
        return observation
    observation["state"] = "unreconciled"
    observation["reasons"].append(
        "the validation batch ownership is "
        f"{kind!r} and no recorded process can prove it is still running"
    )
    return observation


def _blocked_validation_view(
    view: dict[str, Any],
    *,
    reasons: list[str],
    next_action: str,
    invalidated_by: str,
) -> dict[str, Any]:
    view["stage"] = STAGE_BLOCKED
    view["blocked_reasons"] = [str(reason) for reason in reasons if reason][:20]
    view["approval"] = {
        "valid": False,
        "invalidated_by": invalidated_by,
    }
    view["next_action"] = next_action
    view["missing_actions"] = [next_action]
    return view


def _d2_step_view(
    plan_id: str,
    state: dict[str, Any],
    journal: dict[str, Any],
    step: dict[str, Any],
) -> dict[str, Any]:
    d = _d()
    step_id = step["id"]
    b1_step = state["steps"].get(step_id)
    view: dict[str, Any] = {
        "version": D2_VERSION,
        "active": False,
        "step_id": step_id,
        "stage": None,
        "next_action": None,
        "missing_actions": [],
        "blocked_reasons": [],
        "validation": None,
        "review": None,
        "approval": {"valid": False},
        "repair_budget": {
            "limit": FORMAL_REPAIR_LIMIT,
            "used": 0,
            "remaining": FORMAL_REPAIR_LIMIT,
            "lineage": "per-step across designs and restarts",
            "consumption": "DURABLE_ALLOCATION",
        },
        "setup_attempts": None,
        "closed_routes": dict(CLOSED_D2_ROUTES),
        "limitations": [
            "Codex review judgment cannot be mathematically authenticated",
            "session structure is coordinator authority, not proof of reasoning",
            "privileged validation retains host access despite read-only guards",
        ],
    }
    if not isinstance(b1_step, dict) or b1_step.get("cycle") is None:
        return view
    candidate = b1_step.get("candidate") or {}
    candidate_sha256 = candidate.get("digest")
    if not isinstance(candidate_sha256, str):
        return view
    cycle = b1_step["cycle"]
    contract_event = d._contract_event_for(
        journal, step_id, cycle, candidate_sha256
    )
    if contract_event is None:
        return view
    contract = d._load_contract(plan_id, journal, contract_event)
    if contract.get("version") != d.CONTRACT_VERSION_D2:
        # A version 1 plan retains its exact D1 view; D2 never upgrades it.
        return view
    view["active"] = True
    allocations = _allocations_for_step(journal, step_id)
    view["repair_budget"].update(
        {
            "used": len(allocations),
            "remaining": max(0, FORMAL_REPAIR_LIMIT - len(allocations)),
        }
    )
    current_allocations = [
        event
        for event in allocations
        if event["payload"].get("candidate_sha256") == candidate_sha256
        and event["payload"].get("contract_digest")
        == contract_event["payload"]["contract_digest"]
    ]
    latest_allocation = (
        current_allocations[-1] if current_allocations else None
    )
    step_intents = [
        event for event in journal["intents"] if event["step_id"] == step_id
    ]
    latest_writer = step_intents[-1] if step_intents else None
    if latest_writer is not None and latest_writer["payload"].get(
        "repair_allocation_id"
    ):
        repair_state = d._attempt_state(
            journal, latest_writer["payload"]["attempt_id"]
        )["state"]
        if repair_state in {"pending", "claimed"}:
            view["stage"] = STAGE_REPAIRING
            view["next_action"] = (
                "wait for the formal repair to settle and finalize its immutable "
                "evidence"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
    if latest_allocation is not None:
        setup_events = [
            event
            for event in journal["repair_setups"]
            if event["payload"]["allocation_id"]
            == latest_allocation["payload"]["allocation_id"]
        ]
        used_ordinals = {
            int(event["payload"]["ordinal"]) for event in setup_events
        }
        view["setup_attempts"] = {
            "limit": SETUP_ATTEMPT_LIMIT,
            "used": len(used_ordinals),
            "remaining": max(0, SETUP_ATTEMPT_LIMIT - len(used_ordinals)),
        }
    current_intents = [
        event
        for event in journal["intents"]
        if event["step_id"] == step_id
        and event["cycle"] == cycle
        and event["payload"].get("candidate_sha256") == candidate_sha256
        and event["payload"].get("contract_digest")
        == contract_event["payload"]["contract_digest"]
    ]
    d2_history = (
        any(event["step_id"] == step_id for event in journal["reviews"])
        or any(
            event["step_id"] == step_id
            for event in journal["repair_allocations"]
        )
        or any(
            event["step_id"] == step_id
            for event in journal["validation_intents"]
        )
        or any(
            event["step_id"] == step_id
            for event in journal["repair_contracts"]
        )
        or any(event["step_id"] == step_id for event in journal["design_links"])
    )
    if not current_intents:
        linked = [
            event
            for event in journal["design_links"]
            if event["step_id"] == step_id
            and event["payload"].get("new_candidate_sha256")
            == candidate_sha256
            and event["payload"].get("new_contract_digest")
            == contract_event["payload"]["contract_digest"]
        ]
        if linked or d2_history:
            if linked:
                reason = (
                    "the new design has a proven linked source lineage, but this "
                    "implementation has no consumer that can carry the previous "
                    "owned source, open findings and custody into fresh current "
                    "validation or review; reporting READY would advertise an "
                    "unexecutable route"
                )
                guidance = (
                    "request explicit human guidance for the unsupported linked "
                    "source carry; no initial writer, validation or review may "
                    "relabel the previous design's source or approval as authority"
                )
            else:
                reason = (
                    "D2 review/repair ownership exists for this step under an "
                    "earlier design/source, and the current candidate has no "
                    "managed writer invocation or proven design link; the initial "
                    "writer route is closed"
                )
                guidance = (
                    "reconcile the earlier D2 ownership explicitly; no automatic "
                    "initial writer or unlinked source carry is available"
                )
            return _blocked_validation_view(
                view,
                reasons=[reason],
                next_action=guidance,
                invalidated_by="no-current-d2-source",
            )
        # A brand-new version 2 step with no D2 ownership yet: the D1
        # ready-to-implement route is the honest state. D2 adds no stage.
        view["next_action"] = None
        return view
    try:
        source = _latest_writer_source_locked(
            plan_id,
            journal,
            step_id,
            cycle,
            candidate_sha256,
            contract_event["payload"]["contract_digest"],
        )
    except Exception as exc:
        if not d2_history:
            # Only unsettled/aborted initial intents exist and no D2 ownership
            # was created; D1's pending/ready view remains authoritative.
            view["next_action"] = None
            return view
        return _blocked_validation_view(
            view,
            reasons=[str(exc)],
            next_action=(
                "reconcile the managed writer source evidence; D2 cannot "
                "validate or review an unsettled or unproven source"
            ),
            invalidated_by="unsettled-writer-source",
        )
    validation = _latest_validation(
        journal, step_id, candidate_sha256, contract_event["payload"]["contract_digest"]
    )
    review = _latest_review(
        journal, step_id, candidate_sha256, contract_event["payload"]["contract_digest"]
    )
    validation_intents = [
        event
        for event in journal["validation_intents"]
        if event["step_id"] == step_id
        and event["payload"].get("candidate_sha256") == candidate_sha256
        and event["payload"].get("contract_digest")
        == contract_event["payload"]["contract_digest"]
    ]
    result_ids = {
        event["payload"].get("validation_id")
        for event in journal["validation_results"]
    }
    pending_validation = [
        event
        for event in validation_intents
        if event["payload"].get("validation_id") not in result_ids
    ]
    if validation is not None and validation["payload"].get(
        "source_evidence_digest"
    ) != source["evidence_digest"]:
        validation = None
    if review is not None and review["payload"].get(
        "source_evidence_digest"
    ) != source["evidence_digest"]:
        review = None
    if validation is not None:
        view["validation"] = {
            "validation_id": validation["payload"]["validation_id"],
            "job_id": validation["payload"]["job_id"],
            "classification": validation["payload"]["classification"],
            "counts": validation["payload"]["counts"],
            "reasons": list(validation["payload"]["reasons"])[:20],
            "event_id": validation["event_id"],
            "digest": validation["digest"],
            "source_evidence_digest": validation["payload"][
                "source_evidence_digest"
            ],
            "generation": validation["payload"]["generation"],
        }
    if review is not None:
        view["review"] = {
            "review_id": review["payload"]["review_id"],
            "verdict": review["payload"]["verdict"],
            "generation": review["payload"]["generation"],
            "validation_id": review["payload"]["validation_id"],
            "validation_digest": review["payload"]["validation_digest"],
            "finding_counts": review["payload"]["finding_counts"],
            "criteria_counts": review["payload"]["criteria_counts"],
            "event_id": review["event_id"],
            "digest": review["digest"],
        }
    # A derived REVIEW_APPROVED projection is only current if the live source
    # still matches the exact attributed writer source and the frozen branch,
    # HEAD, Git index and original-user custody. The immutable historical
    # review/report evidence above is retained; only current authority is
    # invalidated. This reuses the actual D1 observation primitives.
    static = state.get("static") or {}
    workspace_value = static.get("canonical_workspace")
    if not isinstance(workspace_value, str) or not workspace_value:
        return _blocked_validation_view(
            view,
            reasons=[
                "the canonical workspace is not recorded in the plan state; "
                "current source custody cannot be observed"
            ],
            next_action=(
                "reconcile the plan workspace evidence; no approval can be "
                "presented without an actual current-source observation"
            ),
            invalidated_by="unobservable-current-source",
        )
    try:
        current_snapshot = d._observe_workspace(
            Path(workspace_value), contract, extra_paths=[]
        )
        d._require_branch_and_head(
            current_snapshot, contract, "D2 current-source projection"
        )
        _require_source_current(
            plan_id, source, current_snapshot, "D2 current-source projection"
        )
    except Exception as exc:
        view["source_drift"] = True
        return _blocked_validation_view(
            view,
            reasons=[
                "the current source, HEAD, Git index or original-user custody "
                "no longer matches the exact attributed writer source: " + str(exc)
            ],
            next_action=(
                "preserve the current bytes and request explicit reconciliation; "
                "the immutable historical review/report evidence is retained, but "
                "no current approval is valid and no automatic revert exists"
            ),
            invalidated_by="current-source-drift",
        )
    repair_intent = (
        latest_writer
        if latest_writer is not None
        and latest_writer["payload"].get("repair_allocation_id")
        else None
    )
    repair_state = None
    if repair_intent is not None:
        repair_state = d._attempt_state(
            journal, repair_intent["payload"]["attempt_id"]
        )["state"]
    # Pending newer validation always wins over older approval evidence.
    if pending_validation and (
        validation is None or pending_validation[-1]["sequence"] > validation["sequence"]
    ):
        pending_event = pending_validation[-1]
        latest_pending = pending_event["payload"]
        claim_event = _validation_claim_for(
            journal, latest_pending["validation_id"]
        )
        runtime = _validation_runtime_observation(
            plan_id, journal, pending_event, claim_event
        )
        view["validation_runtime"] = {
            "validation_id": latest_pending["validation_id"],
            "job_id": latest_pending["job_id"],
            "state": runtime["state"],
            "completion_kind": runtime["completion_kind"],
            "missing_proofs": list(runtime["missing_proofs"]),
            "live_processes": list(runtime["live"]),
            "unprobeable_processes": list(runtime["unprobeable"]),
        }
        if runtime["state"] == "prepared":
            view["stage"] = STAGE_AWAITING_VALIDATION
            view["next_action"] = (
                "launch the pending validation intent or abort it as a no-start"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if runtime["state"] == "running":
            view["stage"] = STAGE_VALIDATING
            view["next_action"] = (
                "wait for the claimed validation batch to settle, then finalize "
                "its immutable evidence"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if runtime["state"] == "drained_finalizable":
            view["stage"] = STAGE_VALIDATING
            view["next_action"] = (
                "the validation batch is fully drained; finalize its immutable "
                "evidence with execution-validation-finalize"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if runtime["state"] == "drained_missing_proof":
            view["validation"] = None
            return _blocked_validation_view(
                view,
                reasons=list(runtime["reasons"]),
                next_action=(
                    "the dead validation batch can only become a durable failed/"
                    "blocked result; run execution-validation-finalize to record "
                    "it, then start a fresh validation batch against the unchanged "
                    "source if custody still holds. The older approval is not "
                    "reused and no missing positive evidence is recreated."
                ),
                invalidated_by="dead-validation-missing-evidence",
            )
        view["validation"] = None
        return _blocked_validation_view(
            view,
            reasons=list(runtime["reasons"])
            or ["the claimed validation batch cannot be proven running or drained"],
            next_action=(
                "reconcile the validation job, B2 receipt and recorded processes "
                "explicitly; do not reopen a potentially live lease, recreate "
                "missing evidence or fall back to an older approval"
            ),
            invalidated_by="unreconciled-validation",
        )
    if validation is None:
        if repair_state in {"pending", "claimed"}:
            view["stage"] = STAGE_REPAIRING
            view["next_action"] = "wait for the formal repair to settle and finalize"
            view["missing_actions"] = [view["next_action"]]
            return view
        if repair_state in {"complete", "drained_success", "drained_failure"}:
            view["stage"] = STAGE_AWAITING_VALIDATION
            view["next_action"] = (
                "run fresh independent validation against the repaired source"
            )
            view["missing_actions"] = [view["next_action"]]
            return view
        if latest_allocation is not None:
            view["stage"] = STAGE_REPAIR_PREPARED
            view["next_action"] = (
                "prepare the allocated formal repair without exceeding three "
                "pre-claim setup attempts"
            )
        else:
            view["stage"] = STAGE_AWAITING_VALIDATION
            view["next_action"] = (
                "run the frozen validation policy against the exact current source"
            )
        view["missing_actions"] = [view["next_action"]]
        return view
    classification = validation["payload"]["classification"]
    if classification != "passed":
        if review is not None and review["payload"]["verdict"] == VERDICT_REQUEST_CHANGES:
            if latest_allocation is not None and (
                latest_allocation["sequence"] > review["sequence"]
            ):
                if repair_state in {"pending", "claimed"}:
                    view["stage"] = STAGE_REPAIRING
                    view["next_action"] = "wait for the formal repair to settle"
                else:
                    view["stage"] = STAGE_REPAIR_PREPARED
                    view["next_action"] = "prepare the allocated formal repair"
            else:
                view["stage"] = STAGE_REPAIR_REQUIRED
                view["next_action"] = (
                    "freeze a repair contract and allocate one formal repair slot"
                )
        else:
            view["stage"] = (
                STAGE_VALIDATION_BLOCKED
                if classification in {"blocked", "uncertain"}
                else STAGE_VALIDATION_FAILED
            )
            view["next_action"] = (
                "the latest mandatory validation did not pass; review the actual "
                "failure and record an independent REQUEST_CHANGES or fix the "
                "validation context explicitly"
            )
            view["blocked_reasons"] = list(validation["payload"]["reasons"])[:20]
        view["missing_actions"] = [view["next_action"]]
        return view
    # Validation passed.
    if review is None:
        view["stage"] = STAGE_AWAITING_REVIEW
        view["next_action"] = (
            "issue a single-use session and record the actual active-Codex review"
        )
        view["missing_actions"] = [view["next_action"]]
        return view
    if review["payload"]["verdict"] == VERDICT_APPROVE:
        if (
            review["payload"]["validation_digest"] == validation["digest"]
            and review["payload"]["validation_id"]
            == validation["payload"]["validation_id"]
            and source["source_kind"] == "complete"
        ):
            view["stage"] = STAGE_REVIEW_APPROVED
            view["approval"] = {
                "valid": True,
                "review_id": review["payload"]["review_id"],
                "review_digest": review["payload"]["review_digest"],
                "validation_id": validation["payload"]["validation_id"],
                "validation_digest": validation["digest"],
                "source_evidence_digest": source["evidence_digest"],
                "source_kind": source["source_kind"],
                "generation": source["generation"],
            }
            view["next_action"] = (
                "D2 ends at REVIEW_APPROVED; PR/CI/MERGED and dependency opening "
                "remain closed until E"
            )
            view["missing_actions"] = []
            return view
        view["stage"] = STAGE_AWAITING_REVIEW
        view["approval"] = {
            "valid": False,
            "invalidated_by": "a newer validation batch or source superseded the review",
        }
        view["next_action"] = "record a fresh review against the current evidence"
        view["missing_actions"] = [view["next_action"]]
        return view
    # Current rejection.
    if latest_allocation is not None and latest_allocation["sequence"] > review["sequence"]:
        if repair_state in {"pending", "claimed"}:
            view["stage"] = STAGE_REPAIRING
            view["next_action"] = "wait for the formal repair to settle and finalize"
        elif repair_state in {"drained_failure", "drained_success", "complete"}:
            view["stage"] = STAGE_AWAITING_VALIDATION
            view["next_action"] = (
                "run fresh independent validation against the repaired source"
            )
        elif (
            view.get("setup_attempts")
            and view["setup_attempts"]["used"] >= SETUP_ATTEMPT_LIMIT
        ):
            view["stage"] = STAGE_BLOCKED
            view["blocked_reasons"].append(
                "the current formal repair slot exhausted its three pre-claim "
                "setup attempts; human guidance is required"
            )
            view["next_action"] = (
                "obtain human guidance; no fourth setup attempt or refund exists "
                "in this slot"
            )
        else:
            view["stage"] = STAGE_REPAIR_PREPARED
            view["next_action"] = "prepare the allocated formal repair"
    else:
        view["stage"] = STAGE_REPAIR_REQUIRED
        view["next_action"] = (
            "freeze a repair contract and allocate one formal repair slot"
            if view["repair_budget"]["remaining"] > 0
            else "the formal repair budget is exhausted; human guidance is required"
        )
        if view["repair_budget"]["remaining"] == 0:
            view["blocked_reasons"].append(
                "formal repair budget exhausted for this step"
            )
    view["missing_actions"] = [view["next_action"]]
    return view


def d2_overlay(
    *, plan_id: str, state: dict[str, Any], journal: dict[str, Any]
) -> dict[str, Any]:
    """Derive the plan-level D2 stage from the shared immutable journal."""
    d = _d()
    static = state.get("static") or {}
    manifest = (static.get("manifest") or {}).get("steps") or []
    steps = {
        step["id"]: _d2_step_view(plan_id, state, journal, step)
        for step in manifest
    }
    ordered = [steps[step["id"]] for step in manifest]
    active = [view for view in ordered if view.get("active")]
    if not active:
        return {
            "version": D2_VERSION,
            "active": False,
            "stage": None,
            "steps": steps,
            "next_action": None,
            "missing_actions": [],
            "blocked_reasons": [],
            "closed_routes": dict(CLOSED_D2_ROUTES),
        }
    unfinished = [
        view for view in active if view["stage"] != STAGE_REVIEW_APPROVED
    ]
    selected = unfinished[0] if unfinished else active[-1]
    return {
        "version": D2_VERSION,
        "active": True,
        "stage": selected["stage"],
        "steps": steps,
        "validation": selected.get("validation"),
        "review": selected.get("review"),
        "approval": selected.get("approval"),
        "repair_budget": selected.get("repair_budget"),
        "setup_attempts": selected.get("setup_attempts"),
        "next_action": selected.get("next_action"),
        "missing_actions": [
            f"{view['step_id']}: {action}"
            for view in ordered
            for action in view.get("missing_actions") or []
        ],
        "blocked_reasons": [
            f"{view['step_id']}: {reason}"
            for view in ordered
            for reason in view.get("blocked_reasons") or []
        ],
        "closed_routes": dict(CLOSED_D2_ROUTES),
        "limitations": selected.get("limitations"),
        "d2_never_done": True,
    }


# ---------------------------------------------------------------------------
# Pinned coordinator-owned structured unittest adapter
# ---------------------------------------------------------------------------


def _adapter_sanitizer() -> tuple[Any, Any] | None:
    """Load the shared C sanitizer for the pinned adapter's own report.

    The adapter runs inside the validation sandbox where only this exact file
    is exposed. If the helper cannot be loaded the parent still applies the
    authoritative known-value redaction before any blob/head_text persistence,
    so failure here never grants an unsanitized durable surface.
    """
    try:
        import importlib.util

        path = Path(__file__).resolve().with_name("c_providers.py")
        if not path.is_file():
            return None
        spec = importlib.util.spec_from_file_location(
            "agent_orchestrator_c_sanitizer", path
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, module.Redactor([])
    except Exception:
        return None


def _write_adapter_report(path: str, document: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = target.with_name(
        f".{target.name}.{secrets.token_hex(4)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _unittest_adapter_main(arguments: list[str]) -> int:
    """Pinned stdlib unittest adapter emitting structured machine evidence."""
    report_path = os.environ.get(DEFAULT_REPORT_ENV)
    run_id = os.environ.get(RUN_ID_ENV)
    started_at = _now_iso()
    if not report_path or not run_id:
        print(
            "structured adapter requires D2_STRUCTURED_REPORT and "
            "D2_STRUCTURED_RUN_ID",
            file=sys.stderr,
        )
        return 70
    argv = ["d2-adapter", *arguments]
    failures: list[str] = []
    errors: list[str] = []
    skips: list[str] = []
    expected_failures: list[str] = []
    unexpected_successes: list[str] = []
    adapter_error = None
    tests_run = 0

    class StructuredResult(unittest.TextTestResult):
        def _identity(self, test: Any) -> str:
            try:
                return str(test.id())
            except Exception:
                return "<unidentifiable-test>"

        def addFailure(self, test, err):
            failures.append(self._identity(test))
            super().addFailure(test, err)

        def addError(self, test, err):
            errors.append(self._identity(test))
            super().addError(test, err)

        def addSkip(self, test, reason):
            skips.append(self._identity(test))
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            expected_failures.append(self._identity(test))
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            unexpected_successes.append(self._identity(test))
            super().addUnexpectedSuccess(test)

    try:
        program = unittest.main(
            module=None,
            argv=argv,
            exit=False,
            testRunner=unittest.TextTestRunner(
                stream=sys.stderr, verbosity=2, resultclass=StructuredResult
            ),
            verbosity=2,
        )
        result = getattr(program, "result", None)
        if result is not None:
            tests_run = int(getattr(result, "testsRun", 0) or 0)
    except BaseException as exc:  # adapter must still publish bounded evidence
        adapter_error = f"{type(exc).__name__}: {exc}"[:500]
        if isinstance(exc, KeyboardInterrupt):
            adapter_error = "keyboard interrupt"
    counts = {
        "collected": tests_run,
        "run": tests_run,
        "passed": max(
            0,
            tests_run
            - len(failures)
            - len(errors)
            - len(skips)
            - len(expected_failures)
            - len(unexpected_successes),
        ),
        "failures": len(failures),
        "errors": len(errors),
        "skips": len(skips),
    }
    observed_argv = list(
        getattr(sys, "orig_argv", None) or [sys.executable, *sys.argv]
    )
    document = {
        "version": 1,
        "adapter_id": DEFAULT_ADAPTER_ID,
        "adapter_version": 1,
        "run_id": run_id,
        "argv": observed_argv,
        "argv_sha256": _digest(observed_argv),
        "cwd": os.getcwd(),
        "python": sys.version.split()[0],
        "started_at": started_at,
        "finished_at": _now_iso(),
        "counts": counts,
        "identities": {
            "failures": failures[:10_000],
            "errors": errors[:10_000],
            "skips": skips[:10_000],
            "expected_failures": expected_failures[:10_000],
            "unexpected_successes": unexpected_successes[:10_000],
        },
        "adapter_error": adapter_error,
    }
    sanitizer = _adapter_sanitizer()
    if sanitizer is not None:
        c, adapter_redactor = sanitizer
        try:
            if isinstance(document.get("identities"), dict):
                document["identities"] = c.sanitize_structure(
                    adapter_redactor, document["identities"]
                )
            if document.get("adapter_error"):
                document["adapter_error"] = adapter_redactor.sanitize_text(
                    document["adapter_error"]
                )
        except Exception:
            document["adapter_error"] = "sanitizer failure"
            document["identities"] = {
                key: []
                for key in (
                    "failures",
                    "errors",
                    "skips",
                    "expected_failures",
                    "unexpected_successes",
                )
            }
            document["counts"] = {
                "collected": 0,
                "run": 0,
                "passed": 0,
                "failures": 0,
                "errors": 0,
                "skips": 0,
            }
    try:
        _write_adapter_report(report_path, document)
    except Exception as exc:
        print(f"cannot write structured report: {exc}", file=sys.stderr)
        return 71
    if adapter_error:
        return 1
    if failures or errors or expected_failures or unexpected_successes or counts["collected"] == 0:
        return 1
    return 0


def _now_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["_unittest-adapter"]:
        return _unittest_adapter_main(arguments[1:])
    print(
        "d_review is loaded by cli_agent_job.py; the only standalone entry "
        "point is _unittest-adapter",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":  # pragma: no cover - direct adapter invocation
    raise SystemExit(main())
