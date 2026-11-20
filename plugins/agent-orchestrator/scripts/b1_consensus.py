#!/usr/bin/env python3
"""B1 durable research-team consensus ledger, gates, and projections.

This module is loaded by ``cli_agent_job.py`` through an absolute-path import so
that callers which load the runner with ``importlib`` do not need this scripts
directory on ``sys.path``. The runner supplies a small set of hooks (error type,
state paths, record lock, atomic JSON writer, clock, canonical workspace
identity, and active-job lookup).

Design summary (operator-authorized cycle 2 amendment):

* The plan directory remains the storage boundary. One immutable, ordered JSON
  event file is published per transition under ``consensus/events``. Events are
  written to a same-filesystem temporary file, fsynced, atomically replaced, and
  the directory is fsynced while the plan record lock is held.
* A replayed ledger is authoritative. Computed ``plan.json``/``checkpoint.json``
  views and the Markdown artifacts are regenerated from the ledger after every
  mutation and whenever a checkpoint is read.
* Calls carry stable operation IDs. An exact retry returns the already published
  events; reuse with different content fails.
* Policy version 2 is the active, fixed three-role slot (Codex, DeepSeek, GLM).
  It completes round 1 proposals, round 2 cross-examination, one frozen
  candidate, and round 3 explicit ballots. Consensus is frozen only on three
  AGREE ballots against the exact frozen digest. A non-unanimous final tally
  requires a recorded, human-authorized new cycle; it never overrides the
  unanimity gate.
* Policy version 1 (Codex, Antigravity, DeepSeek, GLM) is retained strictly as
  historical evidence. Its ledgers replay with their original roster, votes,
  digests and artifact bytes, but every read is in-memory only and every
  mutation fails closed. The operator removed Antigravity, so no v1 action may
  launch that provider or synthesize its missing agreement; operators create a
  new policy version 2 plan instead.
* The active policy version is explicit in enrollment, replay, binding and
  artifact rendering. Unknown versions fail closed, the candidate digest binds
  the policy version and roster, and cross-version or stale ballots never
  count.
* Canonical Git workspace enrollment blocks every ordinary runner writer in B1,
  including override flags, alternate path forms, Git administrative
  directories, bare repositories and alternate state homes. The durable
  enrollment marker and lock live in the repository's Git common directory;
  intent records make the pre-first-event interval recoverable and bind recovery
  to the owning state home and the exact normalized request.
* Every admitted launch publishes a repository-local active-job reservation.
  Enrollment consults those reservations in addition to its own state home, so
  a live worker or provider admitted elsewhere blocks enrollment until the
  recorded processes exit.
* Dependent steps stay ``DEPENDENCY_BLOCKED`` until independently verified
  MERGED evidence exists. B1 has no command that can mint it.
* Each step owns deterministic ``steps/<step-id>/`` and
  ``steps/<step-id>/cycle-<n>/`` bundles regenerated only from the immutable
  ledger with the policy-specific artifact set (six for policy version 2,
  seven for historical policy version 1).
* B1 has no managed writer. After ``CONSENSUS_REACHED`` a recorded human
  authorization may open a fresh cycle, but the policy's unanimous AGREE
  ballots are always required. Historical policy version 1 ledgers cannot be
  reopened.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator

POLICY_NAME = "b1-durable-consensus"
# Policy version 2 is the active, fixed Codex/DeepSeek/GLM roster. Policy
# version 1 is archived history: it remains replayable byte-for-byte but is
# never mutable, never rendered over, and can never launch the removed
# Antigravity provider.
ACTIVE_POLICY_VERSION = 2
HISTORICAL_POLICY_VERSION = 1
POLICY_VERSION = ACTIVE_POLICY_VERSION
SUPPORTED_POLICY_VERSIONS = (HISTORICAL_POLICY_VERSION, ACTIVE_POLICY_VERSION)
MUTABLE_POLICY_VERSIONS = (ACTIVE_POLICY_VERSION,)
POLICY_ROLES = {
    HISTORICAL_POLICY_VERSION: ("codex", "antigravity", "deepseek", "glm"),
    ACTIVE_POLICY_VERSION: ("codex", "deepseek", "glm"),
}
ROLES = POLICY_ROLES[POLICY_VERSION]
ROLE_LABELS = {
    "codex": "Codex",
    "antigravity": "Antigravity",
    "deepseek": "DeepSeek",
    "glm": "GLM",
}
VOTES = ("AGREE", "DISAGREE", "NEEDS_DISCUSSION")
DEFAULT_ROUND_BUDGET = 3
HISTORICAL_V1_GUIDANCE = (
    "Policy version 1 is a historical, read-only four-agent record. The operator "
    "removed Antigravity, so this ledger cannot advance, be upgraded in place, or "
    "synthesize the missing agreement. Preserve it for provenance and create a new "
    "policy version 2 replacement plan in a checkout that is not enrolled in this "
    "historical plan, with `create-plan --research-team --policy-version 2` (the "
    "default) for the active Codex, DeepSeek and GLM team. This historical checkout "
    "and its bytes remain unchanged and protected."
)

STAGE_PROPOSALS = "PROPOSALS_OPEN"
STAGE_CROSS = "CROSS_EXAMINATION_OPEN"
STAGE_CANDIDATE = "CANDIDATE_REQUIRED"
STAGE_BALLOTS = "BALLOTS_OPEN"
STAGE_CONSENSUS = "CONSENSUS_REACHED"
STAGE_HUMAN = "HUMAN_DECISION_REQUIRED"
STAGE_DEPENDENCY = "DEPENDENCY_BLOCKED"

MAX_EVENT_BYTES = 65_536
MAX_SUBMISSION_BYTES = 32_768
MAX_CANDIDATE_BYTES = 32_768
MAX_TEXT_BYTES = 8_192
MAX_ITEM_BYTES = 2_048
MAX_LIST_ITEMS = 20
MAX_STEPS = 50
MAX_STEP_BYTES = 16_384

# D1 managed execution. These constants extend the discussion schema only when
# a plan was enrolled in strict execution mode; historical and legacy ledgers
# never contain them and therefore keep their exact original bytes and digests.
STRICT_EXECUTION_KEY = "strict_execution"
EXECUTION_CONSTRAINTS_VERSION = 1
MAX_CONSTRAINT_PATTERNS = 64
MAX_CONSTRAINT_CRITERIA = 50
MAX_VALIDATION_COMMANDS = 32
MAX_VALIDATION_ARGV = 64
MAX_VALIDATION_ARG_BYTES = 4_096
MAX_PATTERN_BYTES = 4_096
CRITERION_ID_RE = re.compile(r"^C[0-9]{3}$")

ZERO_DIGEST = "0" * 64
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RETRY_ID_RE = ID_RE
EVENT_FILE_RE = re.compile(r"^[0-9]{6}\.json$")

ARTIFACT_BRIEF = "DISCUSSION_BRIEF.md"
ARTIFACT_PROPOSALS = {
    role: f"PROPOSAL_{ROLE_LABELS[role].upper()}.md" for role in ROLE_LABELS
}
ARTIFACT_LOG = "DISCUSSION_LOG.md"
ARTIFACT_CONSENSUS = "CONSENSUS.md"


def step_artifact_names(policy_version: int) -> tuple[str, ...]:
    """Return the artifact set for a policy version.

    Policy version 2 binds the fixed three-role team. Policy version 1 history
    retains its four proposal documents; its existing bytes are never rewritten.
    """
    roles = POLICY_ROLES.get(policy_version)
    if roles is None:
        _fail(f"Unknown research policy version {policy_version!r}")
    return (
        ARTIFACT_BRIEF,
        *(ARTIFACT_PROPOSALS[role] for role in roles),
        ARTIFACT_LOG,
        ARTIFACT_CONSENSUS,
    )


STEP_ARTIFACT_NAMES = step_artifact_names(ACTIVE_POLICY_VERSION)

MARKER_KEYS = {
    "version",
    "plan_id",
    "canonical_workspace",
    "workspace_project_id",
    "git_common_dir",
    "policy_version",
    "enrolled_at",
    "plans_dir",
}
INTENT_KEYS = {
    "version",
    "plan_id",
    "canonical_workspace",
    "workspace_project_id",
    "staging",
    "created_at",
    "plans_dir",
    "request_digest",
}
STAGING_MARKER = ".b1-staging.json"
STAGING_PREFIX = ".enroll-"

# Repository-local active-job reservations. They live in the Git common
# directory so enrollment in one state home can see a runner job admitted
# through any other state home. The record is advisory evidence, not a security
# boundary; liveness comes from the recorded coordinator, worker and provider
# process IDs.
#
# Version 2 files are named ``<job_id>.<reservation_id>.json``. The random
# reservation identity is the ownership token: it is unique across state homes
# and launches, and every update or release names the exact record it owns, so
# two admitted jobs with the same job ID can never overwrite or release each
# other's evidence. Version 1 files (``<job_id>.json``) are read and pruned for
# safe handling of jobs admitted before this schema, but are never written or
# released by new code.
RESERVATION_VERSION = 2
LEGACY_RESERVATION_VERSION = 1
RESERVATION_DIR = "active-jobs"
RESERVATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
RESERVATION_COMMON_KEYS = {
    "version",
    "job_id",
    "canonical_workspace",
    "git_common_dir",
    "state_home",
    "plans_dir",
    "job_dir",
    "coordinator_pid",
    "worker_pid",
    "provider_pid",
    "created_at",
    "updated_at",
}
RESERVATION_KEYS = RESERVATION_COMMON_KEYS | {"reservation_id"}
LEGACY_RESERVATION_KEYS = set(RESERVATION_COMMON_KEYS)
RESERVATION_PID_KEYS = ("coordinator_pid", "worker_pid", "provider_pid")

ALLOWED_STEP_KEYS = {
    "id",
    "objective",
    "scope",
    "deliverables",
    "acceptance_criteria",
    "depends_on",
    "brief",
}
BRIEF_KEYS = {
    "original_objective",
    "repository_context",
    "constraints",
    "proposed_approach",
    "expected_changes",
    "acceptance_criteria",
}
FORBIDDEN_EVIDENCE_KEYS = {
    "evidence",
    "verified",
    "verification",
    "merge_receipt",
    "merge_receipts",
    "merged",
    "receipt",
    "receipts",
    "status",
    "state",
    "done",
    "complete",
    "completed",
    "accepted",
    "acceptance_state",
    "implementation_state",
    "signature",
}

EVENT_KEYS = {
    "sequence",
    "event_id",
    "operation_id",
    "request_digest",
    "type",
    "at",
    "plan_id",
    "step_id",
    "cycle",
    "round",
    "payload",
    "prev_digest",
    "digest",
}

PAYLOAD_KEYS = {
    "plan_enrolled": {
        "workspace",
        "canonical_workspace",
        "workspace_project_id",
        "title",
        "workspace_mode",
        "plan_file",
        "plan_sha256",
        "policy",
        "roles",
        "round_budget",
        "manifest",
        "manifest_digest",
        "goal",
        "team_policy",
        "executor_policy",
        STRICT_EXECUTION_KEY,
    },
    "proposal_recorded": {"role", "provenance", "submission", "retry_id"},
    "cross_examination_recorded": {
        "role",
        "provenance",
        "submission",
        "retry_id",
    },
    "candidate_frozen": {"digest", "binding", "candidate", "objection_ids"},
    "ballot_recorded": {
        "role",
        "vote",
        "rationale",
        "digest",
        "provenance",
        "retry_id",
    },
    "consensus_reached": {"digest", "tally", "votes"},
    "consensus_failed": {
        "digest",
        "tally",
        "votes",
        "reason",
        "human_decision_required",
    },
    "provider_paused": {
        "role",
        "round",
        "reason",
        "guidance",
        "provenance",
        "retry_id",
    },
    "provider_resumed": {"role", "round", "retry_id"},
    "new_cycle_authorized": {
        "previous_cycle",
        "previous_outcome",
        "previous_digest",
        "authorization",
        "new_cycle",
    },
}

PROPOSAL_KEYS = {
    "approach",
    "rationale",
    "assumptions",
    "risks",
    "alternatives",
    "feasibility",
    "tests",
}
CROSS_KEYS = {"responses", "challenges", "revisions"}
CANDIDATE_KEYS = {
    "final_design",
    "important_decisions",
    "rejected_alternatives",
    "objection_dispositions",
    "remaining_risks",
}
CANDIDATE_OPTIONAL_KEYS = {"execution_constraints"}

# Optional D1 provenance fields. Old ledgers omit them entirely and replay
# against exactly the original schema.
PROPOSAL_OPTIONAL_KEYS = {"source_evidence"}
CROSS_OPTIONAL_KEYS = {"source_evidence"}
BALLOT_OPTIONAL_KEYS = {"source_evidence"}
ENROLLMENT_OPTIONAL_KEYS = {STRICT_EXECUTION_KEY}
NEW_CYCLE_AUTHORIZATION_OPTIONAL_KEYS = {"authorization_kind"}
SOURCE_EVIDENCE_KEYS = {
    "provider",
    "operation",
    "job_id",
    "evidence_digest",
    "evidence_event_id",
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
}
AUTHORIZATION_KINDS = ("human", "coordinator")

_HOOKS: dict[str, Any] = {}


def configure(**hooks: Any) -> None:
    """Install runner-provided hooks. Safe to call repeatedly."""
    _HOOKS.update(hooks)


def _hook(name: str) -> Any:
    try:
        return _HOOKS[name]
    except KeyError as exc:  # pragma: no cover - only a programming error
        raise RuntimeError(f"b1_consensus is not configured: missing {name}") from exc


def _error(message: str) -> Exception:
    return _hook("runner_error")(message)


def _fail(message: str) -> None:
    raise _error(message)


def _lease_blocker(identity: dict[str, Any]) -> str | None:
    """Consult the B2 repository writer lease through its optional hook.

    B1 owns enrollment/admission ordering; B2 owns the stable writer lease. The
    hook is optional so historical B1-only callers still work, and any failure
    to read lease state fails closed rather than admitting a writer.
    """
    hook = _HOOKS.get("lease_blocker")
    if hook is None:
        return None
    try:
        return hook(identity)
    except Exception as exc:
        return f"Repository writer lease state unavailable; failing closed: {exc}"


def _now() -> str:
    return _hook("utc_now")()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"Cannot read valid JSON from {path}: {exc}")
    if not isinstance(value, dict):
        _fail(f"Expected a JSON object in {path}")
    return value


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        _fsync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    _hook("write_json")(path, value)
    _fsync_dir(path.parent)


def _text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    stripped = value.strip()
    if len(stripped) < minimum:
        _fail(f"{label} must contain at least {minimum} substantive characters")
    if len(stripped.encode("utf-8")) > MAX_TEXT_BYTES:
        _fail(f"{label} exceeds {MAX_TEXT_BYTES} bytes")
    return stripped


def _text_list(
    value: Any,
    label: str,
    minimum_items: int = 1,
    maximum_items: int = MAX_LIST_ITEMS,
    minimum_chars: int = 1,
) -> list[str]:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array of strings")
    if not minimum_items <= len(value) <= maximum_items:
        _fail(
            f"{label} must contain between {minimum_items} and {maximum_items} items"
        )
    items = [
        _text(item, f"{label}[{index}]", minimum_chars)
        for index, item in enumerate(value)
    ]
    for index, item in enumerate(items):
        if len(item.encode("utf-8")) > MAX_ITEM_BYTES:
            _fail(f"{label}[{index}] exceeds {MAX_ITEM_BYTES} bytes")
    return items


def _str_or_list(value: Any, label: str) -> list[str]:
    # A string is normalized into a one-item list. Routing it through
    # ``_text_list`` keeps validation idempotent: replaying the normalized
    # manifest must enforce exactly the same per-item bound as a caller-supplied
    # list, otherwise an accepted string could make the published enrollment
    # event unreplayable.
    if isinstance(value, str):
        value = [value]
    return _text_list(value, label, minimum_items=1)


def _validate_brief(raw: Any, label: str) -> dict[str, Any]:
    """Validate the coordinator-authored immutable per-step brief."""
    value = _exact_keys(raw, BRIEF_KEYS, label)
    return {
        "original_objective": _text(
            value.get("original_objective"),
            f"{label}.original_objective",
            minimum=20,
        ),
        "repository_context": _text(
            value.get("repository_context"),
            f"{label}.repository_context",
            minimum=10,
        ),
        "constraints": _text_list(
            value.get("constraints"), f"{label}.constraints", minimum_chars=3
        ),
        "proposed_approach": _text(
            value.get("proposed_approach"),
            f"{label}.proposed_approach",
            minimum=20,
        ),
        "expected_changes": _text_list(
            value.get("expected_changes"),
            f"{label}.expected_changes",
            minimum_chars=3,
        ),
        "acceptance_criteria": _text_list(
            value.get("acceptance_criteria"),
            f"{label}.acceptance_criteria",
            minimum_chars=3,
        ),
    }


def _plan_is_strict(static: dict[str, Any] | None) -> bool:
    """Return whether an enrollment explicitly opted into strict execution."""
    if not isinstance(static, dict):
        return False
    return static.get(STRICT_EXECUTION_KEY) is True


def _constraint_pattern(value: Any, label: str) -> str:
    """Validate one repository-relative candidate execution pattern.

    Patterns are exact glob expressions approved by consensus. They are never
    resolved as single paths here; contract narrowing compares pattern sets so
    one approved glob cannot be treated as though it named one concrete file.
    """
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty repository-relative pattern")
    if len(value.encode("utf-8")) > MAX_PATTERN_BYTES:
        _fail(f"{label} exceeds {MAX_PATTERN_BYTES} bytes")
    if "\x00" in value or value.startswith("/"):
        _fail(f"{label} must be repository-relative without NUL bytes")
    parts = Path(value).parts
    if any(part == ".." for part in parts):
        _fail(f"{label} must not escape the repository")
    if parts and parts[0] == ".git":
        _fail(f"{label} must not target Git metadata")
    return value


def _constraint_pattern_list(value: Any, label: str, minimum: int) -> list[str]:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array of repository-relative patterns")
    if not minimum <= len(value) <= MAX_CONSTRAINT_PATTERNS:
        _fail(
            f"{label} must contain between {minimum} and "
            f"{MAX_CONSTRAINT_PATTERNS} patterns"
        )
    patterns = [_constraint_pattern(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(set(patterns)) != len(patterns):
        _fail(f"{label} must not repeat a pattern")
    return patterns


def _criterion_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_execution_criteria(
    raw: Any, manifest_step: dict[str, Any] | None
) -> list[dict[str, str]]:
    """Validate stable criterion IDs bound to exact manifest text digests.

    Coverage is deliberately structural: it proves every approved manifest
    criterion text has exactly one stable ID and digest. It makes no semantic
    claim that an arbitrary English requirement is satisfied.
    """
    if not isinstance(raw, list):
        _fail("execution_constraints.criteria must be a JSON array")
    if not 1 <= len(raw) <= MAX_CONSTRAINT_CRITERIA:
        _fail(
            "execution_constraints.criteria must contain between 1 and "
            f"{MAX_CONSTRAINT_CRITERIA} entries"
        )
    criteria: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    for index, entry in enumerate(raw):
        label = f"execution_constraints.criteria[{index}]"
        item = _exact_keys(entry, {"id", "text_sha256"}, label)
        criterion_id = item.get("id")
        if not isinstance(criterion_id, str) or not CRITERION_ID_RE.fullmatch(
            criterion_id
        ):
            _fail(f"{label}.id must match {CRITERION_ID_RE.pattern}")
        digest = item.get("text_sha256")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            _fail(f"{label}.text_sha256 must be a lowercase SHA-256 digest")
        if criterion_id in seen_ids:
            _fail(f"{label}.id {criterion_id!r} is repeated")
        if digest in seen_digests:
            _fail(f"{label}.text_sha256 {digest!r} is repeated")
        seen_ids.add(criterion_id)
        seen_digests.add(digest)
        criteria.append({"id": criterion_id, "text_sha256": digest})
    if manifest_step is not None:
        expected = sorted(
            _criterion_digest(item) for item in manifest_step["acceptance_criteria"]
        )
        actual = sorted(item["text_sha256"] for item in criteria)
        if actual != expected:
            _fail(
                "execution_constraints.criteria must bind exactly the manifest "
                "acceptance criteria text digests for this step"
            )
    return criteria


def _validate_validation_command(raw: Any, label: str) -> dict[str, Any]:
    item = _keys_with_optional(raw, {"argv"}, {"label"}, label)
    argv = item.get("argv")
    if not isinstance(argv, list) or not argv:
        _fail(f"{label}.argv must be a non-empty literal argument array")
    if len(argv) > MAX_VALIDATION_ARGV:
        _fail(f"{label}.argv has too many arguments")
    normalized: list[str] = []
    for index, argument in enumerate(argv):
        if not isinstance(argument, str) or not argument:
            _fail(f"{label}.argv[{index}] must be a non-empty string")
        if len(argument.encode("utf-8")) > MAX_VALIDATION_ARG_BYTES:
            _fail(f"{label}.argv[{index}] exceeds {MAX_VALIDATION_ARG_BYTES} bytes")
        if "\x00" in argument or "\n" in argument or "\r" in argument:
            _fail(
                f"{label}.argv[{index}] must be one literal argument without "
                "NUL or line breaks"
            )
        normalized.append(argument)
    result: dict[str, Any] = {"argv": normalized}
    description = item.get("label")
    if description is not None:
        result["label"] = _text(description, f"{label}.label", minimum=2)
    return result


def _validate_validation_commands(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        _fail("execution_constraints.required_validation must be a JSON array")
    if not 1 <= len(raw) <= MAX_VALIDATION_COMMANDS:
        _fail(
            "execution_constraints.required_validation must contain between 1 and "
            f"{MAX_VALIDATION_COMMANDS} literal commands"
        )
    commands = [
        _validate_validation_command(
            entry, f"execution_constraints.required_validation[{index}]"
        )
        for index, entry in enumerate(raw)
    ]
    seen: set[tuple[str, ...]] = set()
    for command in commands:
        key = tuple(command["argv"])
        if key in seen:
            _fail("execution_constraints.required_validation repeats a command")
        seen.add(key)
    return commands


def validate_execution_constraints(
    raw: Any, manifest_step: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Validate a version 1 candidate execution-constraints object."""
    value = _exact_keys(
        raw,
        {
            "version",
            "allowed_paths",
            "denied_paths",
            "criteria",
            "required_validation",
            "max_changed_files",
        },
        "execution_constraints",
    )
    version = value.get("version")
    if type(version) is not int or version != EXECUTION_CONSTRAINTS_VERSION:
        _fail("execution_constraints.version is not supported")
    allowed = _constraint_pattern_list(
        value.get("allowed_paths"), "execution_constraints.allowed_paths", minimum=1
    )
    denied = _constraint_pattern_list(
        value.get("denied_paths"), "execution_constraints.denied_paths", minimum=0
    )
    criteria = _validate_execution_criteria(value.get("criteria"), manifest_step)
    required = _validate_validation_commands(value.get("required_validation"))
    maximum = value.get("max_changed_files")
    if maximum is not None and (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum <= 0
        or maximum > 100_000
    ):
        _fail("execution_constraints.max_changed_files must be a positive integer")
    return {
        "version": EXECUTION_CONSTRAINTS_VERSION,
        "allowed_paths": allowed,
        "denied_paths": denied,
        "criteria": criteria,
        "required_validation": required,
        "max_changed_files": maximum,
    }


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


def _keys_with_optional(
    value: Any,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, Any]:
    """Validate exact required keys plus a fixed optional allowlist.

    The distinction keeps every historical event schema byte-compatible while
    letting a new strict-mode event carry additional, explicitly enumerated
    fields.  An unknown field is still rejected.
    """
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    actual = set(value)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing:
        _fail(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        _fail(f"{label} has unknown fields: {', '.join(extra)}")
    return value


def _reject_evidence_assumptions(value: Any, where: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in FORBIDDEN_EVIDENCE_KEYS:
                _fail(
                    f"Manifest contains an unchecked evidence assumption at {where}."
                    f"{key}; B1 accepts no claimed merge or verification receipts"
                )
            _reject_evidence_assumptions(child, f"{where}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_evidence_assumptions(child, f"{where}[{index}]")


def validate_manifest(raw: Any) -> tuple[dict[str, Any], str]:
    """Validate and normalize a structured step manifest."""
    if not isinstance(raw, dict):
        _fail("Manifest must be a JSON object")
    _reject_evidence_assumptions(raw, "manifest")
    unknown = sorted(set(raw) - {"policy_version", "steps"})
    if unknown:
        _fail(f"Manifest has unknown fields: {', '.join(unknown)}")
    version = raw.get("policy_version", POLICY_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        _fail("Manifest policy_version must be an integer")
    if version not in SUPPORTED_POLICY_VERSIONS:
        _fail(
            f"Unknown research policy version {version}; supported versions: "
            + ", ".join(str(item) for item in SUPPORTED_POLICY_VERSIONS)
        )
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not 1 <= len(steps_raw) <= MAX_STEPS:
        _fail(f"Manifest steps must contain between 1 and {MAX_STEPS} steps")
    seen: set[str] = set()
    steps: list[dict[str, Any]] = []
    for index, step_raw in enumerate(steps_raw):
        label = f"steps[{index}]"
        step = _exact_keys(step_raw, ALLOWED_STEP_KEYS, label)
        step_id = step.get("id")
        if not isinstance(step_id, str) or not ID_RE.fullmatch(step_id):
            _fail(f"{label}.id must match {ID_RE.pattern}")
        if step_id in seen:
            _fail(f"Duplicate step ID {step_id!r} in manifest")
        seen.add(step_id)
        objective = _text(step.get("objective"), f"{label}.objective", minimum=20)
        scope = _str_or_list(step.get("scope"), f"{label}.scope")
        deliverables = _text_list(
            step.get("deliverables"), f"{label}.deliverables", minimum_chars=3
        )
        acceptance = _text_list(
            step.get("acceptance_criteria"),
            f"{label}.acceptance_criteria",
            minimum_chars=3,
        )
        brief = _validate_brief(step.get("brief"), f"{label}.brief")
        depends_raw = step.get("depends_on", [])
        if not isinstance(depends_raw, list) or len(depends_raw) > MAX_STEPS:
            _fail(
                f"{label}.depends_on must be a JSON array of earlier step IDs; "
                "null is not accepted"
            )
        depends: list[str] = []
        for dep in depends_raw:
            if not isinstance(dep, str) or not ID_RE.fullmatch(dep):
                _fail(f"{label}.depends_on contains an invalid step ID: {dep!r}")
            if dep == step_id:
                _fail(f"{label} cannot depend on itself")
            if dep in depends:
                _fail(f"{label}.depends_on lists {dep!r} more than once")
            if dep not in seen:
                _fail(
                    f"{label} depends on {dep!r}, which is not an earlier manifest step; "
                    "dependencies must be acyclic and refer only to earlier steps"
                )
            depends.append(dep)
        normalized_step = {
            "id": step_id,
            "objective": objective,
            "scope": scope,
            "deliverables": deliverables,
            "acceptance_criteria": acceptance,
            "depends_on": depends,
            "brief": brief,
        }
        # Bound the normalized step, which is what replay validates. Bounding
        # the raw input here would make string-to-list normalization fail only
        # on the second pass.
        if len(_canonical_bytes(normalized_step)) > MAX_STEP_BYTES:
            _fail(f"{label} exceeds {MAX_STEP_BYTES} bytes")
        steps.append(normalized_step)
    manifest = {"policy_version": version, "steps": steps}
    # The same bound is applied to the normalized manifest so validation is
    # idempotent between the create-plan input and the published enrollment
    # event replayed later.
    if len(_canonical_bytes(manifest)) > MAX_SUBMISSION_BYTES:
        _fail(f"Manifest exceeds {MAX_SUBMISSION_BYTES} bytes")
    return manifest, _digest(manifest)


def _plans_root() -> Path:
    return _hook("plans_dir")()


def _plan_path(plan_id: str) -> Path:
    # Creation must be able to address a plan directory before it exists; every
    # read path checks for published evidence or a plan projection explicitly.
    return _hook("plan_dir")(plan_id, must_exist=False)


def _registry_path() -> Path:
    return _plans_root() / "enrollment.json"


@contextlib.contextmanager
def _registry_lock() -> Iterator[None]:
    # The state home may not exist yet (for example, the first launch or legacy
    # create-plan in an enrolled checkout); the lock file's parent must exist.
    _plans_root().mkdir(parents=True, exist_ok=True, mode=0o700)
    with _hook("record_lock")(_registry_path()):
        yield


_LOCK_DEPTH: ContextVar[int] = ContextVar("b1_admission_lock_depth", default=0)
_REPO_LOCK_DEPTH: ContextVar[int] = ContextVar("b1_repo_lock_depth", default=0)


def _repo_enrollment_dir(identity: dict[str, Any]) -> Path | None:
    """Return the repository-level enrollment directory, shared by state homes.

    The Git common directory is the only durable, state-home-independent anchor
    for a repository. It is shared by every linked worktree, distinct for
    sibling bare repositories, submodules and ``--separate-git-dir`` checkouts.
    """
    common = identity.get("git_common_dir")
    if not isinstance(common, str) or not common:
        return None
    return Path(common) / "agent-orchestrator"


def _marker_path(identity: dict[str, Any]) -> Path | None:
    directory = _repo_enrollment_dir(identity)
    return directory / "enrollment.json" if directory else None


def _intent_path(identity: dict[str, Any]) -> Path | None:
    directory = _repo_enrollment_dir(identity)
    return directory / "intent.json" if directory else None


@contextlib.contextmanager
def _repo_lock(identity: dict[str, Any]) -> Iterator[None]:
    directory = _repo_enrollment_dir(identity)
    if directory is None:
        yield
        return
    if _REPO_LOCK_DEPTH.get():
        # Helpers called from inside an admission block (or another repository
        # lock block) reuse the held lock instead of deadlocking on a second
        # flock of the same path.
        yield
        return
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _hook("record_lock")(directory / "enrollment"):
            token = _REPO_LOCK_DEPTH.set(1)
            try:
                yield
            finally:
                _REPO_LOCK_DEPTH.reset(token)
    except OSError as exc:
        _fail(f"Cannot use the repository enrollment lock at {directory}: {exc}")


@contextlib.contextmanager
def _admission_locks(identity: dict[str, Any]) -> Iterator[None]:
    """Serialize enrollment and admission across every state home.

    The repository-level lock is acquired before the state-home registry lock,
    so concurrent legacy creation, enrollment, launch admission and worker
    checks all observe one order. The context is re-entrant: helpers called
    from inside an admission block reuse the already held lock.
    """
    if _LOCK_DEPTH.get():
        yield
        return
    with _repo_lock(identity):
        with _registry_lock():
            token = _LOCK_DEPTH.set(_LOCK_DEPTH.get() + 1)
            try:
                yield
            finally:
                _LOCK_DEPTH.reset(token)


def _validate_marker(marker: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(marker, MARKER_KEYS, "repository enrollment marker")
    if marker.get("version") != 1:
        _fail("Repository enrollment marker has an unsupported version")
    if marker.get("canonical_workspace") != identity["root"]:
        _fail("Repository enrollment marker belongs to another workspace")
    if marker.get("git_common_dir") != identity.get("git_common_dir"):
        _fail("Repository enrollment marker belongs to another Git repository")
    plan_id = marker.get("plan_id")
    if not isinstance(plan_id, str) or not ID_RE.fullmatch(plan_id):
        _fail("Repository enrollment marker has an invalid plan ID")
    marker_policy_version = marker.get("policy_version")
    if (
        not isinstance(marker_policy_version, int)
        or isinstance(marker_policy_version, bool)
        or marker_policy_version not in SUPPORTED_POLICY_VERSIONS
    ):
        _fail("Repository enrollment marker has an unsupported policy version")
    plans_dir = marker.get("plans_dir")
    if not isinstance(plans_dir, str) or not Path(plans_dir).is_absolute():
        _fail("Repository enrollment marker has an invalid owning state location")
    return marker


def _read_repo_marker(identity: dict[str, Any]) -> dict[str, Any] | None:
    path = _marker_path(identity)
    if path is None or not path.exists():
        return None
    marker = _read_json(path)
    return _validate_marker(marker, identity)


def _write_repo_marker(identity: dict[str, Any], plan_id: str) -> None:
    path = _marker_path(identity)
    if path is None:
        _fail("Cannot persist a repository enrollment marker without a Git common directory")
    _write_json_atomic(
        path,
        {
            "version": 1,
            "plan_id": plan_id,
            "canonical_workspace": identity["root"],
            "workspace_project_id": identity.get("project_id"),
            "git_common_dir": identity.get("git_common_dir"),
            "policy_version": POLICY_VERSION,
            "enrolled_at": _now(),
            "plans_dir": _plans_root_string(),
        },
    )


def _plans_root_string() -> str:
    return str(_plans_root().resolve())


def _read_intent(identity: dict[str, Any]) -> dict[str, Any] | None:
    path = _intent_path(identity)
    if path is None or not path.exists():
        return None
    intent = _read_json(path)
    _exact_keys(intent, INTENT_KEYS, "enrollment intent")
    if intent.get("version") != 1:
        _fail("Enrollment intent has an unsupported version")
    if intent.get("canonical_workspace") != identity["root"]:
        _fail("Enrollment intent belongs to another workspace")
    plan_id = intent.get("plan_id")
    if not isinstance(plan_id, str) or not ID_RE.fullmatch(plan_id):
        _fail("Enrollment intent has an invalid plan ID")
    staging = intent.get("staging")
    if not isinstance(staging, str) or not staging or Path(staging).is_absolute():
        _fail("Enrollment intent has an invalid staging path")
    parts = Path(staging).parts
    if (
        len(parts) != 2
        or not parts[0].startswith(STAGING_PREFIX)
        or parts[1] != plan_id
    ):
        # Recovery must never be able to address a published plan directory.
        _fail("Enrollment intent staging path is not a private enrollment directory")
    plans_dir = intent.get("plans_dir")
    if not isinstance(plans_dir, str) or not Path(plans_dir).is_absolute():
        _fail(
            "Enrollment intent has no owning state location; inspect "
            f"{path} before retrying"
        )
    request_digest = intent.get("request_digest")
    if not isinstance(request_digest, str) or not DIGEST_RE.fullmatch(request_digest):
        _fail(
            "Enrollment intent has no normalized request identity; inspect "
            f"{path} before retrying"
        )
    return intent


def _write_intent(
    identity: dict[str, Any],
    plan_id: str,
    staging_relative: str,
    request_digest: str,
) -> None:
    path = _intent_path(identity)
    if path is None:
        _fail("Cannot persist enrollment intent without a Git common directory")
    _write_json_atomic(
        path,
        {
            "version": 1,
            "plan_id": plan_id,
            "canonical_workspace": identity["root"],
            "workspace_project_id": identity.get("project_id"),
            "staging": staging_relative,
            "created_at": _now(),
            "plans_dir": _plans_root_string(),
            "request_digest": request_digest,
        },
    )


def _intent_owner_guard(
    identity: dict[str, Any], intent: dict[str, Any], request_digest: str
) -> None:
    """Bind intent recovery to the owning state home and the exact request.

    A state home other than the owner must never reconcile or clear an intent
    written elsewhere, and the same plan ID must not silently adopt different
    enrollment content just because the original attempt was interrupted.
    """
    owner = Path(intent["plans_dir"]).resolve()
    if owner != _plans_root().resolve():
        _fail(
            f"Workspace {identity['root']} has an incomplete managed enrollment for "
            f"plan {intent['plan_id']} owned by state home {owner}; retry the exact "
            "same create-plan from that state home or inspect "
            f"{_intent_path(identity)}"
        )
    if intent["request_digest"] != request_digest:
        _fail(
            f"Workspace {identity['root']} has an incomplete managed enrollment for "
            f"plan {intent['plan_id']} started with different create-plan content; "
            "retry the exact original request or inspect "
            f"{_intent_path(identity)}"
        )


def _clear_intent(identity: dict[str, Any]) -> None:
    path = _intent_path(identity)
    if path is not None:
        path.unlink(missing_ok=True)
        _fsync_dir(path.parent)


def _staging_contents_are_ours(
    staging: Path, identity: dict[str, Any], plan_id: str
) -> bool:
    """Recognize the known pre-publication staging layout without its marker.

    A crash can land between ``mkdir`` and the staging-marker write, between the
    marker unlink and the atomic directory rename, or in the middle of a marker
    write that leaves only a dot temporary file. Only the exact layout this
    module creates is accepted; anything else fails closed.
    """
    try:
        children = list(staging.iterdir())
    except OSError:
        return False
    temp_marker_re = re.compile(rf"^{re.escape(STAGING_MARKER)}\.[0-9a-f]+\.tmp$")
    for child in children:
        name = child.name
        if name == STAGING_MARKER:
            continue
        if temp_marker_re.fullmatch(name) and child.is_file():
            continue
        if name in {"plan.md", "manifest.json"} and child.is_file():
            continue
        if name == "consensus" and child.is_dir():
            continue
        return False
    events_dir = staging / "consensus" / "events"
    if events_dir.is_dir():
        try:
            files = _published_event_files(events_dir)
        except Exception:
            return False
        for event_path in files:
            try:
                event = _read_json(event_path)
            except Exception:
                return False
            if event.get("plan_id") != plan_id:
                return False
            if event.get("type") == "plan_enrolled":
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    return False
                if payload.get("canonical_workspace") != identity["root"]:
                    return False
    return True


def _cleanup_staging(identity: dict[str, Any], intent: dict[str, Any]) -> None:
    """Remove only our interrupted staging directory, never unrelated state."""
    root = _plans_root().resolve()
    if Path(intent["plans_dir"]).resolve() != root:
        # Recovery is owned by the state home that wrote the intent.
        _fail(
            f"Refusing to clean staging owned by state home {intent['plans_dir']}"
        )
    staging = (root / intent["staging"]).resolve()
    try:
        staging.relative_to(root)
    except ValueError:
        _fail(f"Enrollment intent staging path escapes the plans directory: {staging}")
    if not staging.exists():
        # The interrupted attempt may have left only its private parent.
        with contextlib.suppress(OSError):
            staging.parent.rmdir()
        return
    marker = staging / STAGING_MARKER
    if marker.is_file():
        record = _read_json(marker)
        if (
            record.get("plan_id") != intent["plan_id"]
            or record.get("canonical_workspace") != identity["root"]
        ):
            _fail(
                "Refusing to clean a staging directory owned by another "
                f"enrollment: {staging}"
            )
    elif not _staging_contents_are_ours(staging, identity, intent["plan_id"]):
        _fail(f"Refusing to clean an unrecognized staging directory: {staging}")
    shutil.rmtree(staging, ignore_errors=True)
    with contextlib.suppress(OSError):
        staging.parent.rmdir()
    _fsync_dir(root)


def _prune_orphan_staging(identity: dict[str, Any], plan_id: str) -> None:
    """Drop stale staging directories left by older interrupted attempts."""
    root = _plans_root()
    if not root.exists():
        return
    for directory in root.iterdir():
        if not directory.is_dir() or not directory.name.startswith(STAGING_PREFIX):
            continue
        if not directory.name.startswith(f"{STAGING_PREFIX}{plan_id}-"):
            continue
        for candidate in list(directory.iterdir()):
            if not candidate.is_dir():
                continue
            marker = candidate / STAGING_MARKER
            if not marker.is_file():
                continue
            try:
                record = _read_json(marker)
            except Exception:
                continue
            if (
                record.get("plan_id") == plan_id
                and record.get("canonical_workspace") == identity["root"]
            ):
                shutil.rmtree(candidate, ignore_errors=True)
        with contextlib.suppress(OSError):
            directory.rmdir()
    _fsync_dir(root)


def _reservations_dir(identity: dict[str, Any]) -> Path | None:
    enrollment_dir = _repo_enrollment_dir(identity)
    return enrollment_dir / RESERVATION_DIR if enrollment_dir else None


def _validate_job_id(job_id: Any) -> str:
    if not isinstance(job_id, str) or not ID_RE.fullmatch(job_id):
        _fail(f"Invalid job identifier for an active-job reservation: {job_id!r}")
    return job_id


def _validate_reservation_id(reservation_id: Any) -> str:
    if not isinstance(reservation_id, str) or not RESERVATION_ID_RE.fullmatch(
        reservation_id
    ):
        _fail(
            "Invalid active-job reservation identity: "
            f"{reservation_id!r}; updates and releases must name the exact "
            "reservation they own"
        )
    return reservation_id


def _reservation_path(
    identity: dict[str, Any], job_id: Any, reservation_id: Any
) -> Path | None:
    directory = _reservations_dir(identity)
    if directory is None:
        return None
    job_id = _validate_job_id(job_id)
    reservation_id = _validate_reservation_id(reservation_id)
    return directory / f"{job_id}.{reservation_id}.json"


def _process_alive(pid: Any) -> bool:
    """Best-effort liveness for a recorded process ID.

    An unavailable or unreadable `/proc` does not change the result: a process
    that cannot be probed is treated as alive so admission stays fail-closed.
    An exited-but-unreaped zombie cannot write and is reported as dead.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OverflowError):
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    try:
        data = Path(f"/proc/{pid}/stat").read_bytes()
        if data.rsplit(b")", 1)[1].split()[0] == b"Z":
            return False
    except (OSError, IndexError):
        # Platforms without /proc keep the conservative os.kill result.
        pass
    return True


def _reservation_live(record: dict[str, Any]) -> bool:
    return any(_process_alive(record.get(key)) for key in RESERVATION_PID_KEYS)


def _validate_reservation(
    record: dict[str, Any], identity: dict[str, Any], path: Path
) -> dict[str, Any]:
    version = record.get("version")
    if version == RESERVATION_VERSION:
        _exact_keys(record, RESERVATION_KEYS, f"active-job reservation {path}")
    elif version == LEGACY_RESERVATION_VERSION:
        _exact_keys(
            record, LEGACY_RESERVATION_KEYS, f"active-job reservation {path}"
        )
    else:
        _fail(f"Active-job reservation {path} has an unsupported version")
    if record.get("canonical_workspace") != identity["root"]:
        _fail(f"Active-job reservation {path} belongs to another workspace")
    if record.get("git_common_dir") != identity.get("git_common_dir"):
        _fail(f"Active-job reservation {path} belongs to another Git repository")
    job_id = record.get("job_id")
    if not isinstance(job_id, str) or not ID_RE.fullmatch(job_id):
        _fail(f"Active-job reservation {path} has an invalid job identifier")
    if version == RESERVATION_VERSION:
        reservation_id = record.get("reservation_id")
        if not isinstance(reservation_id, str) or not RESERVATION_ID_RE.fullmatch(
            reservation_id
        ):
            _fail(f"Active-job reservation {path} has an invalid reservation identity")
        if path.name != f"{job_id}.{reservation_id}.json":
            _fail(
                f"Active-job reservation {path} does not match its reservation identity"
            )
    elif path.name != f"{job_id}.json":
        _fail(f"Active-job reservation {path} does not match its job identifier")
    for key in RESERVATION_PID_KEYS:
        value = record.get(key)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
        ):
            _fail(f"Active-job reservation {path} has an invalid {key}")
    job_dir = record.get("job_dir")
    if not isinstance(job_dir, str):
        _fail(f"Active-job reservation {path} has an invalid job directory")
    if version == RESERVATION_VERSION and (
        not job_dir or not Path(job_dir).is_absolute()
    ):
        _fail(f"Active-job reservation {path} has an invalid job directory")
    if not isinstance(record.get("plans_dir"), str) or not Path(
        record["plans_dir"]
    ).is_absolute():
        _fail(f"Active-job reservation {path} has an invalid state location")
    for key in ("state_home", "created_at", "updated_at"):
        if not isinstance(record.get(key), str) or not record[key]:
            _fail(f"Active-job reservation {path} has an invalid {key}")
    return record


def _new_reservation_record(
    identity: dict[str, Any],
    job_id: str,
    reservation_id: str,
    job_dir: Path,
    coordinator_pid: int | None,
) -> dict[str, Any]:
    now = _now()
    return {
        "version": RESERVATION_VERSION,
        "reservation_id": reservation_id,
        "job_id": job_id,
        "canonical_workspace": identity["root"],
        "git_common_dir": identity["git_common_dir"],
        "state_home": str(_hook("state_home")()),
        "plans_dir": _plans_root_string(),
        "job_dir": str(Path(job_dir).resolve()),
        "coordinator_pid": coordinator_pid,
        "worker_pid": None,
        "provider_pid": None,
        "created_at": now,
        "updated_at": now,
    }


def reserve_active_job(
    identity: dict[str, Any],
    job_id: str,
    job_dir: Path,
    coordinator_pid: int,
) -> str | None:
    """Publish a repository-local reservation for an admitted launch.

    Returns the fresh ownership token that names this launch's record. The
    caller must hold the admission locks (``launch_admission`` does) so the
    reservation and the enrollment check are serialized. Non-Git workspaces have
    no repository anchor and keep their legacy behavior.
    """
    if not identity.get("is_git") or not identity.get("git_common_dir"):
        return None
    job_id = _validate_job_id(job_id)
    directory = _reservations_dir(identity)
    if directory is None:
        return None
    reservation_id = ""
    path: Path | None = None
    for _ in range(8):
        reservation_id = secrets.token_hex(16)
        candidate = directory / f"{job_id}.{reservation_id}.json"
        if not candidate.exists():
            path = candidate
            break
    if path is None:
        _fail(f"Cannot allocate a unique active-job reservation for {job_id}")
    record = _new_reservation_record(
        identity, job_id, reservation_id, job_dir, coordinator_pid
    )
    _validate_reservation(record, identity, path)
    _write_json_atomic(path, record)
    return reservation_id


def _update_reservation_locked(
    identity: dict[str, Any],
    job_id: str,
    reservation_id: str,
    fields: dict[str, Any],
    create_job_dir: Path | None = None,
) -> None:
    """Update one owned reservation, or create it only for a worker restart.

    The record is addressed by ``(job_id, reservation_id)``. A missing record is
    never recreated unless the caller explicitly supplies a valid job directory;
    in particular the launch parent's post-Popen registration is update-only so
    it cannot resurrect a reservation released by a worker that already
    finished. The original ownership token is re-checked before writing.
    """
    path = _reservation_path(identity, job_id, reservation_id)
    if path is None:
        return
    if path.is_file():
        record = _validate_reservation(_read_json(path), identity, path)
        if record.get("reservation_id") != reservation_id:
            _fail(
                f"Active-job reservation {path} is owned by another reservation; "
                "refusing to update it"
            )
    elif create_job_dir is not None:
        record = _new_reservation_record(
            identity, job_id, reservation_id, create_job_dir, None
        )
    else:
        # Update-only: never recreate a record another process released.
        return
    record.update(fields)
    record["updated_at"] = _now()
    # Never persist a record that replay would reject.
    _validate_reservation(record, identity, path)
    _write_json_atomic(path, record)


def register_job_process(
    identity: dict[str, Any] | None,
    job_id: Any,
    role: str,
    pid: int,
    *,
    reservation_id: Any = None,
    job_dir: Path | None = None,
) -> str | None:
    """Record the worker or provider process for one admitted job.

    When ``reservation_id`` is supplied the update is bound to that ownership
    token; the record is only created if ``job_dir`` is also supplied (the
    worker restart path). Without a token only a worker carrying a valid job
    directory may create a fresh reservation, which supports jobs admitted by an
    older runner. Registration stays best-effort: failing to record a live
    process can delay cleanup but cannot admit a live writer.
    """
    if role not in {"worker", "provider"}:
        _fail(f"Unknown job process role: {role!r}")
    if identity is None or not identity.get("is_git"):
        return None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    try:
        with _repo_lock(identity):
            if reservation_id is None:
                if role != "worker" or job_dir is None:
                    return None
                job_id = _validate_job_id(job_id)
                reservation_id = secrets.token_hex(16)
            else:
                reservation_id = _validate_reservation_id(reservation_id)
                job_id = _validate_job_id(job_id)
            _update_reservation_locked(
                identity,
                job_id,
                reservation_id,
                {f"{role}_pid": pid},
                create_job_dir=job_dir if role == "worker" else None,
            )
            return reservation_id
    except Exception:
        # Admission remains safe: the existing record still names a live
        # process or a later enrollment prunes a dead one.
        return None


def release_active_job(
    identity: dict[str, Any] | None,
    job_id: Any,
    reservation_id: Any = None,
) -> None:
    """Best-effort removal of the exact reservation owned by this process.

    A release without an ownership token is a no-op: two launches may share a
    job ID in different state homes, and no caller may remove another launch's
    live reservation. The record's token is re-checked before unlinking.
    """
    if identity is None or not identity.get("is_git"):
        return
    if reservation_id is None:
        return
    try:
        with _repo_lock(identity):
            path = _reservation_path(identity, job_id, reservation_id)
            if path is None or not path.is_file():
                return
            record = _validate_reservation(_read_json(path), identity, path)
            if record.get("reservation_id") != reservation_id:
                _fail(
                    f"Refusing to release active-job reservation {path} owned by "
                    "another reservation"
                )
            path.unlink(missing_ok=True)
            _fsync_dir(path.parent)
    except Exception:
        return


def _active_reservation_records_locked(
    identity: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return live reservation records and prune records whose processes are gone."""
    directory = _reservations_dir(identity)
    if directory is None or not directory.is_dir():
        return []
    active: list[dict[str, Any]] = []
    stale: list[Path] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.name.startswith("."):
            # Unpublished temporary files are ignored.
            continue
        if not path.is_file() or path.is_symlink() or path.suffix != ".json":
            _fail(f"Unexpected active-job reservation entry: {path}")
        record = _validate_reservation(_read_json(path), identity, path)
        if _reservation_live(record):
            active.append(record)
        else:
            stale.append(path)
    for path in stale:
        path.unlink(missing_ok=True)
    if stale:
        _fsync_dir(directory)
    return active


def _active_reservations_locked(identity: dict[str, Any]) -> list[str]:
    """Return live reservation job IDs and prune dead records."""
    return [
        str(record["job_id"])
        for record in _active_reservation_records_locked(identity)
    ]


def active_repository_reservations(
    identity: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return live repository-local reservations shared across state homes.

    The caller normally holds the admission locks (launch admission does); the
    repository lock is re-entered safely.  Records whose recorded processes are
    gone are pruned.  Malformed records fail closed instead of being ignored.
    """
    if not identity.get("is_git"):
        return []
    with _repo_lock(identity):
        return _active_reservation_records_locked(identity)


def _active_jobs_with_reservations(
    identity: dict[str, Any], state_home_jobs: list[str] | None = None
) -> list[str]:
    """Combine this state home's jobs with repository-local reservations.

    The repository reservation is the shared anchor: a launch admitted from any
    supported state home is visible here, including while its worker runs after
    the launching coordinator exits.
    """
    jobs = set(state_home_jobs or [])
    if identity.get("is_git"):
        jobs.update(_active_reservations_locked(identity))
    return sorted(jobs)


def _read_registry() -> dict[str, Any]:
    path = _registry_path()
    if not path.exists():
        return {"version": 1, "workspaces": {}}
    value = _read_json(path)
    if value.get("version") != 1:
        _fail(f"Enrollment registry {path} has an unsupported version")
    workspaces = value.get("workspaces")
    if not isinstance(workspaces, dict):
        _fail(f"Enrollment registry {path} is corrupt")
    for key, entry in workspaces.items():
        if (
            not isinstance(key, str)
            or not isinstance(entry, dict)
            or not isinstance(entry.get("plan_id"), str)
            or entry.get("canonical_workspace") != key
        ):
            _fail(f"Enrollment registry {path} is corrupt at {key!r}")
    return {"version": 1, "workspaces": workspaces}


def _write_registry(registry: dict[str, Any]) -> None:
    _write_json_atomic(_registry_path(), registry)


def _canonical(workspace: Path) -> dict[str, Any]:
    return _hook("canonical_workspace")(Path(workspace).expanduser().resolve())


def _managed_plan_for_identity(identity: str) -> str | None:
    """Find a managed plan for a canonical workspace.

    Published ledger events are authoritative: they are inspected before the
    mutable ``plan.json`` projection. A corrupt projection therefore cannot
    turn a managed checkout back into a legacy one.
    """
    root = _plans_root()
    if not root.exists():
        return None
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        if directory.name.startswith("."):
            # Enrollment staging directories are unpublished and not plans.
            continue
        plan_path = directory / "plan.json"
        try:
            events = _published_event_files(directory / "consensus" / "events")
        except Exception:
            # A malformed unrelated plan directory must not make every legacy
            # workspace in this state home unusable. The owning workspace still
            # fails closed through its repository marker/intent or its own
            # checkpoint commands.
            events = []
        ledger_canonical: str | None = None
        ledger_plan_id = directory.name
        if events:
            try:
                first = _read_json(events[0])
            except Exception:
                first = None
            if isinstance(first, dict) and first.get("type") == "plan_enrolled":
                payload = first.get("payload")
                if isinstance(payload, dict):
                    ledger_canonical = payload.get("canonical_workspace")
                    ledger_plan_id = str(first.get("plan_id") or directory.name)
            if ledger_canonical is not None:
                if ledger_canonical == identity:
                    return ledger_plan_id
                # The published ledger wins over any conflicting projection.
                continue
        if not plan_path.is_file():
            continue
        try:
            plan = _read_json(plan_path)
        except Exception:
            # A corrupt projection next to a corrupt ledger is not evidence
            # that this checkout is safe; the repository marker and intent
            # still fail closed. Other plans continue to be inspected.
            continue
        if not plan.get("managed"):
            continue
        canonical = plan.get("canonical_workspace")
        workspace = plan.get("workspace")
        plan_id = str(plan.get("plan_id") or directory.name)
        if canonical == identity:
            return plan_id
        if isinstance(workspace, str) and workspace:
            try:
                if _canonical(Path(workspace)).get("root") == identity:
                    return plan_id
            except Exception:
                continue
    return None


def _workspace_entries(identity: dict[str, Any]) -> dict[str, Any] | None:
    """Read the repository marker, then the state-home registry."""
    marker = _read_repo_marker(identity)
    if marker is not None:
        return {
            "plan_id": marker["plan_id"],
            "canonical_workspace": marker["canonical_workspace"],
            "workspace_project_id": marker.get("workspace_project_id"),
            "policy_version": marker.get("policy_version"),
            "enrolled_at": marker.get("enrolled_at"),
            "plans_dir": marker.get("plans_dir"),
        }
    registry = _read_registry()
    return _enrollment_for_identity_locked(registry, identity["root"])


def enrollment_for_workspace(workspace: Path) -> dict[str, Any] | None:
    """Return the active enrollment for a workspace, using canonical Git identity.

    A repository-level marker is consulted first so an alternate
    ``AGENT_ORCHESTRATOR_HOME`` cannot admit the same checkout as legacy. A
    pending enrollment intent also fails closed.
    """
    identity = _canonical(workspace)
    if not identity.get("is_git"):
        return None
    with _admission_locks(identity):
        intent = _read_intent(identity)
        if intent is not None:
            _fail(
                f"Workspace {identity['root']} has an incomplete managed enrollment "
                f"for plan {intent['plan_id']}; retry that create-plan or inspect it "
                "before any legacy mutation"
            )
        entry = _workspace_entries(identity)
        if entry:
            return entry
        managed = _managed_plan_for_identity(identity["root"])
        if managed:
            # The published ledger is authoritative even when the marker and
            # registry entry were lost. Report its explicit policy version so a
            # historical v1 checkout is never described as active policy 2.
            managed_version = _ledger_policy_version(_plan_path(managed))
            if (
                not isinstance(managed_version, int)
                or isinstance(managed_version, bool)
                or managed_version not in SUPPORTED_POLICY_VERSIONS
            ):
                managed_version = POLICY_VERSION
            return {
                "plan_id": managed,
                "canonical_workspace": identity["root"],
                "workspace_project_id": identity.get("project_id"),
                "policy_version": managed_version,
                "enrolled_at": None,
            }
        return None


def _enrollment_for_identity_locked(
    registry: dict[str, Any], identity: str
) -> dict[str, Any] | None:
    return registry["workspaces"].get(identity)


def _guard_legacy_creation_locked(identity: dict[str, Any]) -> None:
    intent = _read_intent(identity)
    if intent is not None:
        _fail(
            f"Workspace {identity['root']} has an incomplete managed enrollment for "
            f"plan {intent['plan_id']}; legacy plans cannot be created there"
        )
    entry = _workspace_entries(identity)
    if entry:
        _fail(
            f"Workspace {identity['root']} is already enrolled in managed plan "
            f"{entry['plan_id']}; create no additional plan there. Inspect it with "
            f"plan-checkpoint {entry['plan_id']}"
        )
    managed = _managed_plan_for_identity(identity["root"])
    if managed:
        _fail(
            f"Workspace {identity['root']} belongs to managed plan {managed}; "
            "enrollment cannot be replaced or duplicated"
        )
    lease_blocker = _lease_blocker(identity)
    if lease_blocker:
        _fail(lease_blocker)


def guard_legacy_plan_creation(workspace: Path) -> None:
    """Fail closed when a legacy plan would be created in a managed checkout."""
    identity = _canonical(workspace)
    if not identity.get("is_git"):
        return
    with _admission_locks(identity):
        _guard_legacy_creation_locked(identity)


@contextlib.contextmanager
def legacy_plan_creation_admission(workspace: Path) -> Iterator[dict[str, Any]]:
    """Hold admission locks across legacy plan creation to close the TOCTOU gap."""
    identity = _canonical(workspace)
    if not identity.get("is_git"):
        yield identity
        return
    with _admission_locks(identity):
        _guard_legacy_creation_locked(identity)
        yield identity


def require_legacy_plan_mutable(plan: dict[str, Any]) -> None:
    if plan.get("managed"):
        _fail(
            "Managed research plans are derived from the consensus ledger; ordinary plan "
            "mutation is blocked in B1"
        )
    plan_id = plan.get("plan_id")
    if isinstance(plan_id, str) and plan_id:
        if plan_is_managed(plan_id):
            _fail(
                f"Plan {plan_id} has a published managed consensus ledger; ordinary plan "
                "mutation is blocked in B1"
            )
    workspace = plan.get("workspace")
    if not isinstance(workspace, str) or not workspace:
        return
    entry = enrollment_for_workspace(Path(workspace))
    if entry:
        _fail(
            f"Workspace {workspace} is enrolled in managed plan {entry['plan_id']}; "
            "legacy plan mutation is blocked"
        )


def _published_event_files(events_dir: Path) -> list[Path]:
    if not events_dir.is_dir():
        return []
    files: list[Path] = []
    for item in sorted(events_dir.iterdir(), key=lambda candidate: candidate.name):
        if item.name.startswith("."):
            # Unpublished temporary files are ignored; they are never evidence.
            continue
        if (
            not EVENT_FILE_RE.fullmatch(item.name)
            or item.is_symlink()
            or not item.is_file()
        ):
            _fail(f"Unexpected published consensus ledger entry: {item}")
        files.append(item)
    return files


def _has_published_events(events_dir: Path) -> bool:
    return bool(_published_event_files(events_dir))


def plan_is_managed(plan_id: str) -> bool:
    path = _plan_path(plan_id)
    if _has_published_events(path / "consensus" / "events"):
        return True
    plan_path = path / "plan.json"
    if not plan_path.is_file():
        return False
    return bool(_read_json(plan_path).get("managed"))


def plan_is_strict_execution(plan_id: str) -> bool:
    """Read-only check of an enrolled plan's strict-execution mode.

    Used only to give strict plans a fail-closed CLI diagnostic before the
    generic provenance shape is validated. It grants no authority.
    """
    state = replay_events(_plan_path(plan_id))
    return _plan_is_strict(state.get("static"))


def _enrollment_failure_message(
    identity: dict[str, Any], entry: dict[str, Any] | None, managed: str | None
) -> str | None:
    if entry:
        return (
            f"Workspace {identity['root']} is enrolled in managed research plan "
            f"{entry['plan_id']}; B1 blocks every launch, including override flags and "
            f"alternate path forms. Inspect plan-checkpoint {entry['plan_id']}"
        )
    if managed:
        return (
            f"Workspace {identity['root']} belongs to managed research plan {managed}; "
            "B1 starts no managed writer, including override flags and alternate path "
            "forms"
        )
    return None


@contextlib.contextmanager
def launch_admission(
    workspace: Path,
    plan_id: str | None = None,
    managed: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Serialize launch admission against enrollment, then yield the identity.

    The repository marker is read under both the repository lock and the local
    registry lock, so an enrollment performed through another supported state
    home is still visible. The caller must create the job directory and a
    ``state=starting`` meta record before leaving this context so that a
    concurrent enrollment sees an active job and refuses to enroll.

    ``managed`` is an internal D1 descriptor from the execution helper. It is
    never a user CLI flag. A managed checkout admits exactly the pre-registered
    discussion or implementation job named by that descriptor; every other
    launch, including role/config/allow-dirty/concurrent overrides, remains
    blocked. The validator runs under the plan lock owned by the execution
    helper and re-checks the current B1 binding.
    """
    if managed is not None and not isinstance(managed, dict):
        _fail("Managed launch admission requires a protected execution descriptor")
    identity = _canonical(workspace)
    if not identity.get("is_git"):
        # A managed item cannot be accepted through a non-Git workspace either.
        if plan_id and plan_is_managed(plan_id):
            _fail(
                f"Plan {plan_id} is a managed B1 research plan; no managed writer may "
                "start before the B2 implementation gate"
            )
        if managed is not None:
            _fail("Managed execution requires a canonical Git work tree")
        yield identity
        return
    with _admission_locks(identity):
        intent = _read_intent(identity)
        if intent is not None:
            _fail(
                f"Workspace {identity['root']} has an incomplete managed enrollment "
                f"for plan {intent['plan_id']}; B1 fails closed until it is recovered"
            )
        entry = _workspace_entries(identity)
        managed_plan = _managed_plan_for_identity(identity["root"])
        if managed is not None:
            if not identity.get("is_work_tree"):
                _fail("Managed execution requires a canonical Git work tree")
            requested_plan = managed.get("plan_id")
            if plan_id is not None and plan_id != requested_plan:
                _fail("Managed launch plan does not match the requested plan")
            if entry is not None and entry.get("plan_id") != requested_plan:
                _fail(
                    "Managed launch plan does not match this workspace enrollment"
                )
            if managed_plan is not None and managed_plan != requested_plan:
                _fail("Managed launch plan does not own this workspace")
            if entry is None and managed_plan is None:
                _fail(
                    f"Plan {requested_plan} is not the managed enrollment for "
                    f"{identity['root']}"
                )
            validator = _HOOKS.get("managed_launch_validator")
            if validator is None:
                _fail(
                    "Managed execution admission is unavailable; failing closed"
                )
            try:
                validator(managed, identity)
            except _hook("runner_error"):
                raise
            except Exception as exc:
                _fail(f"Managed execution admission failed: {exc}")
            yield identity
            return
        message = _enrollment_failure_message(identity, entry, managed_plan)
        if message:
            _fail(message)
        if plan_id:
            path = _plan_path(plan_id)
            plan_path = path / "plan.json"
            plan = _read_json(plan_path) if plan_path.is_file() else None
            if plan and plan.get("managed"):
                _fail(
                    f"Plan {plan_id} is a managed B1 research plan; no managed writer may "
                    "start before the B2 implementation gate"
                )
            if _has_published_events(path / "consensus" / "events"):
                _fail(
                    f"Plan {plan_id} has a managed consensus ledger; no writer may start "
                    "from it in B1"
                )
        # Launch admission itself acquires the B2 repository writer lease inside
        # this lock via the runner hook, so contention is reported by the atomic
        # acquire path (with its completion hand-off retry) rather than by a
        # racy pre-check here. Enrollment paths below have no acquire step and
        # still consult the lease explicitly.
        yield identity


def worker_block_reason(meta: dict[str, Any]) -> str | None:
    """Return a fail-closed reason when a managed checkout must not run a worker.

    Corrupt registry, marker or ledger state is itself a fail-closed reason; the
    caller records ``worker_blocked`` and a failed result instead of crashing.
    """
    runner_error = _hook("runner_error")
    try:
        if "managed_execution" in meta:
            managed = meta.get("managed_execution")
            if not isinstance(managed, dict):
                return "Managed execution metadata is malformed; failing closed"
            validator = _HOOKS.get("managed_worker_validator")
            if validator is None:
                return (
                    "Managed execution worker validation is unavailable; failing closed"
                )
            return validator(meta)
        plan_id = meta.get("plan_id") or meta.get("managed_plan_id")
        if plan_id:
            if meta.get("managed_plan_id") or plan_is_managed(str(plan_id)):
                return (
                    f"Plan {plan_id} is managed by the B1 consensus gate; no worker may "
                    "execute managed items"
                )
        workspace = meta.get("workspace")
        if isinstance(workspace, str) and workspace:
            entry = enrollment_for_workspace(Path(workspace))
            if entry:
                return (
                    f"Workspace {workspace} is enrolled in managed plan "
                    f"{entry['plan_id']}; B1 blocks worker execution in this checkout"
                )
        lease_hook = _HOOKS.get("lease_worker_blocker")
        if lease_hook is not None:
            lease_block = lease_hook(meta)
            if lease_block:
                return str(lease_block)
    except runner_error as exc:
        return f"Admission state unavailable; B1 fails closed: {exc}"
    except (OSError, ValueError) as exc:
        return f"Admission state unavailable; B1 fails closed: {exc}"
    return None


def _new_step_state(step_id: str, policy_version: int) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "policy_version": policy_version,
        "roles": list(POLICY_ROLES[policy_version]),
        "cycle": 1,
        "proposals": {},
        "cross_examinations": {},
        "objections": [],
        "candidate": None,
        "ballots": {},
        "pauses": [],
        "outcome": None,
        "closed_cycles": [],
        "history": [],
        "freeze_history": [],
        "cycle_opening": {"cycle": 1, "mode": "plan_enrollment"},
    }


def _state_roles(state: dict[str, Any]) -> tuple[str, ...]:
    roles = state.get("roles")
    if isinstance(roles, (list, tuple)) and roles:
        return tuple(roles)
    return ROLES


def _policy_version_of(state: dict[str, Any]) -> int:
    static = state.get("static")
    if not isinstance(static, dict):
        _fail("Cannot determine the policy version of an empty consensus ledger")
    policy = static.get("policy")
    if not isinstance(policy, dict):
        _fail("Managed plan has no policy identity")
    version = policy.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in SUPPORTED_POLICY_VERSIONS
    ):
        _fail(f"Unknown research policy version {version!r}")
    return version


def _historical_state(state: dict[str, Any]) -> bool:
    return _policy_version_of(state) not in MUTABLE_POLICY_VERSIONS


def _reject_historical_state(state: dict[str, Any]) -> None:
    if _historical_state(state):
        _fail(HISTORICAL_V1_GUIDANCE)


def _require_active_role(role: Any) -> None:
    if role not in ROLE_LABELS:
        _fail(f"Unknown role {role!r}; expected one of {', '.join(ROLES)}")
    if role not in ROLES:
        _fail(
            f"Role {role!r} is not in the active policy version {POLICY_VERSION} "
            f"roster ({', '.join(ROLES)}). Policy version 1 is historical read-only "
            "and the removed Antigravity provider is never launched."
        )


def _event_role(state: dict[str, Any], payload: dict[str, Any], label: str) -> str:
    role = payload.get("role")
    roles = _state_roles(state)
    if role not in roles:
        _fail(
            f"{label} role {role!r} is not in the policy version "
            f"{state.get('policy_version')} roster: {', '.join(roles)}"
        )
    return role


def stage_of(state: dict[str, Any]) -> str:
    roles = _state_roles(state)
    if state.get("outcome"):
        return str(state["outcome"])
    if state.get("candidate"):
        return STAGE_BALLOTS
    if len(state.get("cross_examinations", {})) == len(roles):
        return STAGE_CANDIDATE
    if len(state.get("proposals", {})) == len(roles):
        return STAGE_CROSS
    return STAGE_PROPOSALS


def _stage_round(stage: str) -> int | None:
    if stage == STAGE_PROPOSALS:
        return 1
    if stage == STAGE_CROSS:
        return 2
    if stage in {STAGE_CANDIDATE, STAGE_BALLOTS, STAGE_CONSENSUS, STAGE_HUMAN}:
        return 3
    return None


def dependency_blockers(
    step: dict[str, Any], state: dict[str, Any] | None = None
) -> list[str]:
    """Return unmet prerequisites for a step.

    B1 has no command that can mint independently verified MERGED evidence, so
    any declared dependency blocks every transition for the dependent step.
    Previous consensus in the predecessor is deliberately not treated as merge
    evidence.
    """
    reasons: list[str] = []
    for dependency in step.get("depends_on", []):
        reasons.append(
            f"dependency {dependency} has no independently verified MERGED evidence; "
            "B1 provides no command that mints merge evidence"
        )
    return reasons


def effective_stage(step: dict[str, Any], state: dict[str, Any]) -> str:
    if dependency_blockers(step):
        return STAGE_DEPENDENCY
    return stage_of(state)


def _tally(state: dict[str, Any]) -> dict[str, int]:
    counts = {vote: 0 for vote in VOTES}
    for ballot in state["ballots"].values():
        counts[ballot["vote"]] = counts.get(ballot["vote"], 0) + 1
    return counts


def _votes_in_role_order(state: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"role": role, "vote": state["ballots"][role]["vote"]}
        for role in _state_roles(state)
        if role in state["ballots"]
    ]


def _open_pause(
    state: dict[str, Any], round_number: int, role: str
) -> dict[str, Any] | None:
    for pause in state.get("pauses", []):
        if (
            pause.get("round") == round_number
            and pause.get("role") == role
            and pause.get("open")
        ):
            return pause
    return None


def _role_submitted(state: dict[str, Any], stage: str, role: str) -> bool:
    if stage == STAGE_PROPOSALS:
        return role in state["proposals"]
    if stage == STAGE_CROSS:
        return role in state["cross_examinations"]
    if stage == STAGE_BALLOTS:
        return role in state["ballots"]
    return True


def _closed_cycle_record(state: dict[str, Any], event: dict[str, Any]) -> None:
    candidate = state["candidate"] or {}
    tally = event["payload"]["tally"]
    votes = event["payload"]["votes"]
    # Keep the complete settled cycle so regenerated per-cycle artifacts retain
    # proposals, cross-examinations, objections, candidate content, dispositions,
    # ballot rationales/provenance and pauses after a new cycle opens.
    state["history"].append(
        {
            "cycle": state["cycle"],
            "outcome": state["outcome"],
            "digest": candidate.get("digest"),
            "tally": copy.deepcopy(tally),
            "votes": copy.deepcopy(votes),
            "objection_ids": [item["objection_id"] for item in state["objections"]],
            "closed_at": event["at"],
            "cycle_opening": copy.deepcopy(state.get("cycle_opening")),
            "proposals": copy.deepcopy(state["proposals"]),
            "cross_examinations": copy.deepcopy(state["cross_examinations"]),
            "objections": copy.deepcopy(state["objections"]),
            "candidate": copy.deepcopy(state["candidate"]),
            "ballots": copy.deepcopy(state["ballots"]),
            "pauses": copy.deepcopy(state["pauses"]),
            "freeze_history": copy.deepcopy(state["freeze_history"]),
        }
    )
    state["closed_cycles"].append(
        {
            "cycle": state["cycle"],
            "outcome": state["outcome"],
            "digest": candidate.get("digest"),
            "tally": tally,
            "votes": votes,
            "objection_ids": [item["objection_id"] for item in state["objections"]],
            "closed_at": event["at"],
        }
    )


def _provenance(raw: Any, label: str) -> dict[str, Any]:
    value = _exact_keys(raw, {"job_id", "leader"}, label)
    job_id = value.get("job_id")
    leader = value.get("leader")
    if job_id is None and leader is None:
        _fail(f"{label} requires a job_id or leader identity")
    if job_id is not None:
        if not isinstance(job_id, str) or not ID_RE.fullmatch(job_id):
            _fail(f"{label}.job_id must be a valid job identifier")
    if leader is not None:
        leader = _text(leader, f"{label}.leader", minimum=2)
    return {"job_id": job_id, "leader": leader}


def _validate_source_evidence(raw: Any, label: str) -> dict[str, Any]:
    """Validate the immutable provenance record copied from D1 ingestion.

    The original provider payload and result remain in D1's content-addressed
    evidence store; B1 records only fixed hashes and identities so replay can
    validate this ledger without reading another log or probing a process.
    """
    value = _exact_keys(raw, SOURCE_EVIDENCE_KEYS, label)
    provider = value.get("provider")
    if provider not in {"deepseek", "glm"}:
        _fail(f"{label}.provider is not a reserved readonly provider")
    if value.get("operation") not in {"proposal", "cross_examination", "consensus"}:
        _fail(f"{label}.operation is not a readonly discussion operation")
    job_id = value.get("job_id")
    if not isinstance(job_id, str) or not ID_RE.fullmatch(job_id):
        _fail(f"{label}.job_id must be a valid job identifier")
    evidence_event_id = value.get("evidence_event_id")
    if not isinstance(evidence_event_id, str) or not OP_ID_RE.fullmatch(
        evidence_event_id.split(":", 1)[0]
    ):
        _fail(f"{label}.evidence_event_id is invalid")
    for key in (
        "evidence_digest",
        "task_source_sha256",
        "job_meta_sha256",
        "job_result_sha256",
        "provider_result_sha256",
        "provider_payload_sha256",
        "original_payload_sha256",
        "mapped_sha256",
        "observed_workspace_digest",
        "assignment_digest",
    ):
        item = value.get(key)
        if not isinstance(item, str) or not DIGEST_RE.fullmatch(item):
            _fail(f"{label}.{key} must be a lowercase SHA-256 digest")
    candidate = value.get("candidate_sha256")
    if candidate is not None and (
        not isinstance(candidate, str) or not DIGEST_RE.fullmatch(candidate)
    ):
        _fail(f"{label}.candidate_sha256 must be a digest or null")
    return dict(value)


def _strict_participant_evidence(
    static: dict[str, Any],
    payload: dict[str, Any],
    *,
    label: str,
    operation: str,
    candidate_sha256: str | None,
) -> None:
    """Replay the strict participant gate from immutable ledger fields.

    Codex is the trusted active coordinator and must carry a leader identity
    with no provider job. Every other role must carry the immutable D1 source
    evidence for the exact operation, role, slot and (for ballots) candidate.
    This is structural replay validation; semantic review remains D2.
    """
    if not _plan_is_strict(static):
        return
    role = payload.get("role")
    if role == "codex":
        if "source_evidence" in payload:
            _fail(f"{label}.source_evidence is not valid for the Codex leader")
        provenance = payload.get("provenance")
        if not isinstance(provenance, dict):
            _fail(f"{label}.provenance is missing")
        if provenance.get("job_id") is not None or not provenance.get("leader"):
            _fail(
                "Strict-execution Codex content requires the active leader "
                "identity and never a provider job identity"
            )
        return
    source = payload.get("source_evidence")
    if not isinstance(source, dict):
        _fail(
            f"{label} has no protected provider source evidence; role labels and "
            "job strings never grant discussion authority"
        )
    evidence = _validate_source_evidence(source, f"{label}.source_evidence")
    if evidence.get("provider") != role:
        _fail(f"{label} provider does not match its role slot")
    if evidence.get("operation") != operation:
        _fail(f"{label} operation does not match its discussion round")
    if evidence.get("candidate_sha256") != candidate_sha256:
        _fail(f"{label} does not bind the current frozen candidate digest")


def _provider_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        _fail(f"{label} exceeds {MAX_TEXT_BYTES} bytes")
    if "\x00" in value:
        _fail(f"{label} contains a NUL byte")
    return value


def _provider_text_list(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        _fail(f"{label} must be a non-empty JSON array of strings")
    if len(value) > 100:
        _fail(f"{label} has too many entries")
    return [
        _provider_text(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    ]


def _provider_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    return _exact_keys(value, keys, label)


def map_provider_payload(operation: str, payload: Any) -> dict[str, Any]:
    """Deterministically map one validated C payload to the B1 schema.

    The mapping is versioned by C's result_version/operation and preserves both
    original and mapped content: callers keep the original payload in the D1
    evidence blob and B1 records both hashes. No field is synthesized; a valid
    but insufficient provider response fails here and must be recorded as an
    invalid submission, never as agreement.
    """
    if operation == "proposal":
        value = _provider_exact_keys(
            payload,
            {
                "approach",
                "rationale",
                "assumptions",
                "problems",
                "alternatives",
                "feasibility",
                "testing",
            },
            "provider proposal payload",
        )
        return {
            "approach": _provider_text(value["approach"], "proposal.approach"),
            "rationale": _provider_text(value["rationale"], "proposal.rationale"),
            "assumptions": _provider_text_list(
                value["assumptions"], "proposal.assumptions"
            ),
            "risks": _provider_text_list(value["problems"], "proposal.problems"),
            "alternatives": _provider_text_list(
                value["alternatives"], "proposal.alternatives"
            ),
            "feasibility": _provider_text(
                value["feasibility"], "proposal.feasibility"
            ),
            "tests": _provider_text_list(value["testing"], "proposal.testing"),
        }
    if operation == "cross_examination":
        value = _provider_exact_keys(
            payload,
            {"objections", "responses", "revisions"},
            "provider cross-examination payload",
        )
        objections = value["objections"]
        if not isinstance(objections, list):
            _fail("cross-examination.objections must be a JSON array")
        if len(objections) > 100:
            _fail("cross-examination.objections has too many entries")
        challenges: list[dict[str, str]] = []
        for index, item in enumerate(objections):
            label = f"cross-examination.objections[{index}]"
            if isinstance(item, str):
                challenges.append(
                    {"objection": _provider_text(item, label)}
                )
                continue
            entry = _keys_with_optional(
                item, {"objection"}, {"severity"}, label
            )
            challenge = {
                "objection": _provider_text(entry["objection"], f"{label}.objection")
            }
            severity = entry.get("severity")
            if severity is not None:
                if severity not in {"low", "medium", "high"}:
                    _fail(f"{label}.severity must be low, medium, or high")
                challenge["severity"] = severity
            challenges.append(challenge)
        return {
            "responses": _provider_text_list(
                value["responses"], "cross-examination.responses"
            ),
            "challenges": challenges,
            "revisions": _provider_text_list(
                value["revisions"], "cross-examination.revisions"
            ),
        }
    if operation == "consensus":
        value = _provider_exact_keys(
            payload,
            {"decision", "candidate_sha256", "rationale"},
            "provider consensus payload",
        )
        decision = value["decision"]
        if decision not in VOTES:
            _fail("consensus.decision must be AGREE, DISAGREE, or NEEDS_DISCUSSION")
        digest = value["candidate_sha256"]
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            _fail("consensus.candidate_sha256 must be a lowercase SHA-256 digest")
        return {
            "vote": decision,
            "digest": digest,
            "rationale": _provider_text(
                value["rationale"], "consensus.rationale"
            ),
        }
    _fail(f"Provider mapping is unsupported for operation {operation!r}")


def _normalize_cross_without_ids(raw: Any) -> dict[str, Any]:
    """Normalize a mapped cross-examination without assigning objection IDs."""
    value = _exact_keys(raw, CROSS_KEYS, "cross-examination")
    responses = _text_list(
        value.get("responses"), "cross-examination.responses", minimum_chars=10
    )
    challenges = value.get("challenges")
    if not isinstance(challenges, list) or len(challenges) > MAX_LIST_ITEMS:
        _fail(
            f"cross-examination.challenges must contain at most {MAX_LIST_ITEMS} items"
        )
    normalized_challenges: list[dict[str, str]] = []
    for index, challenge in enumerate(challenges):
        label = f"cross-examination.challenges[{index}]"
        item = _keys_with_optional(challenge, {"objection"}, {"severity"}, label)
        normalized = {
            "objection": _text(item.get("objection"), f"{label}.objection", minimum=10)
        }
        severity = item.get("severity")
        if severity is not None:
            normalized["severity"] = _text(severity, f"{label}.severity", minimum=2)
        normalized_challenges.append(normalized)
    revisions = _text_list(
        value.get("revisions"),
        "cross-examination.revisions",
        minimum_items=0,
        minimum_chars=3,
    )
    return {
        "responses": responses,
        "challenges": normalized_challenges,
        "revisions": revisions,
    }


def normalize_provider_mapping(operation: str, payload: Any) -> dict[str, Any]:
    """Map and normalize one provider payload exactly as B1 will record it."""
    mapped = map_provider_payload(operation, payload)
    if operation == "proposal":
        return _validate_proposal(mapped)
    if operation == "cross_examination":
        return _normalize_cross_without_ids(mapped)
    if operation == "consensus":
        rationale = _text(mapped["rationale"], "ballot.rationale", minimum=1)
        return {
            "vote": mapped["vote"],
            "digest": mapped["digest"],
            "rationale": rationale,
        }
    _fail(f"Provider normalization is unsupported for operation {operation!r}")


def provider_operation_for_round(round_number: int) -> str:
    """Return the reserved C operation bound to a discussion round."""
    if round_number == 1:
        return "proposal"
    if round_number == 2:
        return "cross_examination"
    if round_number == 3:
        return "consensus"
    _fail(f"Discussion round {round_number!r} has no provider operation")


def _validate_proposal(raw: Any) -> dict[str, Any]:
    value = _exact_keys(raw, PROPOSAL_KEYS, "proposal")
    return {
        "approach": _text(value.get("approach"), "proposal.approach", minimum=20),
        "rationale": _text(value.get("rationale"), "proposal.rationale", minimum=20),
        "assumptions": _text_list(
            value.get("assumptions"), "proposal.assumptions", minimum_chars=3
        ),
        "risks": _text_list(value.get("risks"), "proposal.risks", minimum_chars=3),
        "alternatives": _text_list(
            value.get("alternatives"), "proposal.alternatives", minimum_chars=3
        ),
        "feasibility": _text(
            value.get("feasibility"), "proposal.feasibility", minimum=10
        ),
        "tests": _text_list(value.get("tests"), "proposal.tests", minimum_chars=3),
    }


def _validate_cross(
    raw: Any, existing_objections: int, assign_ids: bool
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    value = _exact_keys(raw, CROSS_KEYS, "cross-examination")
    responses = _text_list(
        value.get("responses"), "cross-examination.responses", minimum_chars=10
    )
    challenges = value.get("challenges")
    if not isinstance(challenges, list) or len(challenges) > MAX_LIST_ITEMS:
        _fail(
            f"cross-examination.challenges must contain at most {MAX_LIST_ITEMS} items"
        )
    normalized_challenges: list[dict[str, str]] = []
    objections: list[dict[str, str]] = []
    for index, challenge in enumerate(challenges):
        label = f"cross-examination.challenges[{index}]"
        if not isinstance(challenge, dict):
            _fail(f"{label} must be a JSON object")
        actual = set(challenge)
        if "objection" not in actual or actual - {
            "objection",
            "severity",
            "objection_id",
        }:
            _fail(f"{label} must contain an objection and may contain severity")
        if assign_ids and "objection_id" in actual:
            _fail(
                f"{label} must not supply objection_id; the runner numbers objections "
                "in receipt order"
            )
        objection_text = _text(challenge.get("objection"), f"{label}.objection", minimum=10)
        severity = challenge.get("severity")
        if severity is not None:
            severity = _text(severity, f"{label}.severity", minimum=2)
        expected_id = f"O{existing_objections + index + 1:03d}"
        if assign_ids:
            objection_id = expected_id
        else:
            objection_id = challenge.get("objection_id")
            if objection_id != expected_id:
                _fail(
                    f"{label}.objection_id is {objection_id!r}; expected {expected_id!r}"
                )
        normalized = {"objection_id": objection_id, "objection": objection_text}
        if severity is not None:
            normalized["severity"] = severity
        normalized_challenges.append(normalized)
        objections.append(
            {
                "objection_id": objection_id,
                "role": "",
                "text": objection_text,
            }
        )
    revisions = _text_list(
        value.get("revisions"),
        "cross-examination.revisions",
        minimum_items=0,
        minimum_chars=3,
    )
    return (
        {
            "responses": responses,
            "challenges": normalized_challenges,
            "revisions": revisions,
        },
        objections,
    )


def _validate_candidate(
    raw: Any,
    objection_ids: list[str],
    manifest_step: dict[str, Any] | None = None,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    value = _keys_with_optional(
        raw,
        CANDIDATE_KEYS - CANDIDATE_OPTIONAL_KEYS,
        CANDIDATE_OPTIONAL_KEYS,
        "candidate",
    )
    candidate = {
        "final_design": _text(value.get("final_design"), "candidate.final_design", minimum=40),
        "important_decisions": _text_list(
            value.get("important_decisions"),
            "candidate.important_decisions",
            minimum_chars=3,
        ),
        "rejected_alternatives": [],
        "objection_dispositions": [],
        "remaining_risks": _text_list(
            value.get("remaining_risks"), "candidate.remaining_risks", minimum_chars=3
        ),
    }
    rejected = value.get("rejected_alternatives")
    if not isinstance(rejected, list) or not rejected:
        _fail("candidate.rejected_alternatives must list at least one alternative")
    for index, entry in enumerate(rejected):
        item = _exact_keys(
            entry,
            {"alternative", "reason"},
            f"candidate.rejected_alternatives[{index}]",
        )
        candidate["rejected_alternatives"].append(
            {
                "alternative": _text(
                    item.get("alternative"),
                    f"candidate.rejected_alternatives[{index}].alternative",
                    minimum=3,
                ),
                "reason": _text(
                    item.get("reason"),
                    f"candidate.rejected_alternatives[{index}].reason",
                    minimum=3,
                ),
            }
        )
    dispositions = value.get("objection_dispositions")
    if not isinstance(dispositions, list):
        _fail("candidate.objection_dispositions must be a JSON array")
    seen: set[str] = set()
    for index, entry in enumerate(dispositions):
        item = _exact_keys(
            entry,
            {"objection_id", "disposition", "reason"},
            f"candidate.objection_dispositions[{index}]",
        )
        objection_id = item.get("objection_id")
        if not isinstance(objection_id, str) or objection_id not in objection_ids:
            _fail(
                f"candidate.objection_dispositions[{index}].objection_id "
                f"{objection_id!r} is not a numbered objection in this cycle"
            )
        if objection_id in seen:
            _fail(f"Duplicate disposition for objection {objection_id}")
        seen.add(objection_id)
        candidate["objection_dispositions"].append(
            {
                "objection_id": objection_id,
                "disposition": _text(
                    item.get("disposition"),
                    f"candidate.objection_dispositions[{index}].disposition",
                    minimum=3,
                ),
                "reason": _text(
                    item.get("reason"),
                    f"candidate.objection_dispositions[{index}].reason",
                    minimum=3,
                ),
            }
        )
    missing = sorted(set(objection_ids) - seen)
    if missing:
        _fail(
            "candidate.objection_dispositions must dispose every numbered objection; "
            f"missing: {', '.join(missing)}"
        )
    if "execution_constraints" in value:
        if not strict:
            _fail(
                "execution_constraints are valid only for strict-execution "
                "candidates; legacy plans never acquire source-write authority"
            )
        candidate["execution_constraints"] = validate_execution_constraints(
            value.get("execution_constraints"), manifest_step
        )
    elif strict:
        _fail(
            "Strict-execution candidates must include version 1 execution_constraints"
        )
    return candidate


def _validate_enrollment_payload(payload: dict[str, Any], plan_id: str) -> dict[str, Any]:
    _keys_with_optional(
        payload,
        PAYLOAD_KEYS["plan_enrolled"] - ENROLLMENT_OPTIONAL_KEYS,
        ENROLLMENT_OPTIONAL_KEYS,
        "plan_enrolled payload",
    )
    strict_execution = payload.get(STRICT_EXECUTION_KEY)
    if strict_execution is not None and strict_execution is not True:
        _fail("plan_enrolled strict_execution must be true when present")
    manifest, manifest_digest = validate_manifest(payload.get("manifest"))
    if payload.get("manifest_digest") != manifest_digest:
        _fail("plan_enrolled manifest_digest does not match the manifest content")
    policy = payload.get("policy")
    if not isinstance(policy, dict) or policy.get("name") != POLICY_NAME:
        _fail("plan_enrolled policy identity or version is invalid")
    version = policy.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in SUPPORTED_POLICY_VERSIONS
    ):
        _fail("plan_enrolled policy identity or version is invalid")
    expected_roles = list(POLICY_ROLES[version])
    if list(payload.get("roles", [])) != expected_roles:
        _fail(
            f"plan_enrolled roles do not match the policy version {version} roster: "
            + ", ".join(expected_roles)
        )
    if manifest["policy_version"] != version:
        _fail("plan_enrolled manifest policy_version does not match the policy identity")
    if payload.get("round_budget") != DEFAULT_ROUND_BUDGET:
        _fail("plan_enrolled round budget is invalid")
    if payload.get("workspace_mode") != "project":
        _fail("Managed B1 plans require project workspace mode")
    if not isinstance(payload.get("workspace"), str) or not payload.get("workspace"):
        _fail("plan_enrolled workspace identity is invalid")
    canonical = payload.get("canonical_workspace")
    project_id = payload.get("workspace_project_id")
    if not isinstance(canonical, str) or not canonical:
        _fail("plan_enrolled canonical workspace identity is invalid")
    if not isinstance(project_id, str) or not project_id.startswith("p-"):
        _fail("plan_enrolled workspace project identity is invalid")
    for key in ("title", "plan_file"):
        if not isinstance(payload.get(key), str) or not payload.get(key):
            _fail(f"plan_enrolled {key} is invalid")
    if not isinstance(payload.get("plan_sha256"), str) or not DIGEST_RE.fullmatch(
        payload["plan_sha256"]
    ):
        _fail("plan_enrolled plan digest is invalid")
    for key in ("goal", "team_policy", "executor_policy"):
        if not isinstance(payload.get(key), dict):
            _fail(f"plan_enrolled {key} must be a JSON object")
    return {
        **payload,
        "plan_id": plan_id,
        "manifest": manifest,
        "manifest_digest": manifest_digest,
        "roles": list(expected_roles),
        "policy_version": version,
        "created_at": "",
    }


def _validate_event_header(
    event: Any,
    index: int,
    plan_id: str,
    previous_digest: str,
    operation_state: dict[str, Any],
) -> None:
    if not isinstance(event, dict):
        _fail(f"Ledger event {index} is not a JSON object")
    if set(event) != EVENT_KEYS:
        _fail(f"Ledger event {index} has an invalid schema")
    if event.get("sequence") != index:
        _fail(
            f"Ledger event {index} has sequence {event.get('sequence')!r}; expected {index}"
        )
    event_type = event.get("type")
    if event_type not in PAYLOAD_KEYS:
        _fail(f"Ledger event {index} has unknown type {event_type!r}")
    if event.get("plan_id") != plan_id:
        _fail(f"Ledger event {index} belongs to another plan")
    if not isinstance(event.get("at"), str) or not event["at"]:
        _fail(f"Ledger event {index} has no timestamp")
    digest = event.get("digest")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        _fail(f"Ledger event {index} has an invalid digest")
    if event.get("prev_digest") != previous_digest:
        _fail(f"Ledger event {index} does not reference the previous event digest")
    computed = _digest({key: value for key, value in event.items() if key != "digest"})
    if computed != digest:
        _fail(f"Ledger event {index} content digest does not match its bytes")
    operation_id = event.get("operation_id")
    if not isinstance(operation_id, str) or not OP_ID_RE.fullmatch(operation_id):
        _fail(f"Ledger event {index} has an invalid operation ID")
    request_digest = event.get("request_digest")
    if not isinstance(request_digest, str) or not DIGEST_RE.fullmatch(request_digest):
        _fail(f"Ledger event {index} has an invalid request digest")
    last_operation = operation_state.get("operation_id")
    if operation_id == last_operation:
        operation_state["ordinal"] = operation_state.get("ordinal", 0) + 1
    else:
        if operation_id in operation_state.setdefault("seen", set()):
            _fail(f"Operation {operation_id} was published in non-contiguous events")
        operation_state["seen"].add(operation_id)
        operation_state["operation_id"] = operation_id
        operation_state["ordinal"] = 1
        operation_state["request_digest"] = request_digest
    if operation_state.get("request_digest") != request_digest:
        _fail(f"Operation {operation_id} has inconsistent request digests")
    if event.get("event_id") != f"{operation_id}:{operation_state['ordinal']}":
        _fail(f"Ledger event {index} has an invalid event ID")
    cycle = event.get("cycle")
    if not isinstance(cycle, int) or isinstance(cycle, bool) or cycle < 1:
        _fail(f"Ledger event {index} has an invalid cycle")
    round_number = event.get("round")
    if round_number is not None and round_number not in (1, 2, 3):
        _fail(f"Ledger event {index} has an invalid round")
    payload = event.get("payload")
    if not isinstance(payload, dict):
        _fail(f"Ledger event {index} has an invalid payload")
    if len(_canonical_bytes(event)) > MAX_EVENT_BYTES:
        _fail(f"Ledger event {index} exceeds {MAX_EVENT_BYTES} bytes")
    if event_type == "plan_enrolled":
        if event.get("step_id") is not None or cycle != 1 or round_number is not None:
            _fail("plan_enrolled must be the cycle 1, non-step ledger root")
    else:
        step_id = event.get("step_id")
        if not isinstance(step_id, str) or not ID_RE.fullmatch(step_id):
            _fail(f"Ledger event {index} has an invalid step ID")


def _manifest_step(static: dict[str, Any], step_id: str) -> dict[str, Any]:
    for step in static["manifest"]["steps"]:
        if step["id"] == step_id:
            return step
    _fail(f"Ledger references unknown step {step_id!r}")


def _binding_for(
    static: dict[str, Any], step: dict[str, Any], cycle: int
) -> dict[str, Any]:
    version = int(static["policy"]["version"])
    binding: dict[str, Any] = {
        "policy": {"name": POLICY_NAME, "version": version},
        "plan_id": static["plan_id"],
        "plan_sha256": static["plan_sha256"],
        "manifest_digest": static["manifest_digest"],
        "step_id": step["id"],
        "cycle": cycle,
        "vote_round": 3,
        "dependency_references": [
            {"step_id": dependency, "required_evidence": "VERIFIED_MERGED"}
            for dependency in step["depends_on"]
        ],
    }
    if version >= ACTIVE_POLICY_VERSION:
        # Policy version 2 explicitly binds the fixed three-role roster. The
        # historical version 1 binding schema is preserved exactly so archived
        # candidate digests replay unchanged.
        binding["roles"] = list(POLICY_ROLES[version])
    return binding


def _candidate_digest(binding: dict[str, Any], candidate: dict[str, Any]) -> str:
    return _digest({"binding": binding, "candidate": candidate})


def _apply_step_event(
    state: dict[str, Any], event: dict[str, Any], static: dict[str, Any]
) -> None:
    event_type = event["type"]
    cycle = event["cycle"]
    payload = event["payload"]
    step = _manifest_step(static, state["step_id"])
    blockers = dependency_blockers(step)
    if blockers:
        _fail(
            "Ledger event advances a step whose dependencies lack independently "
            "verified MERGED evidence: " + "; ".join(blockers)
        )
    if event_type == "new_cycle_authorized":
        if state["outcome"] not in {STAGE_HUMAN, STAGE_CONSENSUS}:
            _fail(
                "new cycle can only follow a settled cycle "
                "(HUMAN_DECISION_REQUIRED or CONSENSUS_REACHED)"
            )
        if cycle != state["cycle"] + 1:
            _fail("new cycle event has an invalid cycle number")
        _exact_keys(payload, PAYLOAD_KEYS["new_cycle_authorized"], "new_cycle_authorized payload")
        if payload.get("previous_cycle") != state["cycle"]:
            _fail("new cycle previous_cycle does not match the settled cycle")
        previous_outcome = payload.get("previous_outcome")
        if previous_outcome != state["outcome"]:
            _fail("new cycle does not preserve the settled cycle outcome")
        if payload.get("new_cycle") != cycle or event.get("round") != 1:
            _fail("new cycle payload does not match its cycle and opening round")
        previous_digest = (state.get("candidate") or {}).get("digest")
        if payload.get("previous_digest") != previous_digest:
            _fail("new cycle does not preserve the previous frozen digest")
        authorization = _keys_with_optional(
            payload.get("authorization"),
            {"authorized_by", "text"},
            NEW_CYCLE_AUTHORIZATION_OPTIONAL_KEYS,
            "new_cycle_authorized.authorization",
        )
        _text(authorization.get("authorized_by"), "authorization.authorized_by", minimum=2)
        _text(authorization.get("text"), "authorization.text", minimum=10)
        if _plan_is_strict(static):
            kind = authorization.get("authorization_kind")
            if kind not in AUTHORIZATION_KINDS:
                _fail(
                    "Strict-execution new cycles require authorization_kind "
                    "'human' or 'coordinator'"
                )
            if previous_outcome == STAGE_HUMAN and kind != "human":
                _fail(
                    "A non-unanimous cycle can only reopen through an honest human "
                    "authorization; coordinator-requested consensus is available "
                    "only after a successful unanimous cycle"
                )
        state["cycle"] = cycle
        state["proposals"] = {}
        state["cross_examinations"] = {}
        state["objections"] = []
        state["candidate"] = None
        state["ballots"] = {}
        state["pauses"] = []
        state["outcome"] = None
        state["cycle_opening"] = {
            "cycle": cycle,
            "mode": "human_authorized",
            "authorized_by": authorization["authorized_by"],
            "authorization": authorization["text"],
            "previous_cycle": state["cycle"] - 1,
            "previous_outcome": previous_outcome,
            "previous_digest": previous_digest,
            "opened_at": event["at"],
        }
        if "authorization_kind" in authorization:
            state["cycle_opening"]["authorization_kind"] = authorization[
                "authorization_kind"
            ]
        return
    if event["step_id"] != state["step_id"]:
        _fail("Ledger event is attached to the wrong step")
    if cycle != state["cycle"]:
        _fail(
            f"Ledger event cycle {cycle} does not match the active cycle {state['cycle']}"
        )
    stage = stage_of(state)
    round_number = _stage_round(stage)
    if event_type == "proposal_recorded":
        if stage != STAGE_PROPOSALS:
            _fail("Proposal recorded outside an open round 1")
        if event.get("round") != 1:
            _fail("Proposal event must be round 1")
        _keys_with_optional(
            payload,
            PAYLOAD_KEYS["proposal_recorded"],
            PROPOSAL_OPTIONAL_KEYS,
            "proposal_recorded payload",
        )
        if "source_evidence" in payload:
            _validate_source_evidence(
                payload.get("source_evidence"), "proposal_recorded.source_evidence"
            )
        _strict_participant_evidence(
            static,
            payload,
            label="proposal_recorded",
            operation="proposal",
            candidate_sha256=None,
        )
        role = _event_role(state, payload, "Proposal")
        if role in state["proposals"]:
            _fail(f"Duplicate proposal from {role} in cycle {cycle}")
        provenance = _provenance(payload.get("provenance"), "proposal.provenance")
        submission = _validate_proposal(payload.get("submission"))
        retry_id = payload.get("retry_id")
        if retry_id is not None:
            pause = _open_pause(state, 1, role)
            if not pause or pause.get("retry_id") != retry_id:
                _fail("Proposal retry ID does not match an open provider pause")
            pause["open"] = False
        state["proposals"][role] = {
            "role": role,
            "provenance": provenance,
            "submission": submission,
            "retry_id": retry_id,
            "event_id": event["event_id"],
        }
        return
    if event_type == "cross_examination_recorded":
        if stage != STAGE_CROSS:
            _fail("Cross-examination recorded outside an open round 2")
        if event.get("round") != 2:
            _fail("Cross-examination event must be round 2")
        _keys_with_optional(
            payload,
            PAYLOAD_KEYS["cross_examination_recorded"],
            CROSS_OPTIONAL_KEYS,
            "cross_examination_recorded payload",
        )
        if "source_evidence" in payload:
            _validate_source_evidence(
                payload.get("source_evidence"),
                "cross_examination_recorded.source_evidence",
            )
        _strict_participant_evidence(
            static,
            payload,
            label="cross_examination_recorded",
            operation="cross_examination",
            candidate_sha256=None,
        )
        role = _event_role(state, payload, "Cross-examination")
        if role in state["cross_examinations"]:
            _fail(f"Duplicate cross-examination from {role} in cycle {cycle}")
        provenance = _provenance(
            payload.get("provenance"), "cross-examination.provenance"
        )
        submission, objections = _validate_cross(
            payload.get("submission"), len(state["objections"]), assign_ids=False
        )
        for item in objections:
            item["role"] = role
        retry_id = payload.get("retry_id")
        if retry_id is not None:
            pause = _open_pause(state, 2, role)
            if not pause or pause.get("retry_id") != retry_id:
                _fail("Cross-examination retry ID does not match an open provider pause")
            pause["open"] = False
        state["cross_examinations"][role] = {
            "role": role,
            "provenance": provenance,
            "submission": submission,
            "retry_id": retry_id,
            "event_id": event["event_id"],
        }
        state["objections"].extend(objections)
        return
    if event_type == "candidate_frozen":
        if stage != STAGE_CANDIDATE:
            _fail("Candidate freeze is not available before round 2 completes")
        if event.get("round") != 3:
            _fail("Candidate freeze must open round 3")
        _exact_keys(payload, PAYLOAD_KEYS["candidate_frozen"], "candidate_frozen payload")
        objection_ids = [item["objection_id"] for item in state["objections"]]
        if payload.get("objection_ids") != objection_ids:
            _fail("Candidate objection references do not match this cycle's objections")
        manifest_step = _manifest_step(static, state["step_id"])
        candidate = _validate_candidate(
            payload.get("candidate"),
            objection_ids,
            manifest_step,
            strict=_plan_is_strict(static),
        )
        binding = payload.get("binding")
        expected_binding = _binding_for(static, manifest_step, cycle)
        if not isinstance(binding, dict) or binding != expected_binding:
            _fail("Candidate binding does not match the plan, step, dependencies, policy, cycle, and vote round")
        digest = payload.get("digest")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            _fail("Candidate digest is invalid")
        if digest != _candidate_digest(binding, candidate):
            _fail("Candidate digest does not match its binding and content")
        state["candidate"] = {
            "digest": digest,
            "binding": binding,
            "candidate": candidate,
            "event_id": event["event_id"],
        }
        state["freeze_history"].append(
            {"cycle": cycle, "digest": digest, "event_id": event["event_id"]}
        )
        return
    if event_type == "ballot_recorded":
        if stage != STAGE_BALLOTS:
            _fail("Ballot recorded before the candidate was frozen")
        if event.get("round") != 3:
            _fail("Ballot event must be round 3")
        _keys_with_optional(
            payload,
            PAYLOAD_KEYS["ballot_recorded"],
            BALLOT_OPTIONAL_KEYS,
            "ballot_recorded payload",
        )
        if "source_evidence" in payload:
            _validate_source_evidence(
                payload.get("source_evidence"), "ballot_recorded.source_evidence"
            )
        role = _event_role(state, payload, "Ballot")
        _strict_participant_evidence(
            static,
            payload,
            label="ballot_recorded",
            operation="consensus",
            candidate_sha256=state["candidate"]["digest"],
        )
        if role in state["ballots"]:
            _fail(f"Duplicate ballot from {role} in cycle {cycle}")
        if payload.get("vote") not in VOTES:
            _fail("Ballot has an invalid vote")
        digest = payload.get("digest")
        if digest != state["candidate"]["digest"]:
            _fail("Ballot does not reference the frozen digest for this cycle")
        rationale = payload.get("rationale")
        if rationale is not None:
            rationale = _text(rationale, "ballot.rationale", minimum=1)
        provenance = _provenance(payload.get("provenance"), "ballot.provenance")
        retry_id = payload.get("retry_id")
        if retry_id is not None:
            pause = _open_pause(state, 3, role)
            if not pause or pause.get("retry_id") != retry_id:
                _fail("Ballot retry ID does not match an open provider pause")
            pause["open"] = False
        state["ballots"][role] = {
            "role": role,
            "vote": payload["vote"],
            "rationale": rationale,
            "digest": digest,
            "provenance": provenance,
            "event_id": event["event_id"],
        }
        return
    if event_type in {"consensus_reached", "consensus_failed"}:
        if event.get("round") != 3:
            _fail("Consensus outcomes must be recorded in round 3")
        roles = _state_roles(state)
        if stage != STAGE_BALLOTS or len(state["ballots"]) != len(roles):
            _fail(
                "Consensus outcome requires all "
                f"{len(roles)} policy ballots in an open round 3"
            )
        _exact_keys(payload, PAYLOAD_KEYS[event_type], f"{event_type} payload")
        if payload.get("digest") != state["candidate"]["digest"]:
            _fail("Consensus outcome references a stale frozen digest")
        tally = _tally(state)
        if payload.get("tally") != tally:
            _fail("Consensus outcome tally does not match the ballots")
        if payload.get("votes") != _votes_in_role_order(state):
            _fail("Consensus outcome votes do not match the ballots")
        unanimous = tally["AGREE"] == len(roles)
        if event_type == "consensus_reached" and not unanimous:
            _fail(
                "Consensus was frozen without all "
                f"{len(roles)} AGREE ballots required by the policy roster"
            )
        if event_type == "consensus_failed":
            if unanimous:
                _fail(
                    "Consensus failure recorded with all "
                    f"{len(roles)} AGREE ballots"
                )
            if payload.get("human_decision_required") is not True:
                _fail("Non-unanimous outcome must request a human decision")
            _text(payload.get("reason"), "consensus_failed.reason", minimum=10)
        state["outcome"] = (
            STAGE_CONSENSUS if event_type == "consensus_reached" else STAGE_HUMAN
        )
        _closed_cycle_record(state, event)
        return
    if event_type == "provider_paused":
        if event.get("round") != round_number or round_number is None:
            _fail("Provider pause does not match the open round")
        if stage not in {STAGE_PROPOSALS, STAGE_CROSS, STAGE_BALLOTS}:
            _fail("Provider pause is not available at this stage")
        _exact_keys(payload, PAYLOAD_KEYS["provider_paused"], "provider_paused payload")
        role = _event_role(state, payload, "Provider pause")
        if _role_submitted(state, stage, role):
            _fail(f"Provider {role} already submitted in this round")
        if _open_pause(state, round_number, role):
            _fail(f"Provider {role} already has an open pause in this round")
        retry_id = payload.get("retry_id")
        if not isinstance(retry_id, str) or not RETRY_ID_RE.fullmatch(retry_id):
            _fail("Provider pause has an invalid retry ID")
        if any(
            pause.get("retry_id") == retry_id for pause in state.get("pauses", [])
        ):
            _fail("Provider pause retry ID is not unique")
        if payload.get("round") != event.get("round"):
            _fail("Provider pause payload round does not match the event round")
        provenance = _provenance(
            payload.get("provenance"), "provider_paused.provenance"
        )
        _text(payload.get("reason"), "provider_paused.reason", minimum=10)
        _text(payload.get("guidance"), "provider_paused.guidance", minimum=10)
        state["pauses"].append(
            {
                "role": role,
                "round": round_number,
                "reason": payload["reason"],
                "guidance": payload["guidance"],
                "provenance": provenance,
                "retry_id": retry_id,
                "open": True,
                "event_id": event["event_id"],
            }
        )
        return
    if event_type == "provider_resumed":
        if stage not in {STAGE_PROPOSALS, STAGE_CROSS, STAGE_BALLOTS}:
            _fail("Provider resume is not available at this stage")
        if event.get("round") != round_number or round_number is None:
            _fail("Provider resume does not match the open round")
        _exact_keys(payload, PAYLOAD_KEYS["provider_resumed"], "provider_resumed payload")
        role = _event_role(state, payload, "Provider resume")
        retry_id = payload.get("retry_id")
        if payload.get("round") != event.get("round"):
            _fail("Provider resume payload round does not match the event round")
        pause = _open_pause(state, round_number, role)
        if not pause or pause.get("retry_id") != retry_id:
            _fail("Provider resume does not match an open pause")
        pause["open"] = False
        return
    _fail(f"Ledger event type {event_type} cannot follow this step state")


def replay_events(path: Path) -> dict[str, Any]:
    """Replay and cryptographically verify the published ledger."""
    plan_id = path.name
    files = _published_event_files(path / "consensus" / "events")
    events: list[dict[str, Any]] = []
    static: dict[str, Any] | None = None
    states: dict[str, dict[str, Any]] = {}
    operation_state: dict[str, Any] = {"seen": set()}
    previous = ZERO_DIGEST
    for index, event_path in enumerate(files, start=1):
        if event_path.name != f"{index:06d}.json":
            _fail(
                f"Ledger filename {event_path.name!r} does not match its ordered "
                f"sequence {index}; published events must be named "
                f"{index:06d}.json"
            )
        event = _read_json(event_path)
        _validate_event_header(
            event, index, plan_id, previous, operation_state
        )
        previous = event["digest"]
        if event["type"] == "plan_enrolled":
            if index != 1 or static is not None:
                _fail("plan_enrolled must be the single first ledger event")
            static = _validate_enrollment_payload(event["payload"], plan_id)
            static["created_at"] = event["at"]
            for step in static["manifest"]["steps"]:
                states[step["id"]] = _new_step_state(
                    step["id"], int(static["policy"]["version"])
                )
        else:
            if static is None:
                _fail("Ledger step event appears before plan enrollment")
            step_id = event["step_id"]
            if step_id not in states:
                _fail(f"Ledger references unknown step {step_id!r}")
            _apply_step_event(states[step_id], event, static)
        events.append(event)
    if files and static is None:  # pragma: no cover - guarded above
        _fail("Ledger has no plan enrollment event")
    return {
        "plan_id": plan_id,
        "static": static,
        "steps": states,
        "events": events,
    }


@contextlib.contextmanager
def _plan_lock(path: Path) -> Iterator[None]:
    consensus = path / "consensus"
    consensus.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _hook("record_lock")(consensus / "ledger"):
        yield


@contextlib.contextmanager
def plan_lock(plan_id: str) -> Iterator[None]:
    """Hold the one existing B1 plan lock for a composite D1 transition.

    D1 uses this exact lock for every relationship check and journal append so
    a B1 cycle change and an execution admission can never interleave. Callers
    must not call another B1 command that re-acquires the same lock while it is
    held; the ``*_locked`` helpers below are the lock-holding surface.
    """
    path = _plan_path(plan_id)
    with _plan_lock(path):
        yield


def replay_plan_state_locked(
    plan_id: str, *, repair: bool = True
) -> dict[str, Any]:
    """Replay a mutable managed plan while the caller holds ``plan_lock``."""
    path = _plan_path(plan_id)
    state = replay_events(path)
    _reject_historical_state(state)
    if repair:
        state = _repair_outcome_locked(path, state)
    return state


def replay_plan_state_unlocked(
    plan_id: str, *, repair: bool = False
) -> dict[str, Any]:
    """Read-only replay for view overlays that already hold the plan lock."""
    path = _plan_path(plan_id)
    state = replay_events(path)
    _reject_historical_state(state)
    if repair:
        state = _repair_outcome_locked(path, state)
    return state


def _operation_events(
    state: dict[str, Any], operation_id: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in state.get("events", [])
        if event["operation_id"] == operation_id
    ]


def _publish_event(path: Path, event: dict[str, Any]) -> None:
    events_dir = path / "consensus" / "events"
    events_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = events_dir / f"{event['sequence']:06d}.json"
    if target.exists():
        _fail(f"Refusing to replace published ledger event {target}")
    temp = events_dir / f".{target.name}.{secrets.token_hex(4)}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(event, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
        _fsync_dir(events_dir)
    finally:
        temp.unlink(missing_ok=True)


def _append_specs(
    path: Path,
    state: dict[str, Any],
    specs: list[dict[str, Any]],
    operation_id: str,
    request_digest: str,
) -> list[dict[str, Any]]:
    existing = _operation_events(state, operation_id)
    if existing:
        if existing[0]["request_digest"] != request_digest:
            _fail(
                f"Operation ID {operation_id} was already used with different content"
            )
        return existing
    sequence = len(state.get("events", [])) + 1
    previous = (
        state["events"][-1]["digest"] if state.get("events") else ZERO_DIGEST
    )
    timestamp = _now()
    # Build and bound every event before publishing any of them, so an
    # oversized submission cannot leave an unreadable published event behind.
    planned: list[dict[str, Any]] = []
    for ordinal, spec in enumerate(specs, start=1):
        event = {
            "sequence": sequence,
            "event_id": f"{operation_id}:{ordinal}",
            "operation_id": operation_id,
            "request_digest": request_digest,
            "type": spec["type"],
            "at": timestamp,
            "plan_id": path.name,
            "step_id": spec.get("step_id"),
            "cycle": spec["cycle"],
            "round": spec.get("round"),
            "payload": spec["payload"],
            "prev_digest": previous,
        }
        event["digest"] = _digest(event)
        if len(_canonical_bytes(event)) > MAX_EVENT_BYTES:
            _fail(
                f"Consensus transition would publish an event above "
                f"{MAX_EVENT_BYTES} bytes; reduce the submitted content"
            )
        planned.append(event)
        sequence += 1
        previous = event["digest"]
    for event in planned:
        _publish_event(path, event)
    return planned


def _operation_id(value: str | None) -> str:
    if value is None:
        return f"op-{time.time_ns()}-{secrets.token_hex(4)}"
    if not isinstance(value, str) or not OP_ID_RE.fullmatch(value):
        _fail(f"Invalid operation ID: {value!r}")
    return value


def _request_digest(command: str, **fields: Any) -> str:
    return _digest({"command": command, **fields})


def _repair_outcome_locked(path: Path, state: dict[str, Any]) -> dict[str, Any]:
    """Publish deterministic outcomes if a crash separated them from the last ballot.

    Historical policy ledgers are never repaired: a read or mutation attempt
    must not add an event to archived evidence.
    """
    if state.get("static") is None:
        return state
    if int(state["static"]["policy"]["version"]) not in MUTABLE_POLICY_VERSIONS:
        return state
    while True:
        repaired = False
        for step_id in [step["id"] for step in state["static"]["manifest"]["steps"]]:
            current = state["steps"][step_id]
            if (
                current.get("candidate")
                and len(current["ballots"]) == len(_state_roles(current))
                and current.get("outcome") is None
            ):
                outcome_type, payload = _outcome_spec(current)
                # Keep the deterministic repair operation ID inside OP_ID_RE even
                # for the longest legal step IDs; the digest binds step and cycle.
                operation_id = f"repair-{current['candidate']['digest'][:32]}"
                spec = {
                    "type": outcome_type,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "round": 3,
                    "payload": payload,
                }
                _append_specs(
                    path,
                    state,
                    [spec],
                    operation_id,
                    _request_digest("repair-outcome", **spec),
                )
                state = replay_events(path)
                repaired = True
                break
        if not repaired:
            return state


def _outcome_spec(state: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    tally = _tally(state)
    votes = _votes_in_role_order(state)
    digest = state["candidate"]["digest"]
    if tally["AGREE"] == len(_state_roles(state)):
        return (
            "consensus_reached",
            {"digest": digest, "tally": tally, "votes": votes},
        )
    parts = ", ".join(f"{vote}={tally[vote]}" for vote in VOTES)
    return (
        "consensus_failed",
        {
            "digest": digest,
            "tally": tally,
            "votes": votes,
            "reason": (
                "Non-unanimous final tally ("
                + parts
                + "); the default three-round budget is exhausted and a human decision is required"
            ),
            "human_decision_required": True,
        },
    )


def _open_pauses_for(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [pause for pause in state.get("pauses", []) if pause.get("open")]


def _step_blocked_reasons(step: dict[str, Any], state: dict[str, Any]) -> list[str]:
    reasons = dependency_blockers(step, state)
    if stage_of(state) == STAGE_CONSENSUS:
        reasons.append(
            "B1 starts no managed writer; the B2 process-lifetime lease and dirty-checkout "
            "gate are still required"
        )
    return reasons


def _step_missing_actions(step: dict[str, Any], state: dict[str, Any]) -> list[str]:
    if dependency_blockers(step):
        return [
            *dependency_blockers(step, state),
            (
                "this step remains DEPENDENCY_BLOCKED until a later slice supplies "
                "independently verified MERGED evidence; B1 cannot mint it"
            ),
        ]
    stage = stage_of(state)
    cycle = state["cycle"]
    actions: list[str] = []
    if stage in {STAGE_PROPOSALS, STAGE_CROSS, STAGE_BALLOTS}:
        round_number = _stage_round(stage) or 1
        role_map = {
            STAGE_PROPOSALS: state["proposals"],
            STAGE_CROSS: state["cross_examinations"],
            STAGE_BALLOTS: state["ballots"],
        }[stage]
        stage_label = {
            STAGE_PROPOSALS: "round 1 proposal",
            STAGE_CROSS: "round 2 cross-examination",
            STAGE_BALLOTS: "round 3 ballot",
        }[stage]
        for role in _state_roles(state):
            if role in role_map:
                continue
            pause = _open_pause(state, round_number, role)
            if pause:
                actions.append(
                    f"resume provider {role} for cycle {cycle} round {round_number} "
                    f"(retry {pause['retry_id']}): {pause['reason']}; "
                    f"operator guidance: {pause['guidance']}"
                )
            elif stage == STAGE_BALLOTS:
                actions.append(
                    f"record {stage_label} from {role} against frozen digest "
                    f"{state['candidate']['digest']}"
                )
            else:
                actions.append(f"record {stage_label} from {role} for cycle {cycle}")
        if not actions:
            actions.append(f"complete round {round_number} for cycle {cycle}")
        return actions
    if stage == STAGE_CANDIDATE:
        count = len(state["objections"])
        actions.append(
            f"freeze the cycle {cycle} candidate with dispositions for {count} numbered "
            "objection(s) using consensus-freeze --candidate-file"
        )
        return actions
    if stage == STAGE_CONSENSUS:
        actions.append(
            "implementation gate awaits B2: B1 freezes consensus but starts no managed "
            "writer and mints no merge evidence"
        )
        actions.append(
            "to amend the settled design, record an explicit human authorization with "
            "consensus-new-cycle; fresh proposals, cross-examinations, a new frozen "
            f"digest and {len(_state_roles(state))} AGREE ballots are still required"
        )
        actions.extend(_step_blocked_reasons(step, state))
        return actions
    if stage == STAGE_HUMAN:
        actions.append(
            f"consensus did not reach {len(_state_roles(state))} AGREE ballots in "
            f"cycle {cycle}; record an explicit human authorization with "
            "consensus-new-cycle --authorized-by and --authorization before any fresh "
            "votes"
        )
        return actions
    return actions


def _step_summary(step: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    stage = effective_stage(step, state)
    missing = _step_missing_actions(step, state)
    candidate = state.get("candidate") or {}
    return {
        "id": step["id"],
        "objective": step["objective"],
        "scope": step["scope"],
        "deliverables": step["deliverables"],
        "acceptance_criteria": step["acceptance_criteria"],
        "depends_on": step["depends_on"],
        "consensus_state": stage,
        "cycle": state["cycle"],
        "round": _stage_round(stage),
        "dependency_blockers": dependency_blockers(step, state),
        "proposal_roles": [
            role for role in _state_roles(state) if role in state["proposals"]
        ],
        "cross_examination_roles": [
            role for role in _state_roles(state) if role in state["cross_examinations"]
        ],
        "objections": state["objections"],
        "frozen_digest": candidate.get("digest"),
        "candidate_binding": candidate.get("binding"),
        "tally": _tally(state) if state["ballots"] else None,
        "votes": _votes_in_role_order(state),
        "open_pauses": _open_pauses_for(state),
        "missing_actions": missing,
        "next_action": missing[0] if missing else None,
        "blocked_reasons": _step_blocked_reasons(step, state),
        "closed_cycles": state["closed_cycles"],
        "freeze_history": state["freeze_history"],
    }


def _execution_overlay(
    state: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the derived D1 execution view for a strict plan.

    The overlay is an existing B1 view extension, not a second source of truth:
    it is recomputed from the execution-fact journal, and a missing, corrupt or
    unsupported journal fails the whole view closed.
    """
    static = state["static"]
    if not _plan_is_strict(static):
        return None
    hook = _HOOKS.get("execution_overlay")
    if hook is None:
        _fail(
            "Strict-execution plan has no execution journal reader; failing closed"
        )
    error_type = _hook("runner_error")
    try:
        overlay = hook(plan_id=static["plan_id"], state=state)
    except error_type:
        raise
    except Exception as exc:
        _fail(f"Strict-execution execution journal is unavailable: {exc}")
    if not isinstance(overlay, dict):
        _fail("Strict-execution execution journal returned an invalid overlay")
    return overlay


def _build_projection(state: dict[str, Any]) -> dict[str, Any]:
    static = state["static"]
    if static is None:
        _fail("Cannot project an empty consensus ledger")
    items: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for step in static["manifest"]["steps"]:
        current = state["steps"][step["id"]]
        stage = effective_stage(step, current)
        item_state = "pending" if stage != STAGE_CONSENSUS else "consensus_reached"
        counts[item_state] = counts.get(item_state, 0) + 1
        items.append(
            {
                "id": step["id"],
                "title": step["objective"],
                "state": item_state,
                "objective": step["objective"],
                "scope": step["scope"],
                "deliverables": step["deliverables"],
                "acceptance_criteria": step["acceptance_criteria"],
                "depends_on": step["depends_on"],
                "job_ids": [],
                "evidence": [],
                "consensus_state": stage,
                "dependency_blocked": stage == STAGE_DEPENDENCY,
                "cycle": current["cycle"],
            }
        )
    goal = dict(static["goal"])
    historical = _historical_state(state)
    goal["status"] = "historical_read_only" if historical else "active"
    overlay = _execution_overlay(state)
    if overlay is not None:
        step_views = overlay.get("steps") if isinstance(overlay.get("steps"), dict) else {}
        for item in items:
            view = step_views.get(item["id"]) if isinstance(step_views, dict) else None
            if isinstance(view, dict):
                item["execution_stage"] = view.get("stage")
                item["execution_next_action"] = view.get("next_action")
                item["execution_source_drift"] = bool(
                    view.get("source_drift")
                )
                item["execution_blocked_reasons"] = list(
                    view.get("blocked_reasons") or []
                )
    result = {
        "plan_id": static["plan_id"],
        "title": static["title"],
        "workspace": static["workspace"],
        "canonical_workspace": static["canonical_workspace"],
        "workspace_project_id": static["workspace_project_id"],
        "created_at": static["created_at"],
        "updated_at": _now(),
        "plan_file": static["plan_file"],
        "plan_sha256": static["plan_sha256"],
        "workspace_mode": static["workspace_mode"],
        "managed": True,
        "policy": static["policy"],
        "policy_status": "HISTORICAL_READ_ONLY" if historical else "ACTIVE",
        "historical_read_only": historical,
        "replacement_guidance": HISTORICAL_V1_GUIDANCE if historical else None,
        "roles": list(POLICY_ROLES[int(static["policy"]["version"])]),
        "team_policy": static["team_policy"],
        "goal": goal,
        "executor_policy": static["executor_policy"],
        "manifest": static["manifest"],
        "manifest_digest": static["manifest_digest"],
        "items": items,
        "counts": counts,
        "complete": False,
    }
    if overlay is not None:
        result["strict_execution"] = True
        result["execution"] = {
            key: overlay.get(key)
            for key in (
                "stage",
                "next_action",
                "blocked_reasons",
                "attempt",
                "source_drift",
                "implementation_gate",
                "closed_gates",
            )
            if key in overlay
        }
    return result


def _build_checkpoint(state: dict[str, Any]) -> dict[str, Any]:
    static = state["static"]
    if static is None:
        _fail("Cannot checkpoint an empty consensus ledger")
    policy_version = int(static["policy"]["version"])
    roles = list(POLICY_ROLES[policy_version])
    historical = policy_version not in MUTABLE_POLICY_VERSIONS
    steps = [
        _step_summary(step, state["steps"][step["id"]])
        for step in static["manifest"]["steps"]
    ]
    aggregate_missing = [
        f"{summary['id']}: {action}"
        for summary in steps
        for action in summary["missing_actions"]
    ]
    human = any(summary["consensus_state"] == STAGE_HUMAN for summary in steps)
    reached = all(
        summary["consensus_state"] == STAGE_CONSENSUS for summary in steps
    )
    if human:
        consensus_state = STAGE_HUMAN
    elif reached:
        consensus_state = STAGE_CONSENSUS
    else:
        consensus_state = "IN_PROGRESS"
    next_step = next(
        (
            summary
            for summary in steps
            if summary["consensus_state"] != STAGE_CONSENSUS
        ),
        None,
    )
    if next_step is None:
        next_item = steps[0] if steps else None
        next_action = (
            "implementation gate awaits B2: CONSENSUS_REACHED, but B1 starts no managed "
            "writer and mints no merge evidence"
        )
    else:
        next_item = next_step
        next_action = next_step["next_action"]
    if historical:
        # A historical ledger is evidence, not a runnable plan. Do not present
        # continuation actions that would require the removed Antigravity slot.
        for summary in steps:
            summary["missing_actions"] = []
            summary["next_action"] = None
            summary["blocked_reasons"] = []
            summary["historical_read_only"] = True
        aggregate_missing = []
        next_item = None
        next_action = HISTORICAL_V1_GUIDANCE
    artifact_names = (
        "proposals.md",
        "discussion-brief.md",
        "discussion-log.md",
        "consensus.md",
    )
    path = _plan_path(static["plan_id"])
    step_artifacts = _step_artifact_paths(path, state)
    for summary in steps:
        summary["artifacts"] = step_artifacts.get(summary["id"])
    projection = _build_projection(state)
    overlay = _execution_overlay(state)
    implementation_gate = "B1_FAIL_CLOSED_AWAITING_B2"
    if overlay is not None:
        step_views = (
            overlay.get("steps") if isinstance(overlay.get("steps"), dict) else {}
        )
        for summary in steps:
            view = step_views.get(summary["id"])
            if not isinstance(view, dict):
                continue
            summary["execution_stage"] = view.get("stage")
            summary["execution_next_action"] = view.get("next_action")
            summary["execution_source_drift"] = bool(view.get("source_drift"))
            summary["execution_missing_actions"] = list(
                view.get("missing_actions") or []
            )
            summary["execution_blocked_reasons"] = list(
                view.get("blocked_reasons") or []
            )
            summary["execution_attempt"] = view.get("attempt")
            summary["formal_repair_budget"] = view.get("formal_repair_budget")
            if summary["consensus_state"] == STAGE_CONSENSUS:
                # The strict-execution continuation surface replaces the
                # historical "B1 starts no writer" text; the overlay is derived
                # from the execution journal and never marks the item done.
                summary["missing_actions"] = list(
                    view.get("missing_actions") or []
                )
                if view.get("next_action"):
                    summary["next_action"] = view["next_action"]
                summary["blocked_reasons"] = list(
                    view.get("blocked_reasons") or []
                )
        aggregate_missing = [
            f"{summary['id']}: {action}"
            for summary in steps
            for action in summary["missing_actions"]
        ]
        if reached and overlay.get("next_action"):
            next_action = str(overlay["next_action"])
        implementation_gate = str(
            overlay.get("implementation_gate") or "D1_MANAGED_EXECUTION"
        )
    result = {
        "plan_id": static["plan_id"],
        "title": static["title"],
        "workspace": static["workspace"],
        "canonical_workspace": static["canonical_workspace"],
        "workspace_project_id": static["workspace_project_id"],
        "managed": True,
        "policy": static["policy"],
        "policy_version": policy_version,
        "policy_status": "HISTORICAL_READ_ONLY" if historical else "ACTIVE",
        "historical_read_only": historical,
        "replacement_guidance": HISTORICAL_V1_GUIDANCE if historical else None,
        "roles": roles,
        "round_budget": DEFAULT_ROUND_BUDGET,
        "goal": {
            **static["goal"],
            "status": "historical_read_only" if historical else "active",
        },
        "complete": False,
        "counts": projection["counts"],
        "consensus_state": consensus_state,
        "implementation_gate": implementation_gate,
        "next_item": next_item,
        "next_action": next_action,
        "steps": steps,
        "missing_actions": aggregate_missing,
        "active_or_unreviewed_jobs": [],
        "pending_feedback": [],
        "usage_summary": None,
        "markdown_artifacts": {
            name: str(path / name) for name in artifact_names
        },
        "step_artifacts": step_artifacts,
        "continuation_contract": (
            (
                HISTORICAL_V1_GUIDANCE
                + " No continuation command is available for this ledger."
            )
            if historical
            else (
                (
                    "Resume from this replayed ledger checkpoint; record only the "
                    "listed missing actions through the public consensus and D1 "
                    "execution commands. D1 stops at IMPLEMENTATION_COMPLETE; review, "
                    "repair, PR/CI/MERGED completion and dependency opening are closed."
                )
                if overlay is not None
                else (
                    "Resume from this replayed ledger checkpoint; record only the "
                    "listed missing actions through the public consensus commands. B1 "
                    "starts no managed writer."
                )
            )
        ),
    }
    if overlay is not None:
        result["strict_execution"] = True
        result["execution"] = {
            key: overlay.get(key)
            for key in (
                "stage",
                "next_action",
                "blocked_reasons",
                "attempt",
                "source_drift",
                "closed_gates",
                "formal_repair_budget",
            )
            if key in overlay
        }
        result["closed_gates"] = overlay.get("closed_gates") or {
            "review_acceptance": "CLOSED_UNTIL_D2",
            "formal_repair": "CLOSED_UNTIL_D2",
            "independent_validation": "CLOSED_UNTIL_D2",
            "pr_ci_merged": "CLOSED_UNTIL_E",
            "dependency_opening": "CLOSED_UNTIL_E",
        }
    return result


def _step_artifact_paths(
    path: Path, state: dict[str, Any]
) -> dict[str, Any]:
    """Describe the deterministic per-step, per-cycle artifact bundle."""
    static = state["static"]
    policy_version = int(static["policy"]["version"])
    artifact_names = step_artifact_names(policy_version)
    historical = policy_version not in MUTABLE_POLICY_VERSIONS
    result: dict[str, Any] = {}
    for step in static["manifest"]["steps"]:
        directory = path / "steps" / step["id"]
        cycles: dict[str, Any] = {}
        for cycle in _cycles_present(state, step["id"]):
            cycle_dir = directory / f"cycle-{cycle}"
            cycles[str(cycle)] = {
                "directory": str(cycle_dir),
                "historical_read_only": historical,
                "regenerated": not historical,
                "files": {
                    name: str(cycle_dir / name) for name in artifact_names
                },
            }
        result[step["id"]] = {
            "directory": str(directory),
            "current_cycle": state["steps"][step["id"]]["cycle"],
            "policy_version": policy_version,
            "historical_read_only": historical,
            "regenerated": not historical,
            "files": {name: str(directory / name) for name in artifact_names},
            "cycles": cycles,
        }
    return result


def _cycles_present(state: dict[str, Any], step_id: str) -> list[int]:
    step_state = state["steps"][step_id]
    cycles = [int(record["cycle"]) for record in step_state.get("history", [])]
    cycles.append(int(step_state.get("cycle", 1)))
    return sorted(set(cycles))


def _md_list(values: list[str]) -> str:
    if not values:
        return "- (none)"
    return "\n".join(f"- {value}" for value in values)


def _role_proposal_block(role: str, record: dict[str, Any]) -> str:
    submission = record["submission"]
    provenance = record["provenance"]
    origin = provenance.get("job_id") or provenance.get("leader") or "unknown"
    return (
        f"## {ROLE_LABELS[role]} (`{role}`)\n\n"
        f"Provenance: `{origin}`\n\n"
        f"**Approach.** {submission['approach']}\n\n"
        f"**Rationale.** {submission['rationale']}\n\n"
        f"**Assumptions.**\n{_md_list(submission['assumptions'])}\n\n"
        f"**Risks.**\n{_md_list(submission['risks'])}\n\n"
        f"**Alternatives.**\n{_md_list(submission['alternatives'])}\n\n"
        f"**Feasibility.** {submission['feasibility']}\n\n"
        f"**Tests.**\n{_md_list(submission['tests'])}\n"
    )


def _render_proposals(state: dict[str, Any]) -> str:
    static = state["static"]
    version = int(static["policy"]["version"])
    roles = POLICY_ROLES[version]
    lines = [
        f"# B1 proposals — {static['title']}",
        "",
        f"Plan: `{static['plan_id']}`",
        f"Workspace: `{static['canonical_workspace']}`",
        f"Policy: `{POLICY_NAME}` version {version}",
        f"Roles: {', '.join(ROLE_LABELS[role] for role in roles)}",
        "",
    ]
    for step in static["manifest"]["steps"]:
        current = state["steps"][step["id"]]
        lines.extend(
            [
                f"# Step `{step['id']}` — cycle {current['cycle']}",
                "",
                step["objective"],
                "",
            ]
        )
        if not current["proposals"]:
            lines.append("_No proposals recorded yet._")
            lines.append("")
            continue
        for role in roles:
            if role in current["proposals"]:
                lines.append(_role_proposal_block(role, current["proposals"][role]))
            else:
                lines.append(f"## {ROLE_LABELS[role]} (`{role}`)")
                lines.append("")
                lines.append("_Not submitted._")
                lines.append("")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_discussion_brief(state: dict[str, Any]) -> str:
    static = state["static"]
    version = int(static["policy"]["version"])
    roles = POLICY_ROLES[version]
    lines = [
        f"# B1 discussion brief — {static['title']}",
        "",
        f"Policy version {version} freezes the fixed roles "
        f"{', '.join(ROLE_LABELS[role] for role in roles)}.",
        f"Every participant receives all {len(roles)} proposals for the current cycle",
        "and the numbered objections raised during round 2. Round 1 requires approach,",
        "rationale, assumptions, risks, alternatives, feasibility, and tests.",
        "Round 2 requires responses, challenges, and revisions from each role.",
        "",
    ]
    for step in static["manifest"]["steps"]:
        current = state["steps"][step["id"]]
        lines.extend(
            [
                f"# Step `{step['id']}` — cycle {current['cycle']}",
                "",
                f"Objective: {step['objective']}",
                f"Scope: {'; '.join(step['scope'])}",
                f"Dependencies: {', '.join(step['depends_on']) or '(none)'}",
                f"Current consensus state: `{effective_stage(step, current)}`",
                "",
                "## Round 1 proposals",
                "",
            ]
        )
        if not current["proposals"]:
            lines.append("_No proposals recorded yet._")
        for role in roles:
            if role not in current["proposals"]:
                lines.append(f"- {ROLE_LABELS[role]}: not submitted")
                continue
            submission = current["proposals"][role]["submission"]
            lines.append(
                f"- **{ROLE_LABELS[role]}**: {submission['approach']} "
                f"(feasibility: {submission['feasibility']})"
            )
        lines.extend(["", "## Numbered objections", ""])
        if not current["objections"]:
            lines.append("_No numbered objections recorded yet._")
        for objection in current["objections"]:
            lines.append(
                f"- `{objection['objection_id']}` "
                f"({ROLE_LABELS.get(objection['role'], objection['role'])}): "
                f"{objection['text']}"
            )
        lines.extend(["", "## Round 2 receipts", ""])
        if not current["cross_examinations"]:
            lines.append("_No cross-examinations recorded yet._")
        for role in roles:
            if role not in current["cross_examinations"]:
                lines.append(f"- {ROLE_LABELS[role]}: not submitted")
                continue
            submission = current["cross_examinations"][role]["submission"]
            lines.append(
                f"- **{ROLE_LABELS[role]}**: {len(submission['revisions'])} revision(s), "
                f"{len(submission['challenges'])} challenge(s)"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _describe_event(event: dict[str, Any]) -> str:
    event_type = event["type"]
    payload = event["payload"]
    role = payload.get("role")
    role_label = ROLE_LABELS.get(role, role or "-")
    if event_type == "plan_enrolled":
        return "plan enrolled in the B1 research policy"
    if event_type == "proposal_recorded":
        return f"{role_label} recorded a round 1 proposal"
    if event_type == "cross_examination_recorded":
        return f"{role_label} recorded a round 2 cross-examination"
    if event_type == "candidate_frozen":
        return f"candidate frozen with digest `{payload.get('digest')}`"
    if event_type == "ballot_recorded":
        return f"{role_label} voted {payload.get('vote')} against `{payload.get('digest')}`"
    if event_type == "consensus_reached":
        count = len(payload.get("votes") or [])
        qualifier = str(count) if count else "Unanimous"
        return f"{qualifier} AGREE ballots frozen as consensus"
    if event_type == "consensus_failed":
        return "non-unanimous final tally; human decision required"
    if event_type == "provider_paused":
        return (
            f"{role_label} paused in round {payload.get('round')} "
            f"(retry `{payload.get('retry_id')}`): {payload.get('reason')}"
        )
    if event_type == "provider_resumed":
        return (
            f"{role_label} resumed round {payload.get('round')} "
            f"(retry `{payload.get('retry_id')}`)"
        )
    if event_type == "new_cycle_authorized":
        return (
            f"human-authorized new cycle {payload.get('new_cycle')} by "
            f"{payload.get('authorization', {}).get('authorized_by')}"
        )
    return event_type


def _render_discussion_log(state: dict[str, Any]) -> str:
    static = state["static"]
    lines = [
        f"# B1 discussion log — {static['title']}",
        "",
        "Chronological replay of the immutable ledger. Temporary or unpublished files are",
        "not evidence and never appear here. Per-step, per-cycle bundles carry the full",
        "payloads under steps/<step-id>/cycle-<n>/DISCUSSION_LOG.md.",
        "",
    ]
    for event in state["events"]:
        step = event.get("step_id") or "plan"
        lines.append(
            f"- `{event['at']}` event {event['sequence']:06d} step `{step}` "
            f"cycle {event['cycle']} round {event.get('round') or '-'}: "
            f"{_describe_event(event)}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _cycle_snapshot(state: dict[str, Any], cycle: int) -> dict[str, Any]:
    for record in state.get("history", []):
        if int(record.get("cycle", 0)) == cycle:
            return record
    candidate = state.get("candidate") or {}
    return {
        "cycle": cycle,
        "outcome": state.get("outcome"),
        "digest": candidate.get("digest"),
        "tally": _tally(state) if state.get("ballots") else None,
        "votes": _votes_in_role_order(state),
        "objections": state.get("objections", []),
        "proposals": state.get("proposals", {}),
        "cross_examinations": state.get("cross_examinations", {}),
        "candidate": state.get("candidate"),
        "ballots": state.get("ballots", {}),
        "pauses": state.get("pauses", []),
        "freeze_history": state.get("freeze_history", []),
        "cycle_opening": state.get("cycle_opening"),
        "closed_at": None,
    }


def _render_step_brief(
    static: dict[str, Any],
    step: dict[str, Any],
    cycle: int,
    opening: dict[str, Any] | None,
) -> str:
    """Render the immutable pre-discussion brief for one step and cycle.

    The coordinator-authored ``brief`` object is reproduced verbatim. The
    content depends only on the manifest, the policy and the cycle opening, so
    it never changes as proposals or ballots arrive and stays byte-identical
    across replay, voting and later cycles.
    """
    brief = step["brief"]
    version = int(static["policy"]["version"])
    roles = POLICY_ROLES[version]
    lines = [
        f"# B1 DISCUSSION BRIEF — step `{step['id']}`, cycle {cycle}",
        "",
        f"Plan: `{static['plan_id']}`",
        f"Policy: `{POLICY_NAME}` version {version}",
        f"Roles: {', '.join(ROLE_LABELS[role] for role in roles)}",
        "",
        "This is the coordinator-authored brief captured at enrollment, before any",
        "proposal was recorded. It is immutable.",
        "",
        "## Original objective",
        "",
        brief["original_objective"],
        "",
        "## Repository context",
        "",
        brief["repository_context"],
        "",
        "## Constraints",
        "",
        _md_list(brief["constraints"]),
        "",
        "## Proposed technical approach",
        "",
        brief["proposed_approach"],
        "",
        "## Expected changes",
        "",
        _md_list(brief["expected_changes"]),
        "",
        "## Acceptance criteria",
        "",
        _md_list(brief["acceptance_criteria"]),
        "",
        "## Manifest step",
        "",
        f"Objective: {step['objective']}",
        "",
        "Scope:",
        "",
        _md_list(step["scope"]),
        "",
        "Deliverables:",
        "",
        _md_list(step["deliverables"]),
        "",
        "Manifest acceptance criteria:",
        "",
        _md_list(step["acceptance_criteria"]),
        "",
        "## Dependency references",
        "",
    ]
    if step["depends_on"]:
        for dependency in step["depends_on"]:
            lines.append(
                f"- `{dependency}` requires independently verified MERGED evidence. "
                "B1 cannot mint this evidence, so the step remains DEPENDENCY_BLOCKED "
                "until a later slice supplies it."
            )
    else:
        lines.append("- (none)")
    lines.extend(
        [
            "",
            "## Protocol",
            "",
            f"1. Round 1: each of the {len(roles)} roles submits one proposal with "
            "approach,",
            "   rationale, assumptions, risks, alternatives, feasibility and tests.",
            f"2. Round 2: every participant receives all {len(roles)} proposals and "
            "records",
            "   responses, challenges and revisions; the runner numbers objections.",
            "3. The moderator freezes exactly one candidate with dispositions for every",
            "   numbered objection and binds its canonical digest to the plan, step,",
            "   dependency references, policy version, role roster, cycle and vote round.",
            "4. Round 3: each role records one explicit AGREE, DISAGREE or",
            f"   NEEDS_DISCUSSION ballot against that digest. Only {len(roles)} AGREE "
            "ballots",
            "   freeze consensus. A missing or invalid response is never assent.",
            "",
            "The default budget is three complete rounds. A non-unanimous tally requires",
            "a recorded human authorization before a fresh cycle can start.",
            "",
            "## Cycle opening",
            "",
        ]
    )
    if opening and opening.get("mode") == "human_authorized":
        lines.extend(
            [
                f"- Opened by human authorization from `{opening.get('authorized_by')}` "
                f"after cycle {opening.get('previous_cycle')} "
                f"(`{opening.get('previous_outcome')}`, digest "
                f"`{opening.get('previous_digest')}`).",
                f"- Authorization: {opening.get('authorization')}",
            ]
        )
    else:
        lines.append(
            f"- Opened by plan enrollment under policy version {version}."
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_proposal_document(
    static: dict[str, Any],
    step: dict[str, Any],
    cycle: int,
    role: str,
    snapshot: dict[str, Any],
) -> str:
    lines = [
        f"# B1 PROPOSAL_{ROLE_LABELS[role].upper()} — step `{step['id']}`, cycle {cycle}",
        "",
        f"Plan: `{static['plan_id']}`",
        f"Policy: `{POLICY_NAME}` version {int(static['policy']['version'])}",
        f"Role: {ROLE_LABELS[role]} (`{role}`)",
        "",
    ]
    record = (snapshot.get("proposals") or {}).get(role)
    if record is None:
        lines.append("_Not submitted in this cycle._")
        return "\n".join(lines).rstrip() + "\n"
    lines.append(_role_proposal_block(role, record).replace(
        f"## {ROLE_LABELS[role]} (`{role}`)\n\n", ""
    ))
    return "\n".join(lines).rstrip() + "\n"


def _render_step_log(
    static: dict[str, Any],
    step: dict[str, Any],
    cycle: int,
    events: list[dict[str, Any]],
) -> str:
    lines = [
        f"# B1 DISCUSSION_LOG — step `{step['id']}`, cycle {cycle}",
        "",
        f"Plan: `{static['plan_id']}`",
        "Chronological replay of the immutable ledger for this step and cycle.",
        "Temporary or unpublished files are not evidence and never appear here.",
        "",
    ]
    if not events:
        lines.append("_No events recorded in this cycle._")
        return "\n".join(lines).rstrip() + "\n"
    for event in events:
        lines.extend(
            [
                f"## Event {event['sequence']:06d} — `{event['type']}`",
                "",
                f"- At: `{event['at']}`",
                f"- Event ID: `{event['event_id']}`",
                f"- Operation ID: `{event['operation_id']}`",
                f"- Round: {event.get('round') if event.get('round') else '-'}",
                "",
                "```json",
                json.dumps(event["payload"], indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _ballot_lines(
    snapshot: dict[str, Any], roles: tuple[str, ...] | list[str]
) -> list[str]:
    ballots = snapshot.get("ballots") or {}
    lines: list[str] = []
    for role in roles:
        ballot = ballots.get(role)
        if ballot is None:
            lines.append(f"- {ROLE_LABELS[role]}: not recorded")
            continue
        provenance = ballot.get("provenance") or {}
        origin = provenance.get("job_id") or provenance.get("leader") or "unknown"
        rationale = ballot.get("rationale") or "(no rationale recorded)"
        lines.append(
            f"- {ROLE_LABELS[role]}: **{ballot['vote']}** against "
            f"`{ballot.get('digest')}`; provenance `{origin}`; rationale: {rationale}"
        )
    return lines


def _execution_constraints_lines(
    document: dict[str, Any],
) -> list[str]:
    """Render approved version 1 execution constraints, when present.

    Historical candidates omit the field and therefore render exactly their
    original bytes.
    """
    constraints = document.get("execution_constraints")
    if constraints is None:
        return []
    if not isinstance(constraints, dict):
        return ["- (invalid execution constraints)"]
    lines = [
        "### Execution constraints (version 1)",
        "",
        "Allowed repository-relative patterns (exact approved globs):",
        "",
        _md_list(list(constraints.get("allowed_paths") or [])),
        "",
        "Denied repository-relative patterns:",
        "",
        _md_list(list(constraints.get("denied_paths") or [])),
        "",
        "Stable acceptance criteria IDs and text digests:",
        "",
        _md_list(
            [
                f"`{item['id']}` — `{item['text_sha256']}`"
                for item in constraints.get("criteria") or []
            ]
        ),
        "",
        "Required literal validation argv:",
        "",
        _md_list(
            [
                "`" + json.dumps(item.get("argv"), ensure_ascii=False) + "`"
                for item in constraints.get("required_validation") or []
            ]
        ),
        "",
        "Maximum changed files: "
        + (
            str(constraints.get("max_changed_files"))
            if constraints.get("max_changed_files") is not None
            else "(none declared)"
        ),
        "",
    ]
    return lines


def _render_step_consensus(
    static: dict[str, Any],
    step: dict[str, Any],
    cycle: int,
    snapshot: dict[str, Any],
    live_state: dict[str, Any] | None,
) -> str:
    version = int(static["policy"]["version"])
    roles = POLICY_ROLES[version]
    lines = [
        f"# B1 CONSENSUS — step `{step['id']}`, cycle {cycle}",
        "",
        f"Plan: `{static['plan_id']}`",
        f"Policy: `{POLICY_NAME}` version {version}",
        f"Roles: {', '.join(ROLE_LABELS[role] for role in roles)}",
        f"Round budget: {DEFAULT_ROUND_BUDGET} complete protocol rounds",
        f"Outcome: `{snapshot.get('outcome') or 'PENDING'}`",
        f"Frozen digest: `{snapshot.get('digest')}`",
        "",
    ]
    opening = snapshot.get("cycle_opening") or {}
    if opening.get("mode") == "human_authorized":
        lines.extend(
            [
                "## Human authorization",
                "",
                f"- Authorized by: {opening.get('authorized_by')}",
                f"- Authorization: {opening.get('authorization')}",
                f"- Previous cycle: {opening.get('previous_cycle')} "
                f"(`{opening.get('previous_outcome')}`, digest "
                f"`{opening.get('previous_digest')}`)",
                "",
            ]
        )
    candidate = snapshot.get("candidate") or {}
    if candidate:
        document = candidate.get("candidate") or {}
        lines.extend(
            [
                "## Frozen candidate",
                "",
                f"Frozen digest: `{candidate.get('digest')}`",
                "",
                "Binding:",
                "",
                "```json",
                json.dumps(candidate.get("binding"), indent=2, sort_keys=True),
                "```",
                "",
                "### Final design",
                "",
                document.get("final_design", ""),
                "",
                "### Important decisions",
                "",
                _md_list(document.get("important_decisions", [])),
                "",
                *_execution_constraints_lines(document),
                "### Rejected alternatives and reasons",
                "",
                _md_list(
                    [
                        f"{item['alternative']} — {item['reason']}"
                        for item in document.get("rejected_alternatives", [])
                    ]
                ),
                "",
                "### Objection dispositions",
                "",
                _md_list(
                    [
                        f"`{item['objection_id']}` {item['disposition']} — "
                        f"{item['reason']}"
                        for item in document.get("objection_dispositions", [])
                    ]
                ),
                "",
                "### Remaining risks",
                "",
                _md_list(document.get("remaining_risks", [])),
                "",
            ]
        )
    objections = snapshot.get("objections") or []
    lines.extend(["## Numbered objections", ""])
    if not objections:
        lines.append("- (none)")
    for item in objections:
        lines.append(f"- `{item['objection_id']}` ({item.get('role') or 'unknown'}): {item['text']}")
    lines.extend(["", "## Ballots", ""])
    lines.extend(_ballot_lines(snapshot, roles))
    lines.extend(["", "## Pauses", ""])
    pauses = snapshot.get("pauses") or []
    if not pauses:
        lines.append("- (none)")
    for pause in pauses:
        provenance = pause.get("provenance") or {}
        origin = provenance.get("job_id") or provenance.get("leader") or "unknown"
        lines.append(
            f"- Round {pause.get('round')} {pause.get('role')}: {pause.get('reason')} "
            f"(guidance: {pause.get('guidance')}; retry `{pause.get('retry_id')}`; "
            f"provenance `{origin}`; open: {pause.get('open')})"
        )
    lines.append("")
    outcome = snapshot.get("outcome")
    if outcome == STAGE_CONSENSUS:
        lines.extend(
            [
                "## Final consensus",
                "",
                f"All {len(roles)} roles explicitly AGREE against the frozen digest.",
                "",
                *(
                    [
                        "This strict-execution plan may now freeze the separately "
                        "bound implementation contract and admit one reserved "
                        "deepseek writer through D1. Review acceptance, repairs, "
                        "PR/CI/MERGED completion and dependency opening remain "
                        "closed.",
                    ]
                    if _plan_is_strict(static)
                    else [
                        # Historical non-strict rendering is byte-compatible:
                        # these are the original three implementation-gate lines.
                        "B1 reports CONSENSUS_REACHED and starts no managed writer. Verified",
                        "MERGED dependency evidence and the B2 implementation lease are still",
                        "required before implementation.",
                    ]
                ),
                "",
            ]
        )
    elif outcome == STAGE_HUMAN:
        lines.extend(
            [
                "## No consensus",
                "",
                f"The final tally was not {len(roles)} AGREE. The settled design cannot be",
                "overridden by a legacy path or by reusing the same digest. A recorded",
                "human authorization is required to open a new cycle with fresh",
                "discussion and votes.",
                "",
                "Final tally:",
                "",
                "```json",
                json.dumps(snapshot.get("tally"), indent=2, sort_keys=True),
                "```",
                "",
            ]
        )
    elif live_state is not None:
        lines.extend(
            [
                "## Consensus pending",
                "",
                f"Current state: `{effective_stage(step, live_state)}`",
                "",
                "Missing actions:",
                "",
                _md_list(_step_missing_actions(step, live_state)),
                "",
            ]
        )
    reopened = snapshot.get("reopening_authorization")
    if reopened:
        lines.extend(
            [
                "## Reopened by human authorization",
                "",
                f"- Authorized by: {reopened.get('authorized_by')}",
                f"- Authorization: {reopened.get('text')}",
                f"- Reopened as cycle: {snapshot.get('reopened_as_cycle')}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_consensus(state: dict[str, Any]) -> str:
    static = state["static"]
    version = int(static["policy"]["version"])
    roles = POLICY_ROLES[version]
    lines = [
        f"# B1 consensus — {static['title']}",
        "",
        f"Plan: `{static['plan_id']}`",
        f"Policy: `{POLICY_NAME}` version {version}",
        f"Roles: {', '.join(ROLE_LABELS[role] for role in roles)}",
        f"Round budget: {DEFAULT_ROUND_BUDGET} complete protocol rounds "
        "(proposals, cross-examination, ballots)",
        "",
        "Per-step, per-cycle bundles with the complete evidence live under",
        "steps/<step-id>/cycle-<n>/CONSENSUS.md.",
        "",
    ]
    for step in static["manifest"]["steps"]:
        current = state["steps"][step["id"]]
        stage = effective_stage(step, current)
        lines.extend(
            [
                f"# Step `{step['id']}`",
                "",
                f"Objective: {step['objective']}",
                f"Consensus state: `{stage}`",
                f"Cycle: {current['cycle']}",
                "",
            ]
        )
        snapshot = _cycle_snapshot(current, current["cycle"])
        candidate = snapshot.get("candidate") or {}
        if stage == STAGE_DEPENDENCY:
            lines.extend(
                [
                    "## Dependency blocked",
                    "",
                    _md_list(dependency_blockers(step, current)),
                    "",
                ]
            )
        elif stage == STAGE_CONSENSUS and candidate:
            lines.extend(
                [
                    "## Final consensus",
                    "",
                    f"All {len(roles)} roles explicitly AGREE against the frozen "
                    "digest.",
                    "",
                    f"Frozen digest: `{candidate['digest']}`",
                    "",
                    "Binding:",
                    "",
                    "```json",
                    json.dumps(candidate["binding"], indent=2, sort_keys=True),
                    "```",
                    "",
                    "## Final design",
                    "",
                    candidate["candidate"]["final_design"],
                    "",
                    "## Important decisions",
                    "",
                    _md_list(candidate["candidate"]["important_decisions"]),
                    "",
                    *_execution_constraints_lines(candidate["candidate"]),
                    "## Rejected alternatives and reasons",
                    "",
                    _md_list(
                        [
                            f"{item['alternative']} — {item['reason']}"
                            for item in candidate["candidate"]["rejected_alternatives"]
                        ]
                    ),
                    "",
                    "## Objection dispositions",
                    "",
                    _md_list(
                        [
                            f"`{item['objection_id']}` {item['disposition']} — "
                            f"{item['reason']}"
                            for item in candidate["candidate"]["objection_dispositions"]
                        ]
                    ),
                    "",
                    "## Remaining risks",
                    "",
                    _md_list(candidate["candidate"]["remaining_risks"]),
                    "",
                    "## Ballots",
                    "",
                    _md_list(_ballot_lines(snapshot, roles)),
                    "",
                    "## Implementation gate",
                    "",
                    *(
                        [
                            "Strict execution is enabled: freeze the separate "
                            "execution contract and admit one reserved deepseek "
                            "writer through D1. Review acceptance, repairs, "
                            "PR/CI/MERGED completion and dependency opening remain "
                            "closed.",
                        ]
                        if _plan_is_strict(static)
                        else [
                            # Historical non-strict rendering is byte-compatible:
                            # these are the original three implementation-gate lines.
                            "B1 reports CONSENSUS_REACHED and starts no managed writer. Verified",
                            "MERGED dependency evidence and the B2 implementation lease are still",
                            "required before implementation.",
                        ]
                    ),
                    "",
                ]
            )
        elif stage == STAGE_HUMAN:
            lines.extend(
                [
                    "## No consensus",
                    "",
                    f"The final tally was not {len(roles)} AGREE. The settled design "
                    "cannot be",
                    "overridden by a legacy path or by reusing the same digest. A recorded",
                    "human authorization is required to open a new cycle with fresh",
                    "discussion and votes.",
                    "",
                    "Final tally:",
                    "",
                    "```json",
                    json.dumps(snapshot.get("tally"), indent=2, sort_keys=True),
                    "```",
                    "",
                    "Frozen digest:",
                    "",
                    f"`{snapshot.get('digest')}`",
                    "",
                    "Rejected candidate design:",
                    "",
                    (candidate.get("candidate") or {}).get("final_design", "(not recorded)"),
                    "",
                    "Votes:",
                    "",
                    _md_list(_ballot_lines(snapshot, roles)),
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "## Consensus pending",
                    "",
                    f"Current stage: `{stage}`",
                    "",
                    "Missing actions:",
                    "",
                    _md_list(_step_missing_actions(step, current)),
                    "",
                    "## Votes recorded so far",
                    "",
                    _md_list(_ballot_lines(snapshot, roles)),
                    "",
                ]
            )
        if current["closed_cycles"]:
            lines.extend(["## Preserved earlier cycles", ""])
            for record in current["closed_cycles"]:
                lines.append(
                    f"- Cycle {record['cycle']}: `{record['outcome']}` with digest "
                    f"`{record['digest']}`; tally "
                    f"{json.dumps(record['tally'], sort_keys=True)}"
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write_step_bundle(
    directory: Path,
    static: dict[str, Any],
    step: dict[str, Any],
    cycle: int,
    snapshot: dict[str, Any],
    events: list[dict[str, Any]],
    live_state: dict[str, Any] | None,
) -> None:
    opening = snapshot.get("cycle_opening")
    version = int(static["policy"]["version"])
    files = {
        ARTIFACT_BRIEF: _render_step_brief(static, step, cycle, opening),
        ARTIFACT_LOG: _render_step_log(static, step, cycle, events),
        ARTIFACT_CONSENSUS: _render_step_consensus(
            static, step, cycle, snapshot, live_state
        ),
    }
    for role in POLICY_ROLES[version]:
        files[ARTIFACT_PROPOSALS[role]] = _render_proposal_document(
            static, step, cycle, role, snapshot
        )
    for name, text in files.items():
        _write_text_atomic(directory / name, text)


def _regenerate_locked(path: Path, state: dict[str, Any]) -> dict[str, Any]:
    projection = _build_projection(state)
    checkpoint = _build_checkpoint(state)
    _write_json_atomic(path / "plan.json", projection)
    _write_json_atomic(path / "checkpoint.json", checkpoint)
    static = state["static"]
    _write_text_atomic(
        path / "manifest.json",
        json.dumps(
            {
                "manifest": static["manifest"],
                "manifest_digest": static["manifest_digest"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    _write_text_atomic(path / "proposals.md", _render_proposals(state))
    _write_text_atomic(path / "discussion-brief.md", _render_discussion_brief(state))
    _write_text_atomic(path / "discussion-log.md", _render_discussion_log(state))
    _write_text_atomic(path / "consensus.md", _render_consensus(state))
    # Deterministic per-step, per-cycle evidence bundles. Regeneration is
    # idempotent; the immutable ledger remains the only authority.
    for step in static["manifest"]["steps"]:
        step_state = state["steps"][step["id"]]
        directory = path / "steps" / step["id"]
        current_cycle = int(step_state["cycle"])
        for cycle in _cycles_present(state, step["id"]):
            snapshot = _cycle_snapshot(step_state, cycle)
            events = [
                event
                for event in state["events"]
                if event.get("step_id") == step["id"]
                and int(event["cycle"]) == cycle
            ]
            live_state = step_state if cycle == current_cycle else None
            cycle_dir = directory / f"cycle-{cycle}"
            _write_step_bundle(
                cycle_dir, static, step, cycle, snapshot, events, live_state
            )
            if cycle == current_cycle:
                _write_step_bundle(
                    directory, static, step, cycle, snapshot, events, live_state
                )
    return {"plan": projection, "checkpoint": checkpoint, "state": state}


def _ledger_policy_version(path: Path) -> Any:
    """Read the explicit policy version from the immutable enrollment event.

    This is a read-only peek used to keep historical policy reads entirely
    in-memory. Replay remains the authority and rejects unknown versions; if
    the event cannot answer the question the caller falls through to the normal
    locked replay path.
    """
    files = _published_event_files(path / "consensus" / "events")
    if not files:
        return None
    first = _read_json(files[0])
    payload = first.get("payload")
    if not isinstance(payload, dict):
        return None
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        return None
    return policy.get("version")


def load_managed_plan(
    plan_id: str, regenerate: bool = True
) -> dict[str, Any] | None:
    """Return computed views for a managed plan, or None for a legacy plan.

    Historical policy version 1 ledgers are replayed exactly as recorded and
    return computed views without taking a plan lock, writing projections, or
    regenerating artifacts. Their original files and bytes are evidence.
    """
    path = _plan_path(plan_id)
    events_dir = path / "consensus" / "events"
    if _has_published_events(events_dir):
        if _ledger_policy_version(path) == HISTORICAL_POLICY_VERSION:
            state = replay_events(path)
            return {
                "plan": _build_projection(state),
                "checkpoint": _build_checkpoint(state),
                "state": state,
            }
        with _plan_lock(path):
            state = replay_events(path)
            _reject_historical_state(state)
            state = _repair_outcome_locked(path, state)
            if regenerate:
                return _regenerate_locked(path, state)
            return {
                "plan": _build_projection(state),
                "checkpoint": _build_checkpoint(state),
                "state": state,
            }
    plan_path = path / "plan.json"
    if plan_path.is_file():
        plan = _read_json(plan_path)
        if plan.get("managed"):
            _fail(
                f"Managed plan {plan_id} has no published consensus ledger events; "
                "the enrollment event is missing"
            )
    return None


def _manifest_step_for(state: dict[str, Any], step_id: str) -> dict[str, Any]:
    static = state.get("static")
    if static is None:
        _fail("Managed plan has no enrollment event")
    return _manifest_step(static, step_id)


def _require_step_state(
    state: dict[str, Any], step_id: str
) -> dict[str, Any]:
    if not isinstance(step_id, str) or not ID_RE.fullmatch(step_id):
        _fail(f"Invalid step ID: {step_id!r}")
    if step_id not in state["steps"]:
        _fail(f"Unknown step ID {step_id!r} in this plan")
    return state["steps"][step_id]


def _stage_error(stage: str, expected: str) -> None:
    _fail(
        f"This action is unavailable at stage {stage}; expected {expected}. "
        "Consensus commands must follow round 1 proposals, round 2 cross-examination, "
        "one frozen candidate, then round 3 ballots"
    )


def _result(
    state: dict[str, Any],
    step_id: str,
    operation_id: str,
    events: list[dict[str, Any]],
    idempotent: bool,
) -> dict[str, Any]:
    current = state["steps"][step_id]
    summary = _step_summary(_manifest_step_for(state, step_id), current)
    return {
        "plan_id": state["plan_id"],
        "step_id": step_id,
        "cycle": current["cycle"],
        "round": _stage_round(stage_of(current)),
        "stage": stage_of(current),
        "operation_id": operation_id,
        "event_ids": [event["event_id"] for event in events],
        "idempotent": idempotent,
        "objections": current["objections"],
        "frozen_digest": (current.get("candidate") or {}).get("digest"),
        "tally": _tally(current) if current["ballots"] else None,
        "missing_actions": summary["missing_actions"],
        "next_action": summary["next_action"],
    }


def _execute(
    plan_id: str,
    step_id: str,
    operation_id: str | None,
    request_digest: str,
    builder: Any,
) -> dict[str, Any]:
    path = _plan_path(plan_id)
    if not plan_is_managed(plan_id):
        _fail(f"Plan {plan_id} is not a managed B1 research plan")
    selected_operation = _operation_id(operation_id)
    with _plan_lock(path):
        state = replay_events(path)
        # Historical policy ledgers are immutable evidence. Reject every
        # mutation before repair, builder or publication so no event is added
        # and no removed provider can be launched.
        _reject_historical_state(state)
        state = _repair_outcome_locked(path, state)
        current = _require_step_state(state, step_id)
        step = _manifest_step_for(state, step_id)
        blockers = dependency_blockers(step, current)
        if blockers:
            _fail(
                f"Step {step_id} is DEPENDENCY_BLOCKED: " + "; ".join(blockers)
            )
        existing = _operation_events(state, selected_operation)
        if existing:
            if existing[0]["request_digest"] != request_digest:
                _fail(
                    f"Operation ID {selected_operation} was already used with different "
                    "content"
                )
            views = _regenerate_locked(path, state)
            return {
                "state": views["state"],
                "events": existing,
                "idempotent": True,
                "plan": views["plan"],
                "checkpoint": views["checkpoint"],
                "step_id": existing[0]["step_id"],
            }
        specs = builder(state)
        published = _append_specs(
            path, state, specs, selected_operation, request_digest
        )
        state = replay_events(path)
        state = _repair_outcome_locked(path, state)
        views = _regenerate_locked(path, state)
        return {
            "state": views["state"],
            "events": published,
            "idempotent": False,
            "plan": views["plan"],
            "checkpoint": views["checkpoint"],
            "step_id": specs[0]["step_id"],
        }


def _stable_enrollment_policy(value: Any) -> Any:
    """Drop clock fields so an exact retry keeps the same idempotency digest."""
    if isinstance(value, dict):
        return {
            key: _stable_enrollment_policy(child)
            for key, child in value.items()
            if key not in {"updated_at", "created_at", "generated_at"}
        }
    if isinstance(value, list):
        return [_stable_enrollment_policy(child) for child in value]
    return value


def create_managed_plan(
    *,
    plan_id: str,
    title: str,
    workspace: Path,
    plan_file: Path,
    plan_sha256: str,
    workspace_mode: str,
    goal: dict[str, Any],
    team_policy: dict[str, Any],
    executor_policy: dict[str, Any],
    manifest_raw: Any,
    policy_version: int,
    strict_execution: bool = False,
) -> dict[str, Any]:
    """Validate, enroll, and create a managed research plan.

    Enrollment publishes its first durable event inside a private staging
    directory and atomically renames that directory into place. A repository
    level intent record (inside the Git common directory, shared by every
    supported state home) makes the pre-first-event interval recoverable. The
    intent names the owning state home and the normalized request digest, so an
    interrupted attempt is only reconciled by the state home that started it
    and only with identical content; every other retry fails closed with a
    precise recovery location. Deterministic in-process failures before
    publication clean their own staging directory and intent, while a genuine
    interruption leaves the intent for recovery. A live job admitted through
    any state home is visible as a repository-local reservation and blocks
    enrollment until its processes exit.
    """
    if not isinstance(plan_id, str) or not ID_RE.fullmatch(plan_id):
        _fail(f"Invalid plan ID: {plan_id!r}")
    if not isinstance(strict_execution, bool):
        _fail("strict_execution must be a boolean")
    title = _text(title, "title", minimum=2)
    if not isinstance(policy_version, int) or isinstance(policy_version, bool):
        _fail("policy-version must be an integer")
    if policy_version not in SUPPORTED_POLICY_VERSIONS:
        _fail(
            f"Unknown research policy version {policy_version}; supported versions: "
            + ", ".join(str(item) for item in SUPPORTED_POLICY_VERSIONS)
        )
    if policy_version not in MUTABLE_POLICY_VERSIONS:
        _fail(HISTORICAL_V1_GUIDANCE)
    manifest, manifest_digest = validate_manifest(manifest_raw)
    if manifest["policy_version"] != policy_version:
        _fail(
            f"Manifest policy_version {manifest['policy_version']} does not match "
            f"--policy-version {policy_version}"
        )
    if workspace_mode != "project":
        _fail(
            "Research-team plans require project workspace mode; run "
            "preferences --workspace-mode project first"
        )
    identity = _canonical(workspace)
    if not identity.get("is_git"):
        _fail(
            f"Research-team plans require a canonical Git workspace identity; "
            f"{identity.get('workspace') or workspace} is not a Git work tree"
        )
    if not identity.get("is_work_tree"):
        # A Git administrative directory (``<repo>/.git`` and its children) and
        # a bare repository still resolve to a protected canonical identity for
        # admission, but they cannot host a research-team plan checkout.
        _fail(
            "Research-team plans require a Git work tree; "
            f"{identity.get('workspace') or workspace} is a Git administrative "
            "directory or bare repository"
        )
    if not plan_file.is_file():
        _fail(f"Plan file does not exist: {plan_file}")
    try:
        actual_plan_digest = hashlib.sha256(plan_file.read_bytes()).hexdigest()
    except OSError as exc:
        _fail(f"Cannot read plan file {plan_file}: {exc}")
    if actual_plan_digest != plan_sha256:
        _fail("plan_sha256 does not match the plan file content")
    path = _plan_path(plan_id)
    for value, label in (
        (goal, "goal"),
        (team_policy, "team_policy"),
        (executor_policy, "executor_policy"),
    ):
        if not isinstance(value, dict):
            _fail(f"{label} must be a JSON object")
    # Timestamps are deliberately excluded so an exact retry after a lost
    # response is idempotent, while every stable user-supplied policy choice is
    # bound to the enrollment identity and conflicting retries fail closed.
    # Legacy enrollment keeps its exact historical request digest; the strict
    # field participates only when explicitly true.
    enrollment_identity = {
        "plan_id": plan_id,
        "canonical_workspace": identity["root"],
        "title": title,
        "workspace_mode": "project",
        "plan_sha256": plan_sha256,
        "manifest_digest": manifest_digest,
        "policy_version": policy_version,
        "goal": {
            "objective": goal.get("objective"),
            "strategy": goal.get("strategy"),
            "risk": goal.get("risk"),
            "task_type": goal.get("task_type"),
        },
        "team_policy": _stable_enrollment_policy(team_policy),
        "executor_policy": _stable_enrollment_policy(executor_policy),
    }
    if strict_execution:
        enrollment_identity[STRICT_EXECUTION_KEY] = True
    request_digest = _request_digest(
        "create-managed-plan", **enrollment_identity
    )
    # Plan IDs may be 64 characters; leave room for the operation prefix.
    operation_id = f"enroll-{plan_id[:57]}"
    staging: Path | None = None
    with _admission_locks(identity):
        registry = _read_registry()
        intent = _read_intent(identity)
        if intent is not None and intent["plan_id"] != plan_id:
            _fail(
                f"Workspace {identity['root']} has an incomplete enrollment for plan "
                f"{intent['plan_id']} owned by state home {intent['plans_dir']}; "
                f"inspect {_intent_path(identity)} before enrolling {plan_id}"
            )
        if intent is not None:
            _intent_owner_guard(identity, intent, request_digest)
        entry = _workspace_entries(identity)
        if entry and entry.get("plan_id") != plan_id:
            _fail(
                f"Workspace {identity['root']} is already enrolled in managed plan "
                f"{entry['plan_id']}"
            )
        managed = _managed_plan_for_identity(identity["root"])
        if managed and managed != plan_id:
            _fail(
                f"Workspace {identity['root']} already belongs to managed plan {managed}"
            )
        if path.exists():
            # An exact retry after a crash or a lost response reuses the published
            # enrollment event. Anything else fails closed: a published plan
            # directory is authoritative and is never removed by cleanup.
            if not plan_is_managed(plan_id):
                _fail(f"Plan already exists: {plan_id}")
            with _plan_lock(path):
                state = replay_events(path)
                # Remove staging scaffolding left by an older interrupted
                # attempt that published it together with the plan.
                (path / STAGING_MARKER).unlink(missing_ok=True)
                events = state["events"]
                if (
                    not events
                    or events[0]["type"] != "plan_enrolled"
                    or events[0]["operation_id"] != operation_id
                    or events[0]["request_digest"] != request_digest
                ):
                    _fail(
                        f"Plan {plan_id} already exists with different enrollment content"
                    )
                static = state["static"]
                if (
                    static["plan_sha256"] != plan_sha256
                    or static["manifest_digest"] != manifest_digest
                    or static["canonical_workspace"] != identity["root"]
                    or _plan_is_strict(static) != strict_execution
                ):
                    _fail(
                        f"Plan {plan_id} already exists with different enrollment content"
                    )
                views = _regenerate_locked(path, state)
            _write_repo_marker(identity, plan_id)
            if identity["root"] not in registry["workspaces"]:
                registry["workspaces"][identity["root"]] = {
                    "plan_id": plan_id,
                    "canonical_workspace": identity["root"],
                    "workspace_project_id": identity["project_id"],
                    "policy_version": policy_version,
                    "enrolled_at": static["created_at"],
                }
                _write_registry(registry)
            _clear_intent(identity)
            return {**views, "idempotent": True}
        if entry:
            owner = entry.get("plans_dir") or "the state home that owns that plan"
            _fail(
                f"Workspace {identity['root']} is already enrolled in managed plan "
                f"{entry['plan_id']}, but its plan directory is missing here; retry "
                f"from {owner}"
            )
        if managed:
            _fail(
                f"Workspace {identity['root']} already belongs to managed plan {managed}"
            )
        # A launch admitted through any supported state home leaves a
        # repository-local reservation, so enrollment cannot start a second
        # writer in this checkout while that process is alive.
        state_home_jobs = _hook("active_jobs_for_identity")(identity["root"])
        active = _active_jobs_with_reservations(identity, state_home_jobs)
        if active:
            _fail(
                "Cannot enroll over an active job in "
                f"{identity['root']}: {', '.join(active)}. Wait for or cancel it first"
            )
        lease_blocker = _lease_blocker(identity)
        if lease_blocker:
            _fail(lease_blocker)
        # Reconcile an interrupted earlier attempt for this same plan under the
        # repository lock. Only the intent's own staging directory, with the
        # marker or the exact known pre-publication layout, is removed;
        # unrelated state is never touched.
        if intent is not None:
            _cleanup_staging(identity, intent)
            _clear_intent(identity)
        _prune_orphan_staging(identity, plan_id)
        while True:
            token = secrets.token_hex(4)
            staging_parent = _plans_root() / f"{STAGING_PREFIX}{plan_id}-{token}"
            if not staging_parent.exists():
                break
        staging = staging_parent / plan_id
        staging_relative = f"{staging_parent.name}/{plan_id}"
        _write_intent(identity, plan_id, staging_relative, request_digest)
        try:
            staging.mkdir(parents=True, mode=0o700)
            _fsync_dir(staging_parent)
            _write_json_atomic(
                staging / STAGING_MARKER,
                {
                    "plan_id": plan_id,
                    "canonical_workspace": identity["root"],
                    "created_at": _now(),
                },
            )
            destination = staging / "plan.md"
            shutil.copyfile(plan_file, destination)
            os.chmod(destination, 0o600)
            with destination.open("rb") as handle:
                os.fsync(handle.fileno())
            _fsync_dir(staging)
            if hashlib.sha256(destination.read_bytes()).hexdigest() != plan_sha256:
                _fail("Plan file changed while the managed plan was being created")
            _write_text_atomic(
                staging / "manifest.json",
                json.dumps(
                    {"manifest": manifest, "manifest_digest": manifest_digest},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
            )
            payload = {
                "workspace": identity["root"],
                "canonical_workspace": identity["root"],
                "workspace_project_id": identity["project_id"],
                "title": title,
                "workspace_mode": "project",
                "plan_file": str(path / "plan.md"),
                "plan_sha256": plan_sha256,
                "policy": {"name": POLICY_NAME, "version": policy_version},
                "roles": list(POLICY_ROLES[policy_version]),
                "round_budget": DEFAULT_ROUND_BUDGET,
                "manifest": manifest,
                "manifest_digest": manifest_digest,
                "goal": goal,
                "team_policy": team_policy,
                "executor_policy": executor_policy,
            }
            if strict_execution:
                payload[STRICT_EXECUTION_KEY] = True
            with _plan_lock(staging):
                _append_specs(
                    staging,
                    {"events": []},
                    [
                        {
                            "type": "plan_enrolled",
                            "step_id": None,
                            "cycle": 1,
                            "round": None,
                            "payload": payload,
                        }
                    ],
                    operation_id,
                    request_digest,
                )
            # Replay the staged ledger before publication. A normalized
            # manifest that cannot be replayed must never become a published
            # plan, otherwise the plan directory would block every retry.
            replay_events(staging)
            # The staging marker is unpublished scaffolding, not part of the
            # plan. Remove it while the directory is still private so a
            # published plan never contains it.
            (staging / STAGING_MARKER).unlink()
            _fsync_dir(staging)
            # Atomic first-event publication: the final plan directory only
            # appears together with its durable enrollment event.
            os.replace(staging, path)
            _fsync_dir(path.parent)
            staging = None
            with contextlib.suppress(OSError):
                staging_parent.rmdir()
            # A concurrent consensus command may observe the published plan as
            # soon as the rename completes. Regenerate its projections under the
            # same plan lock so those commands cannot interleave a stale view.
            with _plan_lock(path):
                state = replay_events(path)
                views = _regenerate_locked(path, state)
            _write_repo_marker(identity, plan_id)
            registry["workspaces"][identity["root"]] = {
                "plan_id": plan_id,
                "canonical_workspace": identity["root"],
                "workspace_project_id": identity["project_id"],
                "policy_version": policy_version,
                "enrolled_at": _now(),
            }
            _write_registry(registry)
            _clear_intent(identity)
        finally:
            if staging is not None:
                # A deterministic failure before publication removes this
                # attempt's staging directory and its intent: no durable event
                # exists, so admission must not remain blocked. A genuine
                # interruption skips this block, leaving the intent for the
                # owner to recover. Post-publication failures (staging is None)
                # also keep the intent so the published plan can be reconciled.
                shutil.rmtree(staging.parent, ignore_errors=True)
                if not path.exists():
                    with contextlib.suppress(OSError):
                        _clear_intent(identity)
    return {**views, "idempotent": False}


def _strict_source_evidence(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    round_number: int,
    cycle: int,
    candidate_sha256: str | None,
    source: Any,
) -> dict[str, Any]:
    """Validate one D1-ingested provider receipt for the exact strict slot.

    This is the only path by which a non-Codex strict-mode submission acquires
    its content. It returns the immutable evidence plus the original provider
    payload; user-supplied job IDs, role strings and prompts never reach the
    ledger without it.
    """
    if source is None:
        _fail(
            "Strict-execution submissions require --source-job evidence from a "
            "settled reserved provider job"
        )
    hook = _HOOKS.get("execution_source_validator")
    if hook is None:
        _fail(
            "Strict-execution provider provenance is unavailable; failing closed"
        )
    expected_operation = provider_operation_for_round(round_number)
    error_type = _hook("runner_error")
    try:
        evidence = hook(
            plan_id=plan_id,
            step_id=step_id,
            role=role,
            round_number=round_number,
            cycle=cycle,
            candidate_sha256=candidate_sha256,
            source=source,
        )
    except error_type:
        raise
    except Exception as exc:
        _fail(f"Strict-execution provider provenance failed: {exc}")
    required = set(SOURCE_EVIDENCE_KEYS) | {"payload"}
    if not isinstance(evidence, dict):
        _fail("strict-execution source evidence must be a JSON object")
    missing = sorted(required - set(evidence))
    if missing:
        _fail(
            "strict-execution source evidence is missing fields: "
            + ", ".join(missing)
        )
    # The ingestion hook is trusted to return its own display fields; only the
    # enumerated provenance/hash surface is recorded in the ledger.
    evidence = {key: evidence[key] for key in required}
    payload = evidence.get("payload")
    if not isinstance(payload, dict):
        _fail("strict-execution source evidence has no provider payload")
    if evidence.get("provider") != role:
        _fail(
            "Strict-execution provider does not match the "
            f"{ROLE_LABELS.get(role, role)} slot"
        )
    if evidence.get("operation") != expected_operation:
        _fail(
            "Strict-execution provider operation does not match the current "
            f"discussion round ({expected_operation})"
        )
    _validate_source_evidence(
        {key: evidence[key] for key in SOURCE_EVIDENCE_KEYS},
        "strict-execution source evidence",
    )
    if evidence.get("candidate_sha256") != candidate_sha256:
        _fail(
            "Strict-execution source evidence does not bind the current frozen "
            "candidate digest"
        )
    normalized = normalize_provider_mapping(expected_operation, payload)
    if _digest(normalized) != evidence.get("mapped_sha256"):
        _fail(
            "Strict-execution mapped provider content does not match its recorded "
            "mapped digest"
        )
    if _digest(payload) != evidence.get("original_payload_sha256"):
        _fail(
            "Strict-execution original provider payload does not match its "
            "recorded original digest"
        )
    return evidence


def _source_evidence_record(evidence: dict[str, Any]) -> dict[str, Any]:
    return {key: evidence[key] for key in SOURCE_EVIDENCE_KEYS}


def submit_consensus(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    round_number: int,
    submission_raw: Any,
    job_id: str | None,
    leader: str | None,
    retry_id: str | None,
    operation_id: str | None,
    source: Any = None,
) -> dict[str, Any]:
    _require_active_role(role)
    if round_number not in (1, 2):
        _fail("consensus-submit supports round 1 proposals and round 2 cross-examinations")
    provenance = _provenance(
        {"job_id": job_id, "leader": leader}, "submission.provenance"
    )
    if retry_id is not None:
        if not isinstance(retry_id, str) or not RETRY_ID_RE.fullmatch(retry_id):
            _fail(f"Invalid retry ID: {retry_id!r}")
    submission_fields = {
        "plan_id": plan_id,
        "step_id": step_id,
        "role": role,
        "round": round_number,
        "submission": submission_raw,
        "provenance": provenance,
        "retry_id": retry_id,
    }
    if source is not None:
        submission_fields["source"] = source
    request_digest = _request_digest("consensus-submit", **submission_fields)

    def builder(state: dict[str, Any]) -> list[dict[str, Any]]:
        current = _require_step_state(state, step_id)
        stage = stage_of(current)
        expected = STAGE_PROPOSALS if round_number == 1 else STAGE_CROSS
        if stage != expected:
            _stage_error(stage, expected)
        role_map = (
            current["proposals"]
            if round_number == 1
            else current["cross_examinations"]
        )
        if role in role_map:
            _fail(
                f"{ROLE_LABELS[role]} already submitted a round {round_number} receipt in "
                f"cycle {current['cycle']}"
            )
        pause = _open_pause(current, round_number, role)
        if pause and retry_id is None:
            _fail(
                f"Provider {role} is paused: {pause['reason']}. Follow the operator "
                f"guidance ({pause['guidance']}) and pass --retry-id {pause['retry_id']} "
                "when the exact retry succeeds"
            )
        if retry_id is not None:
            if not pause:
                _fail(f"No open provider pause exists for {role} in round {round_number}")
            if pause["retry_id"] != retry_id:
                _fail(
                    f"Retry ID {retry_id!r} does not match the open pause "
                    f"{pause['retry_id']!r}"
                )
        strict = _plan_is_strict(state["static"])
        source_evidence: dict[str, Any] | None = None
        effective_provenance = provenance
        if strict:
            if role == "codex":
                if source is not None:
                    _fail(
                        "Codex strict-mode submissions use the active coordinator "
                        "leader identity, not a provider job"
                    )
                if provenance.get("leader") is None or provenance.get("job_id") is not None:
                    _fail(
                        "Strict-execution Codex submissions require --leader and "
                        "must not claim a provider job identity"
                    )
            else:
                evidence = _strict_source_evidence(
                    plan_id=plan_id,
                    step_id=step_id,
                    role=role,
                    round_number=round_number,
                    cycle=current["cycle"],
                    candidate_sha256=None,
                    source=source,
                )
                source_evidence = _source_evidence_record(evidence)
                effective_provenance = {
                    "job_id": evidence["job_id"],
                    "leader": None,
                }
                mapped = normalize_provider_mapping(
                    provider_operation_for_round(round_number),
                    evidence["payload"],
                )
                if round_number == 1:
                    submitted = _validate_proposal(submission_raw)
                else:
                    submitted = _normalize_cross_without_ids(submission_raw)
                if mapped != submitted or _digest(submitted) != evidence["mapped_sha256"]:
                    _fail(
                        "Strict-execution submission does not equal the deterministic "
                        "mapping of the settled provider payload"
                    )
        elif source is not None:
            _fail(
                "--source-job provenance is available only for strict-execution plans"
            )
        if round_number == 1:
            submission = _validate_proposal(submission_raw)
            event_type = "proposal_recorded"
        else:
            submission, objections = _validate_cross(
                submission_raw, len(current["objections"]), assign_ids=True
            )
            for objection in objections:
                objection["role"] = role
            event_type = "cross_examination_recorded"
        payload: dict[str, Any] = {
            "role": role,
            "provenance": effective_provenance,
            "submission": submission,
            "retry_id": retry_id,
        }
        if source_evidence is not None:
            payload["source_evidence"] = source_evidence
        return [
            {
                "type": event_type,
                "step_id": step_id,
                "cycle": current["cycle"],
                "round": round_number,
                "payload": payload,
            }
        ]

    result = _execute(plan_id, step_id, operation_id, request_digest, builder)
    return _result(
        result["state"],
        step_id,
        result["events"][0]["operation_id"],
        result["events"],
        result["idempotent"],
    )


def freeze_candidate(
    *,
    plan_id: str,
    step_id: str,
    candidate_raw: Any,
    operation_id: str | None,
) -> dict[str, Any]:
    request_digest = _request_digest(
        "consensus-freeze",
        plan_id=plan_id,
        step_id=step_id,
        candidate=candidate_raw,
    )

    def builder(state: dict[str, Any]) -> list[dict[str, Any]]:
        current = _require_step_state(state, step_id)
        stage = stage_of(current)
        if stage != STAGE_CANDIDATE:
            _stage_error(stage, STAGE_CANDIDATE)
        step = _manifest_step_for(state, step_id)
        objection_ids = [item["objection_id"] for item in current["objections"]]
        candidate = _validate_candidate(
            candidate_raw,
            objection_ids,
            step,
            strict=_plan_is_strict(state["static"]),
        )
        binding = _binding_for(state["static"], step, current["cycle"])
        digest = _candidate_digest(binding, candidate)
        return [
            {
                "type": "candidate_frozen",
                "step_id": step_id,
                "cycle": current["cycle"],
                "round": 3,
                "payload": {
                    "digest": digest,
                    "binding": binding,
                    "candidate": candidate,
                    "objection_ids": objection_ids,
                },
            }
        ]

    result = _execute(plan_id, step_id, operation_id, request_digest, builder)
    return _result(
        result["state"],
        step_id,
        result["events"][0]["operation_id"],
        result["events"],
        result["idempotent"],
    )


def cast_ballot(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    digest: str,
    vote: str,
    rationale: str | None,
    job_id: str | None,
    leader: str | None,
    retry_id: str | None,
    operation_id: str | None,
    source: Any = None,
) -> dict[str, Any]:
    _require_active_role(role)
    if vote not in VOTES:
        _fail(f"Invalid vote {vote!r}; expected one of {', '.join(VOTES)}")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        _fail("Ballot requires the 64-character frozen candidate digest")
    if rationale is not None:
        rationale = _text(rationale, "ballot rationale", minimum=1)
    if retry_id is not None:
        if not isinstance(retry_id, str) or not RETRY_ID_RE.fullmatch(retry_id):
            _fail(f"Invalid retry ID: {retry_id!r}")
    provenance = _provenance({"job_id": job_id, "leader": leader}, "ballot.provenance")
    ballot_fields = {
        "plan_id": plan_id,
        "step_id": step_id,
        "role": role,
        "digest": digest,
        "vote": vote,
        "rationale": rationale,
        "provenance": provenance,
        "retry_id": retry_id,
    }
    if source is not None:
        ballot_fields["source"] = source
    request_digest = _request_digest("consensus-vote", **ballot_fields)

    def builder(state: dict[str, Any]) -> list[dict[str, Any]]:
        current = _require_step_state(state, step_id)
        stage = stage_of(current)
        if stage != STAGE_BALLOTS:
            _stage_error(stage, STAGE_BALLOTS)
        if role in current["ballots"]:
            _fail(
                f"{ROLE_LABELS[role]} already voted in cycle {current['cycle']}; "
                "a duplicate or conflicting ballot is not accepted"
            )
        if digest != current["candidate"]["digest"]:
            _fail(
                "Ballot digest is stale or does not match the frozen candidate "
                f"{current['candidate']['digest']}"
            )
        pause = _open_pause(current, 3, role)
        if pause and retry_id is None:
            _fail(
                f"Provider {role} is paused: {pause['reason']}. Follow the operator "
                f"guidance ({pause['guidance']}) and pass --retry-id {pause['retry_id']}"
            )
        if retry_id is not None:
            if not pause:
                _fail(f"No open provider pause exists for {role} in round 3")
            if pause["retry_id"] != retry_id:
                _fail(
                    f"Retry ID {retry_id!r} does not match the open pause "
                    f"{pause['retry_id']!r}"
                )
        strict = _plan_is_strict(state["static"])
        source_evidence: dict[str, Any] | None = None
        effective_vote = vote
        effective_rationale = rationale
        effective_provenance = provenance
        if strict:
            if role == "codex":
                if source is not None:
                    _fail(
                        "Codex strict-mode ballots use the active coordinator "
                        "leader identity, not a provider job"
                    )
                if provenance.get("leader") is None or provenance.get("job_id") is not None:
                    _fail(
                        "Strict-execution Codex ballots require --leader and must "
                        "not claim a provider job identity"
                    )
            else:
                evidence = _strict_source_evidence(
                    plan_id=plan_id,
                    step_id=step_id,
                    role=role,
                    round_number=3,
                    cycle=current["cycle"],
                    candidate_sha256=current["candidate"]["digest"],
                    source=source,
                )
                mapped = normalize_provider_mapping("consensus", evidence["payload"])
                if (
                    mapped["vote"] != vote
                    or mapped["digest"] != digest
                    or mapped["rationale"] != (rationale or "")
                ):
                    _fail(
                        "Strict-execution ballot does not equal the deterministic "
                        "mapping of the settled provider consensus payload"
                    )
                source_evidence = _source_evidence_record(evidence)
                effective_vote = mapped["vote"]
                effective_rationale = mapped["rationale"]
                effective_provenance = {
                    "job_id": evidence["job_id"],
                    "leader": None,
                }
        elif source is not None:
            _fail(
                "--source-job provenance is available only for strict-execution plans"
            )
        ballot_payload: dict[str, Any] = {
            "role": role,
            "vote": effective_vote,
            "rationale": effective_rationale,
            "digest": digest,
            "provenance": effective_provenance,
            "retry_id": retry_id,
        }
        if source_evidence is not None:
            ballot_payload["source_evidence"] = source_evidence
        specs = [
            {
                "type": "ballot_recorded",
                "step_id": step_id,
                "cycle": current["cycle"],
                "round": 3,
                "payload": ballot_payload,
            }
        ]
        preview = {
            **current,
            "ballots": {
                **current["ballots"],
                role: {"role": role, "vote": vote if not strict else effective_vote},
            },
        }
        if len(preview["ballots"]) == len(_state_roles(current)):
            outcome_type, outcome_payload = _outcome_spec(preview)
            specs.append(
                {
                    "type": outcome_type,
                    "step_id": step_id,
                    "cycle": current["cycle"],
                    "round": 3,
                    "payload": outcome_payload,
                }
            )
        return specs

    result = _execute(plan_id, step_id, operation_id, request_digest, builder)
    return _result(
        result["state"],
        step_id,
        result["events"][0]["operation_id"],
        result["events"],
        result["idempotent"],
    )


def pause_provider(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    reason: str,
    guidance: str,
    job_id: str | None,
    leader: str | None,
    operation_id: str | None,
) -> dict[str, Any]:
    _require_active_role(role)
    reason = _text(reason, "pause reason", minimum=10)
    guidance = _text(guidance, "pause operator guidance", minimum=10)
    provenance = _provenance({"job_id": job_id, "leader": leader}, "pause.provenance")
    request_digest = _request_digest(
        "consensus-pause",
        plan_id=plan_id,
        step_id=step_id,
        role=role,
        reason=reason,
        guidance=guidance,
        provenance=provenance,
    )

    def builder(state: dict[str, Any]) -> list[dict[str, Any]]:
        current = _require_step_state(state, step_id)
        stage = stage_of(current)
        round_number = _stage_round(stage)
        if stage not in {STAGE_PROPOSALS, STAGE_CROSS, STAGE_BALLOTS}:
            _stage_error(stage, "an open provider round")
        if _role_submitted(current, stage, role):
            _fail(f"{ROLE_LABELS[role]} already submitted in the current round")
        if _open_pause(current, round_number or 1, role):
            _fail(f"{ROLE_LABELS[role]} already has an open pause in this round")
        retry_id = f"retry-{time.time_ns()}-{secrets.token_hex(3)}"
        return [
            {
                "type": "provider_paused",
                "step_id": step_id,
                "cycle": current["cycle"],
                "round": round_number,
                "payload": {
                    "role": role,
                    "round": round_number,
                    "reason": reason,
                    "guidance": guidance,
                    "provenance": provenance,
                    "retry_id": retry_id,
                },
            }
        ]

    result = _execute(plan_id, step_id, operation_id, request_digest, builder)
    output = _result(
        result["state"],
        step_id,
        result["events"][0]["operation_id"],
        result["events"],
        result["idempotent"],
    )
    output["pause"] = result["events"][0]["payload"]
    return output


def resume_provider(
    *,
    plan_id: str,
    step_id: str,
    role: str,
    retry_id: str,
    operation_id: str | None,
) -> dict[str, Any]:
    _require_active_role(role)
    if not isinstance(retry_id, str) or not RETRY_ID_RE.fullmatch(retry_id):
        _fail(f"Invalid retry ID: {retry_id!r}")
    request_digest = _request_digest(
        "consensus-resume",
        plan_id=plan_id,
        step_id=step_id,
        role=role,
        retry_id=retry_id,
    )

    def builder(state: dict[str, Any]) -> list[dict[str, Any]]:
        current = _require_step_state(state, step_id)
        stage = stage_of(current)
        round_number = _stage_round(stage)
        if stage not in {STAGE_PROPOSALS, STAGE_CROSS, STAGE_BALLOTS}:
            _stage_error(stage, "an open provider round")
        pause = _open_pause(current, round_number or 1, role)
        if not pause or pause["retry_id"] != retry_id:
            _fail(f"No open pause for {role} matches retry ID {retry_id!r}")
        return [
            {
                "type": "provider_resumed",
                "step_id": step_id,
                "cycle": current["cycle"],
                "round": round_number,
                "payload": {
                    "role": role,
                    "round": round_number,
                    "retry_id": retry_id,
                },
            }
        ]

    result = _execute(plan_id, step_id, operation_id, request_digest, builder)
    return _result(
        result["state"],
        step_id,
        result["events"][0]["operation_id"],
        result["events"],
        result["idempotent"],
    )


def authorize_new_cycle(
    *,
    plan_id: str,
    step_id: str,
    authorized_by: str,
    authorization: str,
    operation_id: str | None,
    authorization_kind: str | None = None,
) -> dict[str, Any]:
    authorized_by = _text(authorized_by, "authorized-by", minimum=2)
    authorization = _text(authorization, "authorization", minimum=10)
    if authorization_kind is not None and authorization_kind not in AUTHORIZATION_KINDS:
        _fail(
            "authorization-kind must be 'human' or 'coordinator' when supplied"
        )
    cycle_fields = {
        "plan_id": plan_id,
        "step_id": step_id,
        "authorized_by": authorized_by,
        "authorization": authorization,
    }
    if authorization_kind is not None:
        cycle_fields["authorization_kind"] = authorization_kind
    request_digest = _request_digest("consensus-new-cycle", **cycle_fields)

    def builder(state: dict[str, Any]) -> list[dict[str, Any]]:
        current = _require_step_state(state, step_id)
        stage = stage_of(current)
        if stage not in {STAGE_HUMAN, STAGE_CONSENSUS}:
            _stage_error(stage, f"{STAGE_HUMAN} or {STAGE_CONSENSUS}")
        candidate = current.get("candidate") or {}
        new_cycle = current["cycle"] + 1
        strict = _plan_is_strict(state["static"])
        if strict:
            # A reopen is a B1 mutation. Every live, pending or uncertain D1
            # writer intent/claim/attempt must be reconciled first.
            guard = _HOOKS.get("execution_cycle_guard")
            if guard is None:
                _fail(
                    "Strict-execution cycle mutation guard is unavailable; failing "
                    "closed"
                )
            error_type = _hook("runner_error")
            try:
                blocker = guard(plan_id=plan_id, step_id=step_id)
            except error_type:
                raise
            except Exception as exc:
                _fail(f"Strict-execution cycle mutation guard failed: {exc}")
            if blocker:
                _fail(str(blocker))
            if authorization_kind is None:
                _fail(
                    "Strict-execution new cycles require --authorization-kind "
                    "'human' or 'coordinator'"
                )
            if stage == STAGE_HUMAN and authorization_kind != "human":
                _fail(
                    "A non-unanimous cycle can only reopen through an honest human "
                    "authorization; coordinator-requested consensus is available "
                    "only after a successful unanimous cycle"
                )
        authorization_payload = {
            "authorized_by": authorized_by,
            "text": authorization,
        }
        if authorization_kind is not None:
            authorization_payload["authorization_kind"] = authorization_kind
        return [
            {
                "type": "new_cycle_authorized",
                "step_id": step_id,
                "cycle": new_cycle,
                "round": 1,
                "payload": {
                    "previous_cycle": current["cycle"],
                    "previous_outcome": stage,
                    "previous_digest": candidate.get("digest"),
                    "authorization": authorization_payload,
                    "new_cycle": new_cycle,
                },
            }
        ]

    result = _execute(plan_id, step_id, operation_id, request_digest, builder)
    return _result(
        result["state"],
        step_id,
        result["events"][0]["operation_id"],
        result["events"],
        result["idempotent"],
    )
