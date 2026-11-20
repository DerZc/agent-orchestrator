"""Phase C named provider adapters for the user's Claude Code shell functions.

This module is deliberately standalone: the runner loads it by absolute path.
It provides the frozen C primitives:

* a versioned, typed capability table for the reserved ``deepseek`` and
  ``glm`` profiles and the five discussion/implementation operations;
* strict lexical parsing of the small supported Bash wrapper grammar;
* pre-capture resolution of ``claude`` to a direct external executable in the
  real interactive context, failing closed for Bash function/alias/builtin
  delegation before any capture record or acknowledgement;
* an anonymous-pipe credential capture handshake executed in the real
  interactive startup context, with acknowledgement only after validation and
  redactor initialization;
* bubblewrap confinement around the outer invocation;
* bounded, in-memory, stream-safe output redaction;
* Claude completion-envelope and operation-payload validation;
* a normalized provider-result record written independently of provider
  editable state.

The module never persists wrapper bodies, exported environments, or credential
values.  It makes no network calls and starts no scheduler.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

RESULT_VERSION = 1
BINDING_VERSION = 1
CAPABILITY_TABLE_VERSION = 1

OPERATIONS = (
    "proposal",
    "cross_examination",
    "consensus",
    "implementation",
    "repair",
)
READONLY_OPERATIONS = ("proposal", "cross_examination", "consensus")
WRITER_OPERATIONS = ("implementation", "repair")

PROVIDERS = ("deepseek", "glm")

# D1 protection seam.  These inputs are optional and typed: an empty default
# preserves the historical provider argv byte-for-byte, while a protected D1
# writer supplies workspace-relative original-user roots and their ancestor
# anchors.  C owns validation, mount ordering and the resulting evidence; a
# transport shim or writer report can never supply this proof.
PROTECTION_INPUT_VERSION = 1
MAX_PROTECTION_ROOTS = 256
MAX_PROTECTION_ANCHORS = 1_024
MAX_EXTRA_MOUNT_ARGV_BYTES = 128 * 1024
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_CONFINEMENT_STATUS_BYTES = 4_096

CONFINEMENT_CHECK_SCRIPT = r"""import json
import os
import sys

nonce = sys.argv[1]
status_fd = int(sys.argv[2])
try:
    checks = json.loads(sys.argv[3])
except Exception:
    try:
        os.write(
            status_fd,
            ("C1CONF %s FAIL invalid-check-payload\n" % nonce).encode("utf-8"),
        )
    except OSError:
        pass
    raise SystemExit(1)
command = sys.argv[4:]


def _unescape(value):
    result = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 3 < len(value) + 1:
            octal = value[index + 1 : index + 4]
            if len(octal) == 3 and all(item in "01234567" for item in octal):
                result.append(int(octal, 8))
                index += 4
                continue
        result.extend(char.encode("utf-8", "surrogateescape"))
        index += 1
    return result.decode("utf-8", "surrogateescape")


def _report(ok, detail):
    line = "C1CONF %s %s %s\n" % (
        nonce,
        "OK" if ok else "FAIL",
        detail.replace("\n", " ")[:400],
    )
    try:
        os.write(status_fd, line.encode("utf-8", "replace"))
    except OSError:
        pass
    if not ok:
        os._exit(1)


try:
    with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as handle:
        mountinfo = handle.read(4 * 1024 * 1024 + 1)
    if len(mountinfo) > 4 * 1024 * 1024:
        _report(False, "mountinfo exceeds its bounded size")
        raise SystemExit(1)
except Exception as exc:
    _report(False, "check input unavailable: " + type(exc).__name__)
    raise SystemExit(1)

mounts = {}
for line in mountinfo.splitlines():
    fields = line.split(" ")
    if len(fields) < 6:
        continue
    try:
        mount_id = int(fields[0])
    except ValueError:
        continue
    mountpoint = _unescape(fields[4])
    mounts.setdefault(mountpoint, []).append((mount_id, fields[5]))


def mount_options(path):
    entries = mounts.get(path)
    if not entries:
        return None, "missing"
    if len(entries) != 1:
        # The plan mounts each declared path exactly once.  Multiple entries
        # mean an unexpected overmount topology that cannot be attested
        # without inventing ordering assumptions; fail closed instead.
        return None, "duplicate"
    return entries[0][1], None


errors = []
checked = 0
for root in checks.get("roots") or []:
    checked += 1
    options, problem = mount_options(root["path"])
    if problem == "missing":
        errors.append("protected root is not a private mount: " + root["path"])
    elif problem == "duplicate":
        errors.append("protected root has ambiguous overmounts: " + root["path"])
    elif "ro" not in options.split(","):
        errors.append("protected root is not read-only: " + root["path"])
    if root.get("kind") == "directory":
        prefix = root["path"].rstrip("/") + "/"
        for mountpoint, entries in mounts.items():
            if mountpoint.startswith(prefix):
                for _mount_id, options in entries:
                    if "ro" not in options.split(","):
                        errors.append(
                            "writable mount inside protected root: " + mountpoint
                        )
                        break
for entry in checks.get("anchors") or []:
    checked += 1
    options, problem = mount_options(entry["path"])
    if problem == "missing":
        errors.append("ancestor anchor is not a private mount: " + entry["path"])
    elif problem == "duplicate":
        errors.append("ancestor anchor has ambiguous overmounts: " + entry["path"])
    elif "ro" in options.split(","):
        errors.append("ancestor anchor was remounted read-only: " + entry["path"])
for role, path in (
    ("workspace", checks.get("workspace")),
    ("scratch", checks.get("scratch")),
    ("channel", checks.get("channel")),
):
    if not path:
        continue
    checked += 1
    options, problem = mount_options(path)
    if problem == "missing":
        errors.append(role + " is not writable inside the sandbox: " + path)
    elif problem == "duplicate":
        errors.append(role + " has ambiguous overmounts: " + path)
    elif "ro" in options.split(","):
        errors.append(role + " is read-only inside the sandbox: " + path)
for path in checks.get("git") or []:
    checked += 1
    options, problem = mount_options(path)
    if problem == "missing":
        errors.append("Git custody path is not a private mount: " + path)
    elif problem == "duplicate":
        errors.append("Git custody path has ambiguous overmounts: " + path)
    elif "ro" not in options.split(","):
        errors.append("Git custody path is not read-only: " + path)

if errors:
    _report(False, "; ".join(errors[:4]))
    raise SystemExit(1)
_report(True, str(checked))
try:
    os.close(status_fd)
except OSError:
    pass
try:
    os.execv(command[0], command)
except OSError as exc:
    _report(False, "provider command unavailable: " + type(exc).__name__)
raise SystemExit(1)
"""

# This table is the only authority C introduces.  Reserved profile names are
# fixed; configuration may choose the Bash startup context but cannot widen an
# operation's capability.
CAPABILITY_TABLE: dict[str, Any] = {
    "version": CAPABILITY_TABLE_VERSION,
    "providers": {
        "deepseek": {
            "proposal": "readonly",
            "cross_examination": "readonly",
            "consensus": "readonly",
            "implementation": "workspace_write",
            "repair": "workspace_write",
        },
        "glm": {
            "proposal": "readonly",
            "cross_examination": "readonly",
            "consensus": "readonly",
        },
    },
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


CAPABILITY_TABLE_SHA256 = hashlib.sha256(
    _canonical_bytes(CAPABILITY_TABLE)
).hexdigest()

ERROR_CODES = frozenset(
    {
        "provider_unavailable",
        "isolation_unavailable",
        "unauthorized_role",
        "credential_capture_unavailable",
        "auth_failed",
        "rate_limited",
        "quota_exceeded",
        "timeout",
        "cancelled",
        "execution_failed",
        "invalid_output",
        "output_limit",
    }
)

SENSITIVE_NAME_COMPOUNDS = (
    "AUTH_TOKEN",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
)
SENSITIVE_NAME_SEGMENTS = frozenset(
    {"TOKEN", "PASSWORD", "SECRET", "CREDENTIAL", "CREDENTIALS"}
)
_NAME_SEGMENT_RE = re.compile(r"[^A-Z0-9]+")

# Output limits are enforced while draining pipes.  Raw bytes are never
# written to disk; only sanitized, bounded buffers are returned.
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_STDOUT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 1 * 1024 * 1024
MAX_OUTPUT_LINE_BYTES = 1 * 1024 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024
MAX_PAYLOAD_TEXT = 8 * 1024
MAX_PAYLOAD_ITEMS = 100
MAX_RESULT_TEXT_BYTES = 128 * 1024
MAX_DIAGNOSTIC_TAIL = 4096
TRUNCATION_HOLDBACK = 512
CAPTURE_ACK = b"1"

# A credential can reach a persisted surface after one or more JSON encoding
# layers (the provider result document is itself a string inside the Claude
# completion envelope).  Redaction therefore covers the raw value and bounded
# JSON-escaped representations of it.  Small values (real credentials) get the
# full depth; larger values get a bounded subset so sanitization stays linear
# in the retained output size.
MAX_JSON_ESCAPE_DEPTH = 3
SMALL_SECRET_BYTES = 4096
MAX_ESCAPED_SECRET_BYTES = 64 * 1024

# A provider may spell JSON string characters with arbitrary \uXXXX escapes,
# including literal and escaped characters in the same value.  Finite
# json.dumps variants cannot cover that, so persisted streams get a
# decode-aware verification pass: strings are decoded through bounded JSON and
# escape layers and checked against the known secrets.  A line that still
# decodes to a known secret after canonicalization is replaced wholesale; a
# success report is never accepted from a leaky stored stream.
MAX_DECODE_DEPTH = 6
MAX_UNICODE_DECODE_LAYERS = 4
WITHHELD_LINE = (
    b"[c-provider output line withheld: sanitization could not be verified]"
)

TOKEN_PATTERNS = re.compile(
    rb"(?:"
    rb"sk-ant-[A-Za-z0-9_-]{20,}"
    rb"|sk-[A-Za-z0-9_-]{20,}"
    rb"|gh[pousr]_[A-Za-z0-9]{20,}"
    rb"|xox[baprs]-[A-Za-z0-9-]{10,}"
    rb"|AIza[0-9A-Za-z_-]{30,}"
    rb"|AKIA[0-9A-Z]{16}"
    rb"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    rb"|Bearer[ \t]+[A-Za-z0-9._~+/=-]{16,}"
    rb")",
    re.IGNORECASE,
)

REDACTED = b"[REDACTED]"
SAFE_CAPTURE_ERROR = (
    "provider wrapper definition could not be captured and validated"
)
SAFE_SYNTAX_ERROR = "provider wrapper definition uses unsupported shell syntax"
SAFE_ISOLATION_ERROR = "required bubblewrap isolation is unavailable"
SAFE_BACKEND_ERROR = (
    "the external claude backend is not available in the loaded startup context"
)
SAFE_DELEGATION_ERROR = (
    "the provider wrapper backend must resolve to a direct external claude executable"
)


class ProviderError(Exception):
    """A fixed, nonsecret provider failure from the documented error enum."""

    def __init__(self, code: str, message: str) -> None:
        if code not in ERROR_CODES:
            code = "execution_failed"
        self.code = code
        # Messages are fixed or contain only nonsecret structural facts.  No
        # captured value is ever interpolated here.
        self.message = str(message)[:512]
        super().__init__(f"{self.code}: {self.message}")

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


class WrapperSpec:
    __slots__ = ("function", "assignments", "command")

    def __init__(
        self,
        function: str,
        assignments: tuple[tuple[str, str, bool], ...],
        command: tuple[str, str],
    ) -> None:
        self.function = function
        self.assignments = assignments
        self.command = command

    def exported_values(self) -> dict[str, str]:
        values: dict[str, str] = {}
        for name, value, exported in self.assignments:
            if exported:
                values[name] = value
        return values

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, WrapperSpec)
            and self.function == other.function
            and self.assignments == other.assignments
            and self.command == other.command
        )

    def __repr__(self) -> str:
        return (
            f"WrapperSpec(function={self.function!r}, "
            f"assignments={len(self.assignments)}, command={self.command!r})"
        )


class _Token:
    __slots__ = ("literal", "specials", "quoted")

    def __init__(self, literal: str, specials: tuple[str, ...], quoted: bool) -> None:
        self.literal = literal
        self.specials = specials
        self.quoted = quoted

    @property
    def plain(self) -> bool:
        return not self.specials


def is_sensitive_name(name: str) -> bool:
    """Classify credential-bearing environment or assignment names.

    Compound markers cover common vendor spellings.  Single-word classes match
    underscore-delimited segments so benign names such as
    ``TOKENIZERS_PARALLELISM`` are not mistaken for credentials.
    """
    upper = name.upper()
    if any(marker in upper for marker in SENSITIVE_NAME_COMPOUNDS):
        return True
    segments = [part for part in _NAME_SEGMENT_RE.split(upper) if part]
    return any(part in SENSITIVE_NAME_SEGMENTS for part in segments)


def is_reserved_provider(name: Any) -> bool:
    return isinstance(name, str) and name in PROVIDERS


def capability_for(provider: str, operation: str) -> str:
    capabilities = CAPABILITY_TABLE["providers"].get(provider)
    if not capabilities:
        raise ProviderError(
            "unauthorized_role", "provider is not in the reserved capability table"
        )
    capability = capabilities.get(operation)
    if capability not in {"readonly", "workspace_write"}:
        raise ProviderError(
            "unauthorized_role",
            "operation is not authorized for this reserved provider",
        )
    return capability


def validate_reserved_profile(name: str, raw: Any) -> None:
    """Validate the fixed shape of a reserved wrapper profile.

    Configuration may set ``provider_rcfile`` only; command identity, prompt
    transport, and capability-bearing fields cannot be overridden.
    """
    if not is_reserved_provider(name):
        raise ValueError("not a reserved provider")
    if not isinstance(raw, dict):
        raise ValueError(f"reserved provider profile {name!r} must be an object")
    if raw.get("provider") != name:
        raise ValueError(
            f"reserved provider profile {name!r} must bind its own provider identity"
        )
    if raw.get("argv") != [name]:
        raise ValueError(
            f"reserved provider profile {name!r} must invoke the configured {name} function"
        )
    if raw.get("prompt_transport") != "stdin":
        raise ValueError(
            f"reserved provider profile {name!r} must transport the prompt on stdin"
        )
    forbidden = {
        "executable_candidates",
        "model_args",
        "cli_agent_args",
        "max_turns_args",
        "cost_args",
        "reasoning_effort_args",
        "models",
        "cli_agents",
        "discover_models_argv",
        "discover_cli_agents_argv",
    }
    present = sorted(set(raw) & forbidden)
    if present:
        raise ValueError(
            f"reserved provider profile {name!r} cannot widen invocation fields: "
            + ", ".join(present)
        )
    rcfile = raw.get("provider_rcfile")
    if rcfile is not None:
        if not isinstance(rcfile, str) or not rcfile.strip():
            raise ValueError(
                f"reserved provider profile {name!r} provider_rcfile must be a path"
            )
        if "\x00" in rcfile or not Path(rcfile).expanduser().is_absolute():
            raise ValueError(
                f"reserved provider profile {name!r} provider_rcfile must be absolute"
            )


def resolve_provider_rcfile(profile: Mapping[str, Any]) -> str | None:
    value = profile.get("provider_rcfile")
    if value is None:
        return None
    try:
        resolved = Path(str(value)).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProviderError(
            "provider_unavailable",
            "the configured provider Bash rcfile is unavailable",
        ) from exc
    if not resolved.is_file():
        raise ProviderError(
            "provider_unavailable",
            "the configured provider Bash rcfile is not a regular file",
        )
    return str(resolved)


def build_binding(
    profile_name: str, profile: Mapping[str, Any], operation: str
) -> dict[str, Any]:
    """Build the persisted capability binding for one reserved job."""
    try:
        validate_reserved_profile(profile_name, profile)
    except ValueError as exc:
        raise ProviderError("unauthorized_role", str(exc)) from exc
    if operation not in OPERATIONS:
        raise ProviderError(
            "unauthorized_role", "operation is not in the version 1 operation set"
        )
    capability = capability_for(profile_name, operation)
    if capability == "workspace_write" and profile_name != "deepseek":
        raise ProviderError(
            "unauthorized_role",
            "only the reserved deepseek implementation/repair writer may write",
        )
    rcfile = resolve_provider_rcfile(profile)
    binding: dict[str, Any] = {
        "binding_version": BINDING_VERSION,
        "profile": profile_name,
        "provider": profile_name,
        "operation": operation,
        "capability": capability,
        "capability_table_version": CAPABILITY_TABLE_VERSION,
        "capability_table_sha256": CAPABILITY_TABLE_SHA256,
        "wrapper": {
            "shell": "bash",
            "interactive": True,
            "function": profile_name,
            "startup": "default_rc" if rcfile is None else "explicit_rcfile",
            "rcfile": rcfile,
        },
    }
    binding["binding_sha256"] = hashlib.sha256(
        _canonical_bytes(binding)
    ).hexdigest()
    return binding


def binding_from_meta(meta: Mapping[str, Any]) -> dict[str, Any]:
    """Revalidate a persisted job binding at worker execution time."""
    if not isinstance(meta, Mapping):
        raise ProviderError("unauthorized_role", "job metadata is not an object")
    agent = meta.get("agent")
    cli = meta.get("cli")
    profile = meta.get("profile")
    raw_binding = meta.get("provider_binding")
    if not is_reserved_provider(agent) or cli != agent:
        raise ProviderError(
            "unauthorized_role",
            "job provider identity is not a reserved named provider",
        )
    if not isinstance(profile, Mapping) or not isinstance(raw_binding, Mapping):
        raise ProviderError(
            "unauthorized_role", "job has no valid reserved provider binding"
        )
    operation = raw_binding.get("operation")
    if operation not in OPERATIONS:
        raise ProviderError(
            "unauthorized_role", "job provider operation is not supported"
        )
    if meta.get("operation") not in {None, operation}:
        raise ProviderError(
            "unauthorized_role", "job operation metadata does not match the binding"
        )
    if meta.get("provider") not in {None, agent}:
        raise ProviderError(
            "unauthorized_role", "job provider metadata does not match the binding"
        )
    expected = build_binding(agent, profile, operation)
    if raw_binding.get("binding_sha256") != expected["binding_sha256"]:
        raise ProviderError(
            "unauthorized_role",
            "persisted provider binding does not match the reserved capability table",
        )
    if (
        raw_binding.get("capability") != expected["capability"]
        or raw_binding.get("provider") != expected["provider"]
        or raw_binding.get("profile") != expected["profile"]
        or raw_binding.get("binding_version") != expected["binding_version"]
        or raw_binding.get("capability_table_sha256")
        != expected["capability_table_sha256"]
        or raw_binding.get("capability_table_version")
        != expected["capability_table_version"]
    ):
        raise ProviderError(
            "unauthorized_role", "persisted provider binding was altered"
        )
    if expected["capability"] == "readonly" and isinstance(
        meta.get("workspace_lease"), dict
    ):
        raise ProviderError(
            "unauthorized_role", "readonly provider job must not own a writer lease"
        )
    if expected["capability"] == "workspace_write" and not isinstance(
        meta.get("workspace_lease"), dict
    ):
        raise ProviderError(
            "unauthorized_role",
            "workspace-write provider job requires an active B2 writer lease",
        )
    return expected


def classify_job_capability(meta: Any) -> str:
    """Classify another live job for admission serialization, failing closed."""
    if not isinstance(meta, dict):
        return "unknown"
    managed = meta.get("managed_execution")
    if isinstance(managed, dict) and managed.get("kind") == "validation":
        # Explicit validator classification: never a legacy generic writer or a
        # readonly provider. A validator holds the exclusive repository lease.
        return "validator"
    if "provider_binding" in meta:
        try:
            binding_from_meta(meta)
        except ProviderError:
            return "unknown"
        return str(meta["provider_binding"].get("capability", "unknown"))
    if isinstance(meta.get("workspace_lease"), dict):
        return "workspace_write"
    # Legacy/generic jobs are writers; an unleased live job can never be
    # treated as a readonly discussion.
    return "workspace_write"


# ---------------------------------------------------------------------------
# Bash wrapper capture
# ---------------------------------------------------------------------------

STDOUT_MARKER = b"\x00C1OUT\x00"
STDERR_MARKER = b"\x00C1ERR\x00"

# The capture/acknowledgement channel is an anonymous private AF_UNIX
# socketpair passed to the sandbox as an ordinary inherited descriptor
# (``pass_fds``).  Bubblewrap preserves ordinary inherited descriptors for the
# command but reserves a descriptor named by ``--sync-fd`` for itself and
# closes it in the command, so the control descriptor is never stdin and is
# never declared with ``--sync-fd``.  The wrapper script receives the
# descriptor number as data, writes the NUL-framed capture to it, waits for the
# parent acknowledgement on it, then closes it before the provider function
# runs.  The provider function's stdin is redirected from the immutable task
# file.  Provider stdout/stderr use standard descriptors and are prefixed with
# a NUL barrier that lets the parent discard bash startup output without a raw
# temporary file.
#
# Before any capture record or acknowledgement, the same interactive shell
# resolves ``claude`` in its real execution context.  Only a direct external
# executable (a regular executable file, including a symlink) is supported.  A
# Bash function, alias, builtin or any other shadow could change credential
# state after capture, so it is refused as unsupported delegation and is never
# invoked.  The guard emits only a fixed reason over the private channel; no
# wrapper body, environment or value leaves the shell on this path.
WRAPPER_SCRIPT = r"""name=$1
promptfile=$2
c1fd=$3
shift 3
if ! defn=$(builtin declare -f -- "$name"); then
  builtin printf 'ERR\0missing_function\0END\0' >&"$c1fd"
  command exec 0<&-
  exit 90
fi
if ! c1_backend_kind=$(builtin type -t claude 2>/dev/null); then
  builtin printf 'ERR\0missing_backend\0END\0' >&"$c1fd"
  command exec 0<&-
  exit 94
fi
if [ -z "$c1_backend_kind" ]; then
  builtin printf 'ERR\0missing_backend\0END\0' >&"$c1fd"
  command exec 0<&-
  exit 94
fi
if [ "$c1_backend_kind" != file ]; then
  builtin printf 'ERR\0unsupported_delegation\0END\0' >&"$c1fd"
  command exec 0<&-
  exit 95
fi
if ! c1_backend_path=$(builtin type -P claude 2>/dev/null); then
  builtin printf 'ERR\0missing_backend\0END\0' >&"$c1fd"
  command exec 0<&-
  exit 94
fi
if [ -z "$c1_backend_path" ] || [ ! -f "$c1_backend_path" ] || [ ! -x "$c1_backend_path" ]; then
  builtin printf 'ERR\0missing_backend\0END\0' >&"$c1fd"
  command exec 0<&-
  exit 94
fi
builtin printf 'C1\0%s\0%s\0' "$name" "$defn" >&"$c1fd" || exit 91
for var in $(builtin compgen -e); do
  builtin printf 'E\0%s\0%s\0' "$var" "${!var}" >&"$c1fd" || exit 91
done
builtin printf 'END\0' >&"$c1fd" || exit 91
if ! builtin read -r -n 1 -u "$c1fd" ack; then exit 92; fi
if [ "$ack" != 1 ]; then exit 93; fi
command exec {c1fd}>&-
builtin printf '\0C1OUT\0' >&1
builtin printf '\0C1ERR\0' >&2
"$name" "$@" < "$promptfile"
status=$?
exit $status
"""

PROBE_SCRIPT = r"""if builtin declare -F "$1" >/dev/null 2>&1; then exit 0; fi
exit 90
"""

# The probe script is the only code that exits with this marker.  A different
# nonzero status means bubblewrap or Bash failed before the availability check
# ran (for example bwrap --chdir EACCES), which must not be reported as a
# missing provider function.
PROBE_MISSING_FUNCTION_EXIT = 90
PROBE_MISSING_FUNCTION_REASON = (
    "the reserved provider Bash function is not available in the configured context"
)
PROBE_STARTUP_FAILURE_REASON = (
    "the provider Bash probe could not start inside the isolation sandbox "
    "before the availability check (isolation or Bash startup failure)"
)
PROBE_TIMEOUT_REASON = (
    "the isolated provider Bash availability probe exceeded its bounded timeout"
)
PROBE_EXECUTION_REASON = "provider Bash availability probe could not execute"


def _parse_error() -> ProviderError:
    return ProviderError("credential_capture_unavailable", SAFE_SYNTAX_ERROR)


def _lex_statements(body: str) -> list[list[_Token]]:
    """Lex the supported static grammar without evaluating any shell text."""
    statements: list[list[_Token]] = []
    tokens: list[_Token] = []
    literal: list[str] = []
    specials: list[str] = []
    quoted = False
    word_started = False
    index = 0
    length = len(body)

    def end_word() -> None:
        nonlocal literal, specials, quoted, word_started
        if word_started:
            tokens.append(_Token("".join(literal), tuple(specials), quoted))
        literal = []
        specials = []
        quoted = False
        word_started = False

    def end_statement() -> None:
        nonlocal tokens
        end_word()
        if tokens:
            statements.append(tokens)
        tokens = []

    while index < length:
        char = body[index]
        if char in " \t\r":
            end_word()
            index += 1
            continue
        if char == "\n":
            end_statement()
            index += 1
            continue
        if char == ";":
            end_statement()
            index += 1
            continue
        if char == "#" and not word_started:
            while index < length and body[index] != "\n":
                index += 1
            continue
        if char == "\\":
            if index + 1 < length:
                if body[index + 1] == "\n":
                    index += 2
                    continue
                literal.append(body[index + 1])
                word_started = True
                index += 2
                continue
            index += 1
            continue
        if char == "'":
            quoted = True
            word_started = True
            index += 1
            end = body.find("'", index)
            if end < 0:
                raise _parse_error()
            literal.append(body[index:end])
            index = end + 1
            continue
        if char == '"':
            quoted = True
            word_started = True
            index += 1
            closed = False
            while index < length:
                inner = body[index]
                if inner == '"':
                    index += 1
                    closed = True
                    break
                if inner == "\\":
                    if index + 1 >= length:
                        raise _parse_error()
                    escaped = body[index + 1]
                    if escaped == "\n":
                        index += 2
                        continue
                    if escaped in '$`"\\':
                        literal.append(escaped)
                    else:
                        literal.append("\\")
                        literal.append(escaped)
                    index += 2
                    continue
                if inner == "$":
                    if index + 1 < length and body[index + 1] == "@":
                        specials.append("dollar_at")
                        index += 2
                        continue
                    specials.append("expansion")
                    index += 1
                    continue
                if inner == "`":
                    specials.append("expansion")
                    index += 1
                    continue
                literal.append(inner)
                index += 1
            if not closed:
                raise _parse_error()
            continue
        if char == "`":
            specials.append("expansion")
            word_started = True
            index += 1
            continue
        if char == "$":
            if index + 1 < length and body[index + 1] == "@":
                specials.append("dollar_at")
                index += 2
            else:
                specials.append("expansion")
                index += 1
            word_started = True
            continue
        if char == "~":
            if not word_started or (literal and literal[-1] == "="):
                specials.append("expansion")
            else:
                literal.append(char)
            word_started = True
            index += 1
            continue
        if char in "|&<>()":
            raise _parse_error()
        literal.append(char)
        word_started = True
        index += 1

    end_statement()
    return statements


_ASSIGNMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _split_assignment(token: _Token) -> tuple[str, str, bool]:
    if not token.plain:
        raise _parse_error()
    text = token.literal
    if "=" not in text:
        raise _parse_error()
    name, value = text.split("=", 1)
    if not _ASSIGNMENT_NAME.fullmatch(name):
        raise _parse_error()
    return name, value, False


def parse_wrapper_definition(definition: str, expected_function: str) -> WrapperSpec:
    """Parse the exact supported static export-then-``claude \"$@\"`` grammar."""
    if not isinstance(definition, str) or not definition.strip():
        raise _parse_error()
    text = definition.replace("\r\n", "\n")
    match = re.match(
        r"\s*" + re.escape(expected_function) + r"\s*\(\s*\)\s*", text
    )
    if not match:
        raise _parse_error()
    rest = text[match.end() :].lstrip()
    if not rest.startswith("{"):
        raise _parse_error()
    rest = rest[1:].rstrip()
    if not rest.endswith("}"):
        raise _parse_error()
    body = rest[:-1]
    statements = _lex_statements(body)
    if not statements:
        raise _parse_error()
    assignments: list[tuple[str, str, bool]] = []
    command: tuple[str, str] | None = None
    for tokens in statements:
        if command is not None:
            raise _parse_error()
        if len(tokens) == 1 and tokens[0].plain:
            name, value, _ = _split_assignment(tokens[0])
            assignments.append((name, value, False))
            continue
        if (
            len(tokens) == 2
            and tokens[0].plain
            and tokens[0].literal == "export"
        ):
            name, value, _ = _split_assignment(tokens[1])
            assignments.append((name, value, True))
            continue
        if (
            len(tokens) == 2
            and tokens[0].plain
            and tokens[0].literal == "claude"
            and tokens[1].literal == ""
            and tokens[1].specials == ("dollar_at",)
            and tokens[1].quoted
        ):
            command = ("claude", '"$@"')
            continue
        raise _parse_error()
    if command is None:
        raise _parse_error()
    return WrapperSpec(
        function=expected_function,
        assignments=tuple(assignments),
        command=command,
    )


def parse_capture_stream(
    data: bytes, expected_function: str
) -> tuple[str, dict[str, bytes]]:
    """Parse the NUL-framed capture stream sent by the loaded shell."""
    if not isinstance(data, bytes) or not data:
        raise ProviderError("credential_capture_unavailable", SAFE_CAPTURE_ERROR)
    if not data.endswith(b"\x00"):
        raise ProviderError("credential_capture_unavailable", SAFE_CAPTURE_ERROR)
    fields = data.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    position = 0

    def take() -> bytes:
        nonlocal position
        if position >= len(fields):
            raise ProviderError(
                "credential_capture_unavailable", SAFE_CAPTURE_ERROR
            )
        value = fields[position]
        position += 1
        return value

    tag = take()
    if tag == b"ERR":
        reason = take()
        # An error record is ``ERR\\0reason\\0`` optionally followed by the
        # same terminal ``END`` used by the success protocol.  Any other
        # trailing field is malformed and must not be reinterpreted as a
        # trustworthy guard reason (for example after a truncated or
        # interleaved write).  The record is otherwise terminal, so the
        # parser raises rather than continuing.
        if fields[position:] not in ([], [b"END"]):
            raise ProviderError(
                "credential_capture_unavailable", SAFE_CAPTURE_ERROR
            )
        if reason == b"missing_function":
            raise ProviderError(
                "provider_unavailable",
                "the reserved provider Bash function is not defined in the loaded context",
            )
        if reason == b"missing_backend":
            raise ProviderError("provider_unavailable", SAFE_BACKEND_ERROR)
        if reason == b"unsupported_delegation":
            raise ProviderError(
                "credential_capture_unavailable", SAFE_DELEGATION_ERROR
            )
        raise ProviderError("credential_capture_unavailable", SAFE_CAPTURE_ERROR)
    if tag != b"C1":
        raise ProviderError("credential_capture_unavailable", SAFE_CAPTURE_ERROR)
    try:
        name = take().decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProviderError(
            "credential_capture_unavailable", SAFE_CAPTURE_ERROR
        ) from exc
    if name != expected_function:
        raise ProviderError(
            "credential_capture_unavailable",
            "the captured Bash function does not match the reserved provider",
        )
    try:
        definition = take().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderError(
            "credential_capture_unavailable", SAFE_CAPTURE_ERROR
        ) from exc
    environment: dict[str, bytes] = {}
    while True:
        tag = take()
        if tag == b"END":
            break
        if tag != b"E":
            raise ProviderError(
                "credential_capture_unavailable", SAFE_CAPTURE_ERROR
            )
        try:
            env_name = take().decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProviderError(
                "credential_capture_unavailable", SAFE_CAPTURE_ERROR
            ) from exc
        environment[env_name] = take()
    if position != len(fields):
        raise ProviderError("credential_capture_unavailable", SAFE_CAPTURE_ERROR)
    return definition, environment


def capture_sensitive_values(
    spec: WrapperSpec, environment: Mapping[str, bytes]
) -> list[bytes]:
    """Seed every sensitive static assignment and inherited environment value.

    The ``export`` spelling is not required for a value to reach ``claude``:
    Bash preserves an existing export attribute across plain reassignment
    (``export TOKEN=old; TOKEN=new; claude`` exports ``new``), and ``set -a``
    can be enabled by the surrounding startup context.  Seeding every
    sensitive static assignment, exported or not, is therefore the only safe
    lexical rule; over-seeding a genuinely local assignment merely redacts a
    value that never reaches the provider.
    """
    values: set[bytes] = set()
    for name, value, _exported in spec.assignments:
        if is_sensitive_name(name) and value:
            values.add(value.encode("utf-8", errors="surrogateescape"))
    for name, value in environment.items():
        if is_sensitive_name(name) and value:
            values.add(value)
    return sorted(values, key=len, reverse=True)


def _json_escaped_text(text: str, ensure_ascii: bool) -> str | None:
    try:
        encoded = json.dumps(text, ensure_ascii=ensure_ascii)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None
    return encoded[1:-1]


def _redaction_variants(secret: bytes) -> set[bytes]:
    """Return the raw value plus bounded JSON-escaped representations.

    A provider result document is a JSON string nested inside the Claude
    completion envelope, so an echoed credential may appear with its quotes,
    backslashes and non-ASCII characters escaped once or several times.  Both
    ``ensure_ascii`` spellings are generated at each depth because the inner
    document and outer envelope may be produced by different encoders.
    """
    variants: set[bytes] = {secret}
    try:
        text = secret.decode("utf-8", errors="surrogateescape")
    except UnicodeDecodeError:  # pragma: no cover - surrogateescape is total
        return variants
    if len(secret) <= SMALL_SECRET_BYTES:
        depth_limit = MAX_JSON_ESCAPE_DEPTH
    elif len(secret) <= MAX_ESCAPED_SECRET_BYTES:
        depth_limit = 2
    else:
        depth_limit = 1
    frontier = {text}
    for _depth in range(depth_limit):
        next_frontier: set[str] = set()
        for item in frontier:
            for ensure_ascii in (True, False):
                escaped = _json_escaped_text(item, ensure_ascii)
                if escaped is not None:
                    next_frontier.add(escaped)
        for item in next_frontier:
            try:
                variants.add(item.encode("utf-8", errors="surrogatepass"))
            except UnicodeEncodeError:  # pragma: no cover - defensive
                continue
        frontier = next_frontier
        if not frontier:
            break
    return variants


def _longest_prefix_suffix_size(data: bytes, pattern: bytes) -> int:
    """Length of the longest proper prefix of ``pattern`` suffixing ``data``."""
    length = len(pattern)
    if length <= 1 or not data:
        return 0
    failure = [0] * length
    matched = 0
    for index in range(1, length):
        while matched and pattern[index] != pattern[matched]:
            matched = failure[matched - 1]
        if pattern[index] == pattern[matched]:
            matched += 1
            failure[index] = matched
    matched = 0
    start = max(0, len(data) - (length - 1))
    for index in range(start, len(data)):
        byte = data[index]
        while matched and byte != pattern[matched]:
            matched = failure[matched - 1]
        if byte == pattern[matched]:
            matched += 1
        if matched == length:  # pragma: no cover - scan excludes full match
            matched = failure[length - 1]
    return matched


class Redactor:
    """Bounded exact-value and token-pattern redaction over complete buffers.

    ``sanitize`` always sees the whole retained buffer, so secrets split across
    provider write chunks are still removed as one value.  Every raw secret is
    expanded into its bounded JSON-escaped spellings so a credential echoed
    through a nested JSON document is removed before parsing or persistence,
    not only when it appears as literal bytes.
    """

    def __init__(self, secrets: Iterable[bytes]) -> None:
        patterns: set[bytes] = set()
        for secret in dict.fromkeys(secrets):
            if secret:
                patterns.update(_redaction_variants(bytes(secret)))
        self._patterns = tuple(
            sorted(patterns, key=lambda item: (len(item), item), reverse=True)
        )

    @property
    def patterns(self) -> tuple[bytes, ...]:
        return self._patterns

    @property
    def max_secret_bytes(self) -> int:
        return max((len(item) for item in self._patterns), default=0)

    def sanitize(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("redactor input must be bytes")
        for pattern in self._patterns:
            data = data.replace(pattern, REDACTED)
        data = TOKEN_PATTERNS.sub(REDACTED, data)
        return data

    def sanitize_text(self, text: str) -> str:
        """Sanitize one decoded JSON string value."""
        encoded = text.encode("utf-8", errors="surrogatepass")
        return self.sanitize(encoded).decode("utf-8", errors="surrogatepass")

    def contains_known_secret(self, data: bytes) -> bool:
        """Exact-secret check used to verify a persisted view, not to redact."""
        return any(pattern in data for pattern in self._patterns)

    def holdback(self) -> int:
        return max(TRUNCATION_HOLDBACK, self.max_secret_bytes - 1)

    def strip_partial_suffix(self, data: bytes) -> bytes:
        """Remove any retained suffix that is a proper prefix of a pattern."""
        if not data:
            return data
        longest = 0
        for pattern in self._patterns:
            size = _longest_prefix_suffix_size(data, pattern)
            if size > longest:
                longest = size
        if longest:
            return data[:-longest] + REDACTED
        return data


_NO_JSON = object()


def _decode_json_escapes(text: str) -> str:
    """Decode one layer of JSON-style escapes without requiring valid JSON."""
    output: list[str] = []
    simple = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char != "\\" or index + 1 >= length:
            output.append(char)
            index += 1
            continue
        escape = text[index + 1]
        if escape == "u" and index + 5 < length:
            digits = text[index + 2 : index + 6]
            if all(digit in "0123456789abcdefABCDEF" for digit in digits):
                output.append(chr(int(digits, 16)))
                index += 6
                continue
        if escape in simple:
            output.append(simple[escape])
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _join_surrogates(text: str) -> str:
    try:
        return text.encode("utf-16", errors="surrogatepass").decode("utf-16")
    except (UnicodeError, ValueError):
        return text


def _decoded_views(text: str) -> list[str]:
    views = [text]
    current = text
    for _layer in range(MAX_UNICODE_DECODE_LAYERS):
        decoded = _join_surrogates(_decode_json_escapes(current))
        if decoded == current:
            break
        views.append(decoded)
        current = decoded
    return views


def _json_text_candidates(text: str) -> list[str]:
    stripped = text.strip()
    candidates = [stripped]
    if stripped.startswith("```"):
        match = re.fullmatch(
            r"```(?:json)?[ \t]*\n(.*)\n```", stripped, flags=re.DOTALL
        )
        if match:
            candidates.append(match.group(1).strip())
    return candidates


def _try_json(text: str) -> Any:
    for candidate in _json_text_candidates(text):
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError):
            continue
    return _NO_JSON


def _iter_json_strings(value: Any) -> Iterable[str]:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, list) and depth < MAX_DECODE_DEPTH:
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict) and depth < MAX_DECODE_DEPTH:
            for key, child in item.items():
                if isinstance(key, str):
                    yield key
                stack.append((child, depth + 1))


def _string_view_contains_secret(redactor: Redactor, text: str) -> bool:
    for view in _decoded_views(text):
        if redactor.contains_known_secret(
            view.encode("utf-8", errors="surrogatepass")
        ):
            return True
    return False


def _decoded_text_contains_secret(
    redactor: Redactor, text: str, depth: int = 0
) -> bool:
    if _string_view_contains_secret(redactor, text):
        return True
    if depth >= MAX_DECODE_DEPTH:
        return False
    parsed = _try_json(text)
    if parsed is _NO_JSON:
        return False
    for item in _iter_json_strings(parsed):
        if _decoded_text_contains_secret(redactor, item, depth + 1):
            return True
    return False


def _sanitize_decoded_value(
    redactor: Redactor, value: Any, depth: int
) -> Any:
    if isinstance(value, str):
        cleaned = redactor.sanitize_text(value)
        if depth >= MAX_DECODE_DEPTH:
            return cleaned
        parsed = _try_json(cleaned)
        if parsed is not _NO_JSON:
            try:
                return json.dumps(
                    _sanitize_decoded_value(redactor, parsed, depth + 1),
                    ensure_ascii=False,
                )
            except (TypeError, ValueError, RecursionError):
                return redactor.sanitize_text(cleaned)
        if _string_view_contains_secret(redactor, cleaned):
            for view in _decoded_views(cleaned):
                if redactor.contains_known_secret(
                    view.encode("utf-8", errors="surrogatepass")
                ):
                    return redactor.sanitize_text(view)
        return cleaned
    if isinstance(value, list):
        return [
            _sanitize_decoded_value(redactor, item, depth) for item in value
        ]
    if isinstance(value, dict):
        return {
            (
                _sanitize_decoded_value(redactor, key, depth)
                if isinstance(key, str)
                else key
            ): _sanitize_decoded_value(redactor, item, depth)
            for key, item in value.items()
        }
    return value


def _sanitize_line_text(redactor: Redactor, text: str) -> str | None:
    parsed = _try_json(text)
    if parsed is not _NO_JSON:
        try:
            candidate = json.dumps(
                _sanitize_decoded_value(redactor, parsed, 0),
                ensure_ascii=False,
            )
        except (TypeError, ValueError, RecursionError):
            return None
    else:
        candidate = redactor.sanitize_text(text)
        for view in _decoded_views(candidate):
            if redactor.contains_known_secret(
                view.encode("utf-8", errors="surrogatepass")
            ):
                candidate = redactor.sanitize_text(view)
                break
    if _decoded_text_contains_secret(redactor, candidate):
        return None
    return candidate


def sanitize_persisted_stream(redactor: Redactor, data: bytes) -> bytes:
    """Decode-aware final guard for persisted stdout/stderr buffers.

    Exact redaction cannot enumerate every legal JSON spelling of a string, so
    each line containing a JSON unicode escape is verified through bounded JSON
    and escape decoding.  A leaking line is canonicalized and re-verified; if it
    still decodes to a known secret the whole line is withheld.  Lines without
    escape syntax were already covered by exact redaction and are kept
    byte-for-byte.
    """
    if not data or not redactor.patterns:
        return data
    output: list[bytes] = []
    for raw_line in data.splitlines(keepends=True):
        body = raw_line.rstrip(b"\r\n")
        ending = raw_line[len(body) :]
        if not body or b"\\u" not in body:
            output.append(raw_line)
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            output.append(WITHHELD_LINE + ending)
            continue
        if not _decoded_text_contains_secret(redactor, text):
            output.append(raw_line)
            continue
        candidate = _sanitize_line_text(redactor, text)
        if candidate is None:
            output.append(WITHHELD_LINE + ending)
            continue
        encoded = candidate.encode("utf-8", errors="surrogatepass")
        if _decoded_text_contains_secret(
            redactor, encoded.decode("utf-8", errors="surrogatepass")
        ):
            output.append(WITHHELD_LINE + ending)
        else:
            output.append(encoded + ending)
    return b"".join(output)


class CaptureBuffer:
    """A bounded in-memory capture buffer that keeps draining safely."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.total = 0
        self.truncated = False
        self.overflow = threading.Event()

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if self.total > self.limit:
            self.truncated = True
            self.overflow.set()


class MarkerCapture:
    """Discard startup output until the wrapper's NUL barrier, then capture.

    The barrier is written on the same descriptor as provider output after the
    capture acknowledgement, so ordering is kernel-guaranteed and no timing
    race can attribute pre-ack bash diagnostics to the provider.
    """

    def __init__(self, limit: int, marker: bytes) -> None:
        self.marker = marker
        self.capture = CaptureBuffer(limit)
        self.started = False
        self._pending = b""

    @property
    def data(self) -> bytearray:
        return self.capture.data

    @property
    def total(self) -> int:
        return self.capture.total

    @property
    def truncated(self) -> bool:
        return self.capture.truncated

    @property
    def overflow(self) -> threading.Event:
        return self.capture.overflow

    def feed(self, chunk: bytes) -> None:
        if self.started:
            self.capture.feed(chunk)
            return
        data = self._pending + chunk
        index = data.find(self.marker)
        if index < 0:
            keep = max(0, len(self.marker) - 1)
            self._pending = data[-keep:] if keep else b""
            return
        self.started = True
        self._pending = b""
        remainder = data[index + len(self.marker) :]
        if remainder:
            self.capture.feed(remainder)


def sanitize_capture(buffer: CaptureBuffer, redactor: Redactor) -> bytes:
    data = bytes(buffer.data)
    if buffer.truncated:
        # Never let an incomplete secret or partial token straddle the
        # truncation boundary into a persisted surface.
        cut = min(len(data), redactor.holdback())
        if cut:
            data = data[:-cut]
        data = redactor.strip_partial_suffix(data)
        data += b"\n[c-provider output truncated]\n"
    return sanitize_persisted_stream(redactor, redactor.sanitize(data))


# ---------------------------------------------------------------------------
# Invocation, isolation, and execution
# ---------------------------------------------------------------------------


def bash_executable() -> str:
    return shutil.which("bash") or "/bin/bash"


def shell_command(
    profile: Mapping[str, Any],
    prompt_file: Path,
    control_fd: int,
    provider_argv: list[str],
) -> list[str]:
    """Build the interactive Bash invocation and its control descriptor.

    ``control_fd`` is an ordinary inherited descriptor (see
    ``WRAPPER_SCRIPT``); it is passed as data, never through ``--sync-fd`` and
    never as the shell's stdin.
    """
    provider = profile["provider"]
    rcfile = profile.get("provider_rcfile")
    command = [bash_executable()]
    if rcfile:
        command.extend(["--rcfile", str(rcfile)])
    command.extend(
        [
            "-ic",
            WRAPPER_SCRIPT,
            "c-provider",
            str(provider),
            str(prompt_file),
            str(int(control_fd)),
            *provider_argv,
        ]
    )
    return command


def provider_argv(
    operation: str,
    capability: str,
    scratch: Path | None = None,
    channel: Path | None = None,
) -> list[str]:
    """Build the Claude Code argv passed to the user's unchanged function."""
    if capability not in {"readonly", "workspace_write"}:
        raise ProviderError("unauthorized_role", "unknown provider capability")
    if operation not in OPERATIONS:
        raise ProviderError("unauthorized_role", "unknown provider operation")
    args = ["-p", "--output-format", "stream-json", "--verbose"]
    if capability == "readonly":
        args.extend(
            [
                "--permission-mode",
                "plan",
                "--tools",
                "Read,Glob,Grep",
                "--allowedTools",
                "Read,Glob,Grep",
                "--disallowedTools",
                "Write,Edit,MultiEdit,NotebookEdit,Bash,WebFetch,WebSearch,Task,Agent",
            ]
        )
    else:
        args.extend(
            [
                "--permission-mode",
                "acceptEdits",
                "--tools",
                "Read,Write,Edit,Glob,Grep,Bash",
                "--allowedTools",
                "Read,Write,Edit,Glob,Grep,Bash",
                "--disallowedTools",
                "MultiEdit,NotebookEdit,WebFetch,WebSearch,Task,Agent",
            ]
        )
        if scratch is not None:
            args.extend(["--add-dir", str(scratch)])
        if channel is not None:
            args.extend(["--add-dir", str(channel)])
    args.extend(
        [
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--disable-slash-commands",
            "--no-session-persistence",
        ]
    )
    return args


def bwrap_executable() -> str | None:
    return shutil.which("bwrap")


ISOLATION_PROBE_PAYLOAD = b"C1FD-OK"


def _isolation_probe_command(bwrap: str, control_fd: int) -> list[str]:
    return [
        bwrap,
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        bash_executable(),
        "-c",
        'builtin printf %s "$2" >&"$1"',
        "c-probe",
        str(int(control_fd)),
        ISOLATION_PROBE_PAYLOAD.decode("ascii"),
    ]


def isolation_status() -> tuple[bool, str | None]:
    """Probe namespaces and ordinary inherited-descriptor preservation.

    The wrapper capture handshake needs an inherited descriptor to survive
    bubblewrap into the sandboxed command, so isolation is only usable when the
    probe proves both namespace creation and descriptor inheritance.  This is
    the same mechanism as the real transport; no ``--sync-fd`` is involved.
    """
    bwrap = bwrap_executable()
    if not bwrap:
        return False, "bubblewrap (bwrap) is not installed"
    try:
        parent_control, child_control = socket.socketpair()
    except OSError:
        return False, "the isolation probe control channel could not be created"
    control_fd = child_control.fileno()
    completed: subprocess.CompletedProcess[bytes] | None = None
    try:
        completed = subprocess.run(
            _isolation_probe_command(bwrap, control_fd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            pass_fds=(control_fd,),
        )
    except (OSError, subprocess.TimeoutExpired):
        parent_control.close()
        return False, "bubblewrap isolation probe could not execute"
    finally:
        child_control.close()
    if completed.returncode != 0:
        parent_control.close()
        return (
            False,
            "bubblewrap cannot create the required isolated namespaces "
            f"(exit {completed.returncode})",
        )
    try:
        parent_control.settimeout(2.0)
        received = parent_control.recv(len(ISOLATION_PROBE_PAYLOAD) + 1)
    except (OSError, socket.timeout):
        received = b""
    finally:
        parent_control.close()
    if received != ISOLATION_PROBE_PAYLOAD:
        return (
            False,
            "bubblewrap does not preserve an ordinary inherited communication "
            "descriptor",
        )
    return True, None


def _protection_parts(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or not value:
        raise ProviderError(
            "isolation_unavailable", f"{label} must be a workspace-relative path"
        )
    if "\x00" in value or value.startswith("/") or "\\" in value:
        raise ProviderError(
            "isolation_unavailable", f"{label} must be a relative path"
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ProviderError(
            "isolation_unavailable", f"{label} must not escape the workspace"
        )
    if parts[0] == ".git":
        raise ProviderError(
            "isolation_unavailable", f"{label} must not target Git metadata"
        )
    return parts


def _protection_entry(
    workspace_real: Path,
    parts: list[str],
    label: str,
    *,
    expected_kind: str | None = None,
) -> dict[str, Any]:
    current = workspace_real
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError as exc:
            raise ProviderError(
                "isolation_unavailable", f"{label} does not exist"
            ) from exc
        except OSError as exc:
            raise ProviderError(
                "isolation_unavailable", f"{label} cannot be inspected: {exc}"
            ) from exc
        if stat_is_symlink(info.st_mode):
            raise ProviderError(
                "isolation_unavailable",
                f"{label} traverses or names a symlink, which cannot be pinned safely",
            )
        if index < len(parts) - 1 and not stat_is_dir(info.st_mode):
            raise ProviderError(
                "isolation_unavailable", f"{label} has a non-directory ancestor"
            )
    is_directory = stat_is_dir(info.st_mode)
    is_file = stat_is_file(info.st_mode)
    if not is_directory and not is_file:
        raise ProviderError(
            "isolation_unavailable",
            f"{label} is not a regular file or directory",
        )
    kind = "directory" if is_directory else "file"
    if expected_kind is not None and kind != expected_kind:
        raise ProviderError(
            "isolation_unavailable", f"{label} changed type before protection"
        )
    return {
        "path": "/".join(parts),
        "absolute": str(current),
        "kind": kind,
        "dev": info.st_dev,
        "ino": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
    }


def stat_is_symlink(mode: int) -> bool:
    return stat.S_ISLNK(mode)


def stat_is_dir(mode: int) -> bool:
    return stat.S_ISDIR(mode)


def stat_is_file(mode: int) -> bool:
    return stat.S_ISREG(mode)


class _NormalizedProtection(dict):
    """Private marker for a plan that passed C's typed validation.

    Serialized or caller-supplied mappings can never instantiate this class,
    so a forged ``plan_sha256`` key cannot bypass normalization.
    """

    __slots__ = ()


def normalize_protection(
    workspace: Path,
    protection: Mapping[str, Any] | None,
    *,
    capability: str,
    scratch: Path | None = None,
    channel: Path | None = None,
    git_dir: Path | None = None,
    git_common_dir: Path | None = None,
) -> dict[str, Any] | None:
    """Validate typed D1 protection inputs and normalize their mount order.

    The caller supplies only repository-relative original-user roots and the
    normal-directory ancestors that must stay pinned.  C is the sole authority
    for the resulting absolute mount plan, ordering and evidence.  Symlinked,
    special, escaping or Git/metadata-colliding paths are refused rather than
    resolved.
    """
    if protection is None:
        return None
    if not isinstance(protection, Mapping):
        raise ProviderError(
            "isolation_unavailable", "protected execution inputs must be an object"
        )
    if set(protection) != {
        "version",
        "manifest_sha256",
        "roots",
        "anchors",
    }:
        raise ProviderError(
            "isolation_unavailable",
            "protected execution inputs have an unsupported schema",
        )
    if protection.get("version") != PROTECTION_INPUT_VERSION:
        raise ProviderError(
            "isolation_unavailable",
            "protected execution input version is not supported",
        )
    manifest = protection.get("manifest_sha256")
    if not isinstance(manifest, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest):
        raise ProviderError(
            "isolation_unavailable",
            "protected execution input has no valid manifest digest",
        )
    workspace_text = str(workspace)
    workspace_real = Path(os.path.realpath(workspace))
    if str(workspace_real) == "/":
        raise ProviderError(
            "isolation_unavailable", "the repository root cannot be protected"
        )
    if workspace_text != str(workspace_real):
        raise ProviderError(
            "isolation_unavailable",
            "protected execution requires the canonical workspace path",
        )
    roots_raw = protection.get("roots")
    anchors_raw = protection.get("anchors")
    if not isinstance(roots_raw, list) or not isinstance(anchors_raw, list):
        raise ProviderError(
            "isolation_unavailable",
            "protected execution roots and anchors must be arrays",
        )
    if len(roots_raw) > MAX_PROTECTION_ROOTS:
        raise ProviderError(
            "isolation_unavailable",
            f"protected execution exceeds {MAX_PROTECTION_ROOTS} roots",
        )
    if len(anchors_raw) > MAX_PROTECTION_ANCHORS:
        raise ProviderError(
            "isolation_unavailable",
            f"protected execution exceeds {MAX_PROTECTION_ANCHORS} anchors",
        )
    if capability == "readonly" and anchors_raw:
        raise ProviderError(
            "isolation_unavailable",
            "readonly capability cannot accept writable ancestor anchors",
        )
    roots: list[dict[str, Any]] = []
    for index, raw in enumerate(roots_raw):
        label = f"protected root {index}"
        if not isinstance(raw, Mapping) or set(raw) != {"path", "kind"}:
            raise ProviderError(
                "isolation_unavailable",
                f"{label} has an unsupported schema",
            )
        kind = raw.get("kind")
        if kind not in {"file", "directory"}:
            raise ProviderError(
                "isolation_unavailable", f"{label} has an unsupported kind"
            )
        entry = _protection_entry(
            workspace_real,
            _protection_parts(raw.get("path"), label),
            label,
            expected_kind=kind,
        )
        entry["declared_kind"] = kind
        roots.append(entry)
    anchors: list[dict[str, Any]] = []
    seen_anchors: set[str] = set()
    for index, raw in enumerate(anchors_raw):
        label = f"ancestor anchor {index}"
        if not isinstance(raw, Mapping) or set(raw) != {"path"}:
            raise ProviderError(
                "isolation_unavailable",
                f"{label} has an unsupported schema",
            )
        entry = _protection_entry(
            workspace_real,
            _protection_parts(raw.get("path"), label),
            label,
            expected_kind="directory",
        )
        if entry["absolute"] in seen_anchors:
            raise ProviderError(
                "isolation_unavailable", f"{label} is duplicated"
            )
        seen_anchors.add(entry["absolute"])
        anchors.append(entry)
    root_paths = [entry["path"] for entry in roots]
    if len(set(root_paths)) != len(root_paths):
        raise ProviderError(
            "isolation_unavailable", "protected roots repeat a path"
        )
    root_absolute = {entry["absolute"] for entry in roots}
    directory_roots = [
        entry["absolute"] for entry in roots if entry["kind"] == "directory"
    ]
    for root in root_paths:
        for other in root_paths:
            if root == other:
                continue
            if root.startswith(other + "/"):
                raise ProviderError(
                    "isolation_unavailable",
                    "protected roots are nested; refine them before protection",
                )
    for anchor in anchors:
        absolute = anchor["absolute"]
        if absolute in root_absolute:
            raise ProviderError(
                "isolation_unavailable",
                "an ancestor anchor collides with a protected root",
            )
        for root in directory_roots:
            if absolute.startswith(root.rstrip("/") + "/"):
                raise ProviderError(
                    "isolation_unavailable",
                    "an ancestor anchor is inside a protected read-only root",
                )
        if not any(
            root.startswith(anchor["path"] + "/") for root in root_paths
        ):
            raise ProviderError(
                "isolation_unavailable",
                "an ancestor anchor does not pin any protected path",
            )
    for path, label in (
        (workspace_real / ".git", "Git marker"),
        (
            Path(os.path.realpath(git_dir)) if git_dir is not None else None,
            "Git administrative directory",
        ),
        (
            Path(os.path.realpath(git_common_dir))
            if git_common_dir is not None
            else None,
            "Git common directory",
        ),
    ):
        if path is None:
            continue
        path_text = str(path)
        for entry in roots + anchors:
            absolute = entry["absolute"]
            if absolute == path_text or absolute.startswith(
                path_text.rstrip("/") + "/"
            ):
                raise ProviderError(
                    "isolation_unavailable",
                    f"protected execution collides with the {label}",
                )
            if path_text.startswith(absolute.rstrip("/") + "/") and entry in roots:
                raise ProviderError(
                    "isolation_unavailable",
                    f"a protected root contains the {label}",
                )
    extra_argv_bytes = 0
    for entry in roots:
        raw = os.fsencode(entry["absolute"])
        extra_argv_bytes += len(b"--ro-bind") + 1 + 2 * (len(raw) + 1)
    for entry in anchors:
        raw = os.fsencode(entry["absolute"])
        extra_argv_bytes += len(b"--bind") + 1 + 2 * (len(raw) + 1)
    if extra_argv_bytes > MAX_EXTRA_MOUNT_ARGV_BYTES:
        raise ProviderError(
            "isolation_unavailable",
            "protected execution exceeds the encoded extra mount argv bound",
        )
    anchors.sort(key=lambda item: (item["path"].count("/"), item["path"]))
    roots.sort(key=lambda item: item["path"])
    normalized = _NormalizedProtection(
        {
            "version": PROTECTION_INPUT_VERSION,
            "manifest_sha256": manifest,
            "capability": capability,
            "workspace": workspace_text,
            "roots": roots,
            "anchors": anchors,
            "extra_mount_argv_bytes": extra_argv_bytes,
        }
    )
    normalized["plan_sha256"] = _protection_plan_sha256(normalized)
    return normalized


def _protection_mounts(
    normalized: Mapping[str, Any] | None,
    workspace_text: str,
    *,
    capability: str,
    scratch: Path | None,
    channel: Path | None,
    git_paths: list[str],
) -> list[list[str]]:
    entries: list[list[str]] = [
        ["ro-bind", "/", "/"],
        ["dev", "/dev"],
        ["proc", "/proc"],
    ]
    if normalized is None:
        if capability == "workspace_write":
            if scratch is None or channel is None:
                raise ProviderError(
                    "isolation_unavailable",
                    "writer scratch and channel paths are required",
                )
            entries.append(["bind", workspace_text, workspace_text])
            entries.extend(
                ["ro-bind", path, path] for path in git_paths
            )
            entries.extend(
                [
                    ["bind", str(scratch), str(scratch)],
                    ["bind", str(channel), str(channel)],
                ]
            )
        return entries
    if capability == "workspace_write":
        if scratch is None or channel is None:
            raise ProviderError(
                "isolation_unavailable",
                "writer scratch and channel paths are required",
            )
        entries.append(["bind", workspace_text, workspace_text])
        entries.extend(
            ["bind", entry["absolute"], entry["absolute"]]
            for entry in normalized["anchors"]
        )
        entries.extend(["ro-bind", path, path] for path in git_paths)
        entries.extend(
            ["ro-bind", entry["absolute"], entry["absolute"]]
            for entry in normalized["roots"]
        )
        entries.append(["bind", str(scratch), str(scratch)])
        entries.append(["bind", str(channel), str(channel)])
    else:
        entries.extend(
            ["ro-bind", entry["absolute"], entry["absolute"]]
            for entry in normalized["roots"]
        )
    return entries


def _protection_plan_sha256(normalized: Mapping[str, Any]) -> str:
    plan = {
        "version": normalized["version"],
        "manifest_sha256": normalized["manifest_sha256"],
        "capability": normalized["capability"],
        "workspace": normalized["workspace"],
        "roots": [
            {"path": entry["path"], "kind": entry["kind"]}
            for entry in normalized["roots"]
        ],
        "anchors": [entry["path"] for entry in normalized["anchors"]],
        "extra_mount_argv_bytes": normalized["extra_mount_argv_bytes"],
    }
    return hashlib.sha256(_canonical_bytes(plan)).hexdigest()


def _git_custody_paths(
    workspace_text: str,
    git_dir: Path | None,
    git_common_dir: Path | None,
) -> list[str]:
    protected: list[str] = []
    git_marker = Path(workspace_text) / ".git"
    if os.path.lexists(git_marker):
        protected.append(str(git_marker))
    for path in (git_dir, git_common_dir):
        if path is not None:
            text = str(path)
            if text not in protected:
                protected.append(text)
    return protected


def bwrap_command(
    workspace: Path,
    capability: str,
    shell_argv: list[str],
    *,
    scratch: Path | None = None,
    channel: Path | None = None,
    git_dir: Path | None = None,
    git_common_dir: Path | None = None,
    protection: Mapping[str, Any] | None = None,
) -> list[str]:
    bwrap = bwrap_executable()
    if not bwrap:
        raise ProviderError("isolation_unavailable", SAFE_ISOLATION_ERROR)
    workspace_text = str(workspace)
    if workspace_text == "/":
        raise ProviderError(
            "isolation_unavailable", "the repository root cannot be isolated as a workspace"
        )
    if protection is not None and not isinstance(
        protection, _NormalizedProtection
    ):
        # A raw mapping is always revalidated here, even if it claims a
        # plan_sha256 marker; the private class cannot be forged from JSON.
        protection = normalize_protection(
            workspace,
            protection,
            capability=capability,
            scratch=scratch,
            channel=channel,
            git_dir=git_dir,
            git_common_dir=git_common_dir,
        )
    git_paths = _git_custody_paths(
        workspace_text, git_dir, git_common_dir
    )
    command = [
        bwrap,
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
    ]
    command.extend(
        entry for mount in _protection_mounts(
            protection,
            workspace_text,
            capability=capability,
            scratch=scratch,
            channel=channel,
            git_paths=git_paths,
        ) for entry in (["--" + mount[0], *mount[1:]])
    )
    command.extend(["--chdir", workspace_text])
    command.extend(shell_argv)
    return command


def probe_provider(
    profile: Mapping[str, Any],
    timeout_seconds: float = 20,
    *,
    workspace: Path | None = None,
) -> tuple[bool, str | None]:
    """Availability-only probe in the configured interactive Bash context.

    Reserved-provider startup is never executed unconfined: bubblewrap
    establishes the read-only root before the rcfile is loaded, and the probe
    unshares the network namespace so an availability check cannot reach a
    provider model or consume quota.  The function itself is only inspected
    with ``declare -F``; no provider dispatch occurs.

    The boolean/reason tuple is unchanged.  The reason distinguishes three
    failure categories without surfacing captured startup output: the probe
    script's explicit missing-function exit marker, a bounded timeout, and a
    pre-start isolation/Bash-startup failure where bubblewrap or Bash never
    reached the probe script.
    """
    name = profile.get("provider")
    if not is_reserved_provider(name):
        return False, "not a reserved provider"
    bwrap = bwrap_executable()
    if not bwrap:
        return False, "bubblewrap (bwrap) is required for availability probes"
    shell = [bash_executable()]
    rcfile = profile.get("provider_rcfile")
    if rcfile:
        shell.extend(["--rcfile", str(rcfile)])
    shell.extend(["-ic", PROBE_SCRIPT, "c-probe", str(name)])
    command = [
        bwrap,
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
    ]
    if workspace is not None:
        workspace_path = Path(workspace).expanduser()
        if workspace_path.is_dir() and not workspace_path.is_symlink():
            command.extend(["--chdir", str(workspace_path.resolve())])
    command.extend(shell)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, PROBE_TIMEOUT_REASON
    except OSError:
        return False, PROBE_EXECUTION_REASON
    if completed.returncode == 0:
        return True, None
    if completed.returncode == PROBE_MISSING_FUNCTION_EXIT:
        return False, PROBE_MISSING_FUNCTION_REASON
    # bubblewrap can fail before the probe script runs (for example a
    # restricted ancestor making --chdir fail with EACCES), and Bash startup
    # can fail while loading the rcfile.  Neither proves the function absent.
    return False, PROBE_STARTUP_FAILURE_REASON


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_path_layout(
    workspace: Path,
    job_dir: Path,
    scratch: Path,
    channel: Path,
    protected_paths: Iterable[Path],
) -> None:
    """C-owned canonical path and symlink-escape validation."""
    workspace_real = Path(os.path.realpath(workspace))
    job_real = Path(os.path.realpath(job_dir))
    scratch_real = Path(os.path.realpath(scratch))
    channel_real = Path(os.path.realpath(channel))
    if str(workspace_real) == "/":
        raise ProviderError(
            "isolation_unavailable", "the repository root cannot be a provider workspace"
        )
    for path in (job_dir, scratch, channel):
        if path.is_symlink():
            raise ProviderError(
                "isolation_unavailable", "provider job paths must not be symlinks"
            )
    if not _is_within(scratch_real, job_real) or not _is_within(
        channel_real, job_real
    ):
        raise ProviderError(
            "isolation_unavailable",
            "provider scratch and channel paths must stay inside the job directory",
        )
    if job_real == workspace_real or _is_within(job_real, workspace_real):
        raise ProviderError(
            "isolation_unavailable",
            "the provider job directory must stay outside the writable workspace",
        )
    for protected in protected_paths:
        protected_real = Path(os.path.realpath(protected))
        if protected_real == workspace_real or _is_within(
            protected_real, workspace_real
        ):
            raise ProviderError(
                "isolation_unavailable",
                "coordinator or credential state must stay outside the writable workspace",
            )


def _close(fd: int | None) -> None:
    if fd is None or fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _terminate_group(pid: int, force: bool = False) -> None:
    try:
        os.killpg(pid, signal.SIGKILL if force else signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass


class _CaptureControlInterrupted(Exception):
    """Run control won over capture completion before the acknowledgement.

    The whole-run deadline and an explicit cancellation outrank a missing,
    malformed or oversized capture: those failures stay
    ``credential_capture_unavailable`` only while the run is still live.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CaptureFramer:
    """Recognize capture records while ignoring tag-looking value bytes.

    The wrapper emits ``C1\\0name\\0definition\\0``, zero or more
    ``E\\0name\\0value\\0`` records, then one final ``END\\0``.  A legal
    environment value may itself end with ``END`` (for example ``BACKEND`` or
    ``END``), so a byte-suffix test is not a message boundary: it would end the
    capture in the middle of an environment record.  This framer consumes NUL
    fields incrementally and only treats ``END`` as a terminator when it is in
    tag position.
    """

    __slots__ = ("_scan", "_remaining", "_terminated", "_malformed")

    def __init__(self) -> None:
        self._scan = 0
        self._remaining = 0
        self._terminated = False
        self._malformed = False

    @property
    def terminated(self) -> bool:
        return self._terminated

    @property
    def malformed(self) -> bool:
        return self._malformed

    def feed(self, data: bytearray) -> bool:
        """Consume complete fields from the growing buffer.

        Returns true when the stream terminated or became malformed; callers
        stop reading either way and let the parser produce a fixed error.
        """
        if self._terminated or self._malformed:
            return True
        while True:
            end = data.find(b"\x00", self._scan)
            if end < 0:
                return False
            field = bytes(data[self._scan : end])
            self._scan = end + 1
            if self._remaining:
                self._remaining -= 1
                continue
            if field == b"END":
                self._terminated = True
                return True
            if field in (b"C1", b"E"):
                self._remaining = 2
            elif field == b"ERR":
                self._remaining = 1
            else:
                self._malformed = True
                return True


def _read_capture(
    fd: int,
    limit: int,
    deadline: float,
    process: subprocess.Popen[Any],
    cancel_marker: Path | None = None,
) -> tuple[bytes, bool]:
    data = bytearray()
    truncated = False
    framer = CaptureFramer()
    while not framer.feed(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # Check the deadline before cancellation so a simultaneous
            # deadline and cancel request deterministically classifies as
            # timeout, matching the worker's state precedence.
            raise _CaptureControlInterrupted("timeout")
        if cancel_marker is not None and cancel_marker.exists():
            raise _CaptureControlInterrupted("cancelled")
        try:
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.1))
        except (OSError, ValueError):
            break
        if not ready:
            if process.poll() is not None:
                # EOF (closed write descriptor) is reported as readable, so a
                # non-ready descriptor after process exit means the capture is
                # already complete or the shell failed before writing.
                break
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        available = limit - len(data)
        if available > 0:
            data.extend(chunk[:available])
        if len(chunk) > available:
            truncated = True
            break
    return bytes(data), truncated


def _reader_loop(fd: int, buffer: CaptureBuffer) -> None:
    try:
        while True:
            try:
                chunk = os.read(fd, 65536)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            buffer.feed(chunk)
    finally:
        _close(fd)


class ProviderRun:
    __slots__ = (
        "exit_code",
        "timed_out",
        "cancelled",
        "scope_violations",
        "stdout",
        "stderr",
        "stdout_total",
        "stderr_total",
        "stdout_truncated",
        "stderr_truncated",
        "result",
        "error",
        "child_pid",
        "capture_error",
    )

    def __init__(
        self,
        *,
        exit_code: int,
        timed_out: bool,
        cancelled: bool,
        scope_violations: list[str],
        stdout: bytes,
        stderr: bytes,
        stdout_total: int,
        stderr_total: int,
        stdout_truncated: bool,
        stderr_truncated: bool,
        result: dict[str, Any],
        error: dict[str, str] | None,
        child_pid: int | None,
        capture_error: dict[str, str] | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.cancelled = cancelled
        self.scope_violations = scope_violations
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_total = stdout_total
        self.stderr_total = stderr_total
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated
        self.result = result
        self.error = error
        self.child_pid = child_pid
        self.capture_error = capture_error


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _safe_message_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def classify_failure(text: bytes | str, exit_code: int) -> ProviderError:
    if isinstance(text, bytes):
        decoded = text.decode("utf-8", errors="replace")
    else:
        decoded = str(text)
    folded = decoded.casefold()
    if exit_code == 127 or "command not found" in folded:
        return ProviderError(
            "provider_unavailable", "the provider command was not available"
        )
    if any(
        marker in folded
        for marker in (
            "401",
            "403",
            "unauthorized",
            "authentication",
            "not authenticated",
            "invalid api key",
            "invalid x-api-key",
            "api key is invalid",
            "please log in",
        )
    ):
        return ProviderError(
            "auth_failed", "the provider reported an authentication failure"
        )
    if any(
        marker in folded
        for marker in (
            "429",
            "rate limit",
            "rate_limit",
            "too many requests",
            "overloaded",
        )
    ):
        return ProviderError(
            "rate_limited", "the provider reported rate limiting"
        )
    if any(
        marker in folded
        for marker in (
            "402",
            "quota",
            "insufficient balance",
            "insufficient_quota",
            "credit balance",
            "billing",
            "payment required",
        )
    ):
        return ProviderError(
            "quota_exceeded", "the provider reported exhausted quota or credit"
        )
    return ProviderError("execution_failed", "the provider execution failed")


def _payload_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProviderError("invalid_output", f"{label} must be a non-empty string")
    if len(value.encode("utf-8", errors="replace")) > MAX_PAYLOAD_TEXT:
        raise ProviderError("output_limit", f"{label} exceeds the size limit")
    if "\x00" in value:
        raise ProviderError("invalid_output", f"{label} contains a NUL byte")
    return value


def _payload_text_list(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ProviderError(
            "invalid_output", f"{label} must be a non-empty array of strings"
        )
    if len(value) > MAX_PAYLOAD_ITEMS:
        raise ProviderError("output_limit", f"{label} has too many entries")
    result: list[str] = []
    for item in value:
        result.append(_payload_text(item, f"{label} entry"))
    return result


def _exact_payload_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderError("invalid_output", f"{label} must be a JSON object")
    if set(value) != keys:
        raise ProviderError(
            "invalid_output",
            f"{label} must contain exactly: {', '.join(sorted(keys))}",
        )
    return value


def _changed_path(value: Any, label: str) -> str:
    text = _payload_text(value, label)
    if "\x00" in text or text.startswith("/") or "\\" in text:
        raise ProviderError(
            "invalid_output", f"{label} must be a relative repository path"
        )
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ProviderError(
            "invalid_output", f"{label} must not escape the workspace"
        )
    return text


def validate_payload(operation: str, payload: Any) -> dict[str, Any]:
    if operation == "proposal":
        value = _exact_payload_keys(
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
            "proposal payload",
        )
        return {
            "approach": _payload_text(value["approach"], "proposal.approach"),
            "rationale": _payload_text(value["rationale"], "proposal.rationale"),
            "assumptions": _payload_text_list(
                value["assumptions"], "proposal.assumptions"
            ),
            "problems": _payload_text_list(
                value["problems"], "proposal.problems"
            ),
            "alternatives": _payload_text_list(
                value["alternatives"], "proposal.alternatives"
            ),
            "feasibility": _payload_text(
                value["feasibility"], "proposal.feasibility"
            ),
            "testing": _payload_text_list(value["testing"], "proposal.testing"),
        }
    if operation == "cross_examination":
        value = _exact_payload_keys(
            payload,
            {"objections", "responses", "revisions"},
            "cross-examination payload",
        )
        objections = value["objections"]
        if not isinstance(objections, list):
            raise ProviderError(
                "invalid_output", "cross-examination.objections must be an array"
            )
        if len(objections) > MAX_PAYLOAD_ITEMS:
            raise ProviderError(
                "output_limit", "cross-examination.objections has too many entries"
            )
        normalized_objections: list[dict[str, str]] = []
        for item in objections:
            if isinstance(item, str):
                normalized_objections.append(
                    {
                        "objection": _payload_text(
                            item, "cross-examination objection"
                        )
                    }
                )
                continue
            if not isinstance(item, dict) or "objection" not in item:
                raise ProviderError(
                    "invalid_output",
                    "cross-examination objections must contain objection and optional severity",
                )
            if set(item) - {"objection", "severity"}:
                raise ProviderError(
                    "invalid_output",
                    "cross-examination objections may contain only objection and severity",
                )
            normalized: dict[str, str] = {
                "objection": _payload_text(
                    item["objection"], "cross-examination objection"
                )
            }
            severity = item.get("severity")
            if severity is not None:
                if severity not in {"low", "medium", "high"}:
                    raise ProviderError(
                        "invalid_output",
                        "cross-examination severity must be low, medium, or high",
                    )
                normalized["severity"] = severity
            normalized_objections.append(normalized)
        return {
            "objections": normalized_objections,
            "responses": _payload_text_list(
                value["responses"], "cross-examination.responses"
            ),
            "revisions": _payload_text_list(
                value["revisions"], "cross-examination.revisions"
            ),
        }
    if operation == "consensus":
        value = _exact_payload_keys(
            payload,
            {"decision", "candidate_sha256", "rationale"},
            "consensus payload",
        )
        decision = value["decision"]
        if decision not in {"AGREE", "DISAGREE", "NEEDS_DISCUSSION"}:
            raise ProviderError(
                "invalid_output",
                "consensus.decision must be AGREE, DISAGREE, or NEEDS_DISCUSSION",
            )
        digest = value["candidate_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ProviderError(
                "invalid_output",
                "consensus.candidate_sha256 must be a lowercase SHA-256 digest",
            )
        return {
            "decision": decision,
            "candidate_sha256": digest,
            "rationale": _payload_text(value["rationale"], "consensus.rationale"),
        }
    if operation in WRITER_OPERATIONS:
        value = _exact_payload_keys(
            payload,
            {
                "changed_paths",
                "validation_commands",
                "validation_outcomes",
                "remaining_issues",
            },
            f"{operation} payload",
        )
        changed = value["changed_paths"]
        if not isinstance(changed, list):
            raise ProviderError(
                "invalid_output", f"{operation}.changed_paths must be an array"
            )
        if len(changed) > MAX_PAYLOAD_ITEMS:
            raise ProviderError(
                "output_limit", f"{operation}.changed_paths has too many entries"
            )
        return {
            "changed_paths": [
                _changed_path(item, f"{operation}.changed_paths entry")
                for item in changed
            ],
            "validation_commands": _payload_text_list(
                value["validation_commands"],
                f"{operation}.validation_commands",
            ),
            "validation_outcomes": _payload_text_list(
                value["validation_outcomes"],
                f"{operation}.validation_outcomes",
            ),
            "remaining_issues": _payload_text_list(
                value["remaining_issues"],
                f"{operation}.remaining_issues",
                allow_empty=True,
            ),
        }
    raise ProviderError("unauthorized_role", "operation is not supported")


def _extract_payload_text(result_text: str) -> str:
    text = result_text.strip()
    if not text:
        raise ProviderError("invalid_output", "the completion result is empty")
    if len(text.encode("utf-8", errors="replace")) > MAX_RESULT_TEXT_BYTES:
        raise ProviderError(
            "output_limit", "the completion result exceeds the size limit"
        )
    if text.startswith("```"):
        match = re.fullmatch(
            r"```(?:json)?[ \t]*\n(.*)\n```", text, flags=re.DOTALL
        )
        if not match:
            raise ProviderError(
                "invalid_output",
                "the completion result fence is malformed",
            )
        text = match.group(1).strip()
    return text


PROVIDER_RESULT_CONTRACT = """# C provider result contract

The Claude completion `result` field must contain exactly one JSON object (optionally inside
one ```json fence) with this shape and no extra text:

{{"result_version": 1, "operation": "{operation}", "payload": <payload>}}

Payload for this operation:

- proposal: `{{"approach": str, "rationale": str, "assumptions": [str], "problems": [str],
  "alternatives": [str], "feasibility": str, "testing": [str]}}`
- cross_examination: `{{"objections": [{{"objection": str, "severity": "low|medium|high"}}],
  "responses": [str], "revisions": [str]}}`
- consensus: `{{"decision": "AGREE|DISAGREE|NEEDS_DISCUSSION", "candidate_sha256": <64 lowercase hex>,
  "rationale": str}}`
- implementation/repair: `{{"changed_paths": [relative str], "validation_commands": [str],
  "validation_outcomes": [str], "remaining_issues": [str]}}`

A valid Claude `result` envelope with `subtype: "success"` and `is_error: false` is required;
exit status alone is not evidence. Do not include credentials, environment values, or extra keys.
"""


def provider_contract(operation: str) -> str:
    if operation not in OPERATIONS:
        raise ProviderError("unauthorized_role", "unknown provider operation")
    return PROVIDER_RESULT_CONTRACT.format(operation=operation)


def validate_completion(
    stdout: bytes, operation: str, context: bytes = b""
) -> dict[str, Any]:
    """Validate exactly one successful Claude envelope and one role payload."""
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderError(
            "invalid_output", "provider stdout is not valid UTF-8"
        ) from exc
    result_events: list[dict[str, Any]] = []
    saw_content = False
    for line in text.splitlines():
        if not line.strip():
            continue
        saw_content = True
        if len(line.encode("utf-8", errors="replace")) > MAX_OUTPUT_LINE_BYTES:
            raise ProviderError("output_limit", "a provider output line is oversized")
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProviderError(
                "invalid_output", "provider stdout is not a valid JSON stream"
            ) from exc
        if not isinstance(event, dict):
            raise ProviderError(
                "invalid_output", "provider stdout contains a non-object event"
            )
        if event.get("type") == "result":
            result_events.append(event)
    if not saw_content:
        raise ProviderError("invalid_output", "provider stdout is empty")
    if len(result_events) != 1:
        raise ProviderError(
            "invalid_output",
            "provider stdout must contain exactly one completion envelope",
        )
    envelope = result_events[0]
    if envelope.get("is_error") is not False or envelope.get("subtype") != "success":
        combined = str(envelope.get("result") or "").encode(
            "utf-8", errors="replace"
        )
        raise classify_failure(combined + b"\n" + context, 1)
    result_text = envelope.get("result")
    if not isinstance(result_text, str) or not result_text.strip():
        raise ProviderError(
            "invalid_output", "the completion envelope has no non-empty result"
        )
    json_text = _extract_payload_text(result_text)
    if len(json_text.encode("utf-8", errors="replace")) > MAX_PAYLOAD_BYTES:
        raise ProviderError("output_limit", "the operation payload exceeds the size limit")
    try:
        document = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ProviderError(
            "invalid_output", "the completion result is not valid JSON"
        ) from exc
    document = _exact_payload_keys(
        document,
        {"result_version", "operation", "payload"},
        "provider result",
    )
    version = document["result_version"]
    if type(version) is not int or version != RESULT_VERSION:
        raise ProviderError(
            "invalid_output", "the provider result version is not supported"
        )
    if document["operation"] != operation:
        raise ProviderError(
            "invalid_output",
            "the provider result operation does not match the bound operation",
        )
    payload = validate_payload(operation, document["payload"])
    payload_sha256 = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    summary: dict[str, Any] = {
        "subtype": "success",
        "is_error": False,
        "num_turns": envelope.get("num_turns"),
        "duration_ms": envelope.get("duration_ms"),
        "duration_api_ms": envelope.get("duration_api_ms"),
        "session_id": envelope.get("session_id"),
        "total_cost_usd": envelope.get("total_cost_usd"),
        "usage": envelope.get("usage"),
    }
    return {
        "envelope": summary,
        "payload": payload,
        "payload_sha256": payload_sha256,
    }


def sanitize_structure(redactor: Redactor, value: Any) -> Any:
    """Sanitize every string (including keys) in a decoded JSON structure.

    Wire-level redaction handles nested JSON escapes; this second pass applies
    the same redactor to the decoded values that are about to be persisted so
    no decoded credential survives in the normalized result even if a provider
    used an escaping spelling outside the bounded wire variants.
    """
    if isinstance(value, str):
        return redactor.sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_structure(redactor, item) for item in value]
    if isinstance(value, dict):
        return {
            (
                redactor.sanitize_text(key)
                if isinstance(key, str)
                else key
            ): sanitize_structure(redactor, item)
            for key, item in value.items()
        }
    return value


def _sanitized_diagnostic_tail(data: bytes) -> str | None:
    if not data:
        return None
    tail = data[-MAX_DIAGNOSTIC_TAIL:]
    return tail.decode("utf-8", errors="replace")


def _read_confinement_status(
    fd: int,
    deadline: float,
    cancel_marker: Path | None = None,
) -> tuple[bytes | None, str | None]:
    data = bytearray()
    while b"\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # The whole-run deadline is authoritative over a missing status,
            # matching the canonical timeout-before-cancel precedence.
            return None, "timeout"
        if cancel_marker is not None and cancel_marker.exists():
            return None, "cancelled"
        try:
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.1))
        except (OSError, ValueError):
            return None, "the confinement status channel was unreadable"
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return None, "the confinement status channel was unreadable"
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_CONFINEMENT_STATUS_BYTES:
            return None, "the confinement status exceeded its size bound"
    if not data:
        return None, "the confinement status channel closed without evidence"
    return bytes(data).split(b"\n", 1)[0], None


def _confinement_evidence(
    normalized: Mapping[str, Any],
    command: list[str],
    application: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "version": 1,
        "manifest_sha256": normalized["manifest_sha256"],
        "plan_sha256": normalized["plan_sha256"],
        "capability": normalized["capability"],
        "counts": {
            "protected_roots": len(normalized["roots"]),
            "ancestor_anchors": len(normalized["anchors"]),
            "extra_mount_argv_bytes": normalized["extra_mount_argv_bytes"],
        },
        "bwrap_argv_sha256": hashlib.sha256(
            _canonical_bytes(list(command))
        ).hexdigest(),
        "application": dict(application),
    }


def run_provider(
    *,
    profile: Mapping[str, Any],
    binding: Mapping[str, Any],
    workspace: Path,
    job_dir: Path,
    prompt_file: Path,
    timeout_seconds: float,
    cancel_marker: Path,
    scratch: Path,
    channel: Path,
    protected_paths: Iterable[Path] = (),
    git_dir: Path | None = None,
    git_common_dir: Path | None = None,
    on_spawn: Callable[[int], None] | None = None,
    on_heartbeat: Callable[[dict[str, Any]], None] | None = None,
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    scope_check: Callable[[], list[str]] | None = None,
    protection: Mapping[str, Any] | None = None,
) -> ProviderRun:
    """Run one reserved provider under bwrap and return sanitized evidence.

    ``protection`` is the optional typed D1 seam: workspace-relative original
    protected-user roots and their normal-directory ancestor anchors.  Empty
    defaults preserve the historical argv exactly.  When roots are declared, C
    runs a read-only/mount-identity self-check inside the claimed namespace
    before the provider rcfile is loaded and refuses to start the provider if
    the requested confinement was not actually applied.
    """
    operation = str(binding.get("operation"))
    capability = str(binding.get("capability"))
    if binding.get("provider") != profile.get("provider"):
        raise ProviderError("unauthorized_role", "profile and binding providers differ")
    provider_name = str(profile.get("provider"))
    expected_binding = build_binding(provider_name, profile, operation)
    if (
        expected_binding["capability"] != capability
        or expected_binding["binding_sha256"] != binding.get("binding_sha256")
    ):
        raise ProviderError(
            "unauthorized_role",
            "execution binding does not match the reserved capability table",
        )
    validate_path_layout(
        workspace, job_dir, scratch, channel, list(protected_paths)
    )
    rcfile = resolve_provider_rcfile(profile)
    workspace_real = Path(os.path.realpath(workspace))
    if rcfile is not None:
        rcfile_real = Path(os.path.realpath(rcfile))
        if rcfile_real == workspace_real or _is_within(
            rcfile_real, workspace_real
        ):
            raise ProviderError(
                "isolation_unavailable",
                "the provider rcfile must stay outside the writable workspace",
            )
    normalized_protection = normalize_protection(
        workspace,
        protection,
        capability=capability,
        scratch=scratch,
        channel=channel,
        git_dir=git_dir,
        git_common_dir=git_common_dir,
    )
    isolation_ok, isolation_reason = isolation_status()
    if not isolation_ok:
        error = ProviderError(
            "isolation_unavailable",
            isolation_reason or SAFE_ISOLATION_ERROR,
        )
        return ProviderRun(
            exit_code=127,
            timed_out=False,
            cancelled=False,
            scope_violations=[],
            stdout=b"",
            stderr=b"",
            stdout_total=0,
            stderr_total=0,
            stdout_truncated=False,
            stderr_truncated=False,
            result=_provider_result(
                binding,
                capture_error=error,
                exit_code=127,
                timed_out=False,
                cancelled=False,
                scope_violations=[],
                envelope=None,
                payload=None,
                payload_sha256=None,
                diagnostics={},
            ),
            error=error.as_dict(),
            child_pid=None,
            capture_error=error.as_dict(),
        )

    try:
        parent_control, child_control = socket.socketpair()
    except OSError as exc:
        raise ProviderError(
            "credential_capture_unavailable",
            "the private provider control channel could not be created",
        ) from exc
    # Ordinary inherited descriptor, not stdin and not --sync-fd: bubblewrap
    # preserves pass_fds descriptors for the sandboxed command, while a
    # descriptor named by --sync-fd belongs to bubblewrap and is closed before
    # the command runs.
    control_fd = child_control.fileno()
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    started = time.monotonic()
    deadline = started + max(1.0, float(timeout_seconds))
    process: subprocess.Popen[Any] | None = None
    stdout_buffer = MarkerCapture(MAX_STDOUT_BYTES, STDOUT_MARKER)
    stderr_buffer = MarkerCapture(MAX_STDERR_BYTES, STDERR_MARKER)
    stdout_thread: threading.Thread | None = None
    stderr_thread: threading.Thread | None = None
    capture_error: ProviderError | None = None
    timed_out = False
    cancelled = False
    scope_violations: list[str] = []
    exit_code = 127
    redactor = Redactor(())
    child_pid: int | None = None
    confinement: dict[str, Any] | None = None
    confinement_status_read: int | None = None
    confinement_status_write: int | None = None
    confinement_nonce: str | None = None
    confinement_status_line: bytes | None = None
    confinement_application: dict[str, Any] | None = None
    command: list[str] | None = None

    def capture_control_reason() -> str | None:
        # The deadline is authoritative before cancellation so a simultaneous
        # deadline and cancel request deterministically yields timeout, which
        # is also the worker's state precedence (timed out before cancelled).
        if time.monotonic() >= deadline:
            return "timeout"
        if cancel_marker.exists():
            return "cancelled"
        return None

    def apply_capture_control(reason: str) -> None:
        nonlocal capture_error, timed_out, cancelled
        # A control reason replaces any capture-layer failure: absent control,
        # missing/malformed/oversized captures remain capture errors.
        if reason == "timeout":
            timed_out = True
            capture_error = ProviderError(
                "timeout", "provider execution reached its timeout"
            )
        else:
            cancelled = True
            capture_error = ProviderError(
                "cancelled", "provider execution was cancelled"
            )

    try:
        try:
            provider_arguments = provider_argv(
                operation, capability, scratch, channel
            )
            shell_argv = shell_command(
                profile, prompt_file, control_fd, provider_arguments
            )
            payload_argv = shell_argv
            if (
                normalized_protection is not None
                and normalized_protection["roots"]
            ):
                checks = {
                    "workspace": str(workspace),
                    "roots": [
                        {
                            "path": entry["absolute"],
                            "kind": entry["kind"],
                        }
                        for entry in normalized_protection["roots"]
                    ],
                    "anchors": [
                        {"path": entry["absolute"]}
                        for entry in normalized_protection["anchors"]
                    ],
                    "scratch": str(scratch),
                    "channel": str(channel),
                    "git": _git_custody_paths(
                        str(workspace), git_dir, git_common_dir
                    ),
                }
                confinement_status_read, confinement_status_write = os.pipe()
                confinement_nonce = os.urandom(16).hex()
                payload_argv = [
                    bash_executable(),
                    "-c",
                    'exec "$0" "$@"',
                    sys.executable,
                    "-I",
                    "-c",
                    CONFINEMENT_CHECK_SCRIPT,
                    confinement_nonce,
                    str(confinement_status_write),
                    json.dumps(
                        checks, sort_keys=True, separators=(",", ":")
                    ),
                    *shell_argv,
                ]
            command = bwrap_command(
                workspace,
                capability,
                payload_argv,
                scratch=scratch,
                channel=channel,
                git_dir=git_dir,
                git_common_dir=git_common_dir,
                protection=normalized_protection,
            )
            pass_fds = [control_fd]
            if confinement_status_write is not None:
                pass_fds.append(confinement_status_write)
            process = subprocess.Popen(
                command,
                cwd=str(workspace),
                stdin=subprocess.DEVNULL,
                stdout=stdout_write,
                stderr=stderr_write,
                start_new_session=True,
                close_fds=True,
                pass_fds=tuple(pass_fds),
            )
            child_pid = process.pid
            if on_spawn is not None:
                on_spawn(child_pid)
            if normalized_protection is not None:
                if normalized_protection["roots"]:
                    assert confinement_status_read is not None
                    status_line, status_problem = _read_confinement_status(
                        confinement_status_read,
                        min(deadline, time.monotonic() + 15.0),
                        cancel_marker=cancel_marker,
                    )
                    confinement_status_line = status_line
                    expected_prefix = (
                        "C1CONF " + str(confinement_nonce) + " OK "
                    ).encode("ascii")
                    # C-R1 precedence remains authoritative: a whole-run
                    # deadline or cancellation wins over a missing/failed
                    # confinement status, and cancellation interrupts the wait.
                    control_reason = capture_control_reason()
                    if control_reason is not None:
                        apply_capture_control(control_reason)
                    elif status_problem is not None:
                        confinement_application = {
                            "method": "in-namespace-mountinfo",
                            "verified": False,
                            "checked": 0,
                            "nonce_sha256": hashlib.sha256(
                                str(confinement_nonce).encode("ascii")
                            ).hexdigest(),
                            "errors": [
                                "confinement status was not reported: "
                                + status_problem
                            ],
                        }
                        capture_error = ProviderError(
                            "isolation_unavailable",
                            "protected confinement was not established before "
                            "provider startup: " + status_problem,
                        )
                    elif not status_line.startswith(expected_prefix):
                        detail = status_line.decode("utf-8", "replace")[:400]
                        confinement_application = {
                            "method": "in-namespace-mountinfo",
                            "verified": False,
                            "checked": 0,
                            "nonce_sha256": hashlib.sha256(
                                str(confinement_nonce).encode("ascii")
                            ).hexdigest(),
                            "errors": [detail],
                        }
                        capture_error = ProviderError(
                            "isolation_unavailable",
                            "protected confinement check failed before provider "
                            "startup: " + detail,
                        )
                    else:
                        try:
                            checked = int(
                                status_line[len(expected_prefix) :].decode("ascii")
                            )
                        except (UnicodeDecodeError, ValueError):
                            checked = -1
                        expected_checks = (
                            len(normalized_protection["roots"])
                            + len(normalized_protection["anchors"])
                            + 3
                            + len(
                                _git_custody_paths(
                                    str(workspace), git_dir, git_common_dir
                                )
                            )
                        )
                        if checked < expected_checks:
                            confinement_application = {
                                "method": "in-namespace-mountinfo",
                                "verified": False,
                                "checked": max(checked, 0),
                                "nonce_sha256": hashlib.sha256(
                                    str(confinement_nonce).encode("ascii")
                                ).hexdigest(),
                                "errors": [
                                    "confinement check covered "
                                    f"{checked} of {expected_checks} declared mounts"
                                ],
                            }
                            capture_error = ProviderError(
                                "isolation_unavailable",
                                "protected confinement check did not verify the "
                                "complete declared mount plan",
                            )
                        else:
                            confinement_application = {
                                "method": "in-namespace-mountinfo",
                                "verified": True,
                                "checked": checked,
                                "nonce_sha256": hashlib.sha256(
                                    str(confinement_nonce).encode("ascii")
                                ).hexdigest(),
                                "status_sha256": hashlib.sha256(
                                    status_line
                                ).hexdigest(),
                                "errors": [],
                            }
                else:
                    confinement_application = {
                        "method": "empty-protected-set",
                        "verified": True,
                        "checked": 0,
                        "errors": [],
                        "coverage": (
                            "no original protected-user roots or ancestor anchors "
                            "were declared for this attempt; the empty set carries "
                            "no kernel protection claim"
                        ),
                    }
        except ProviderError as exc:
            capture_error = exc
        except (OSError, ValueError):
            capture_error = ProviderError(
                "isolation_unavailable",
                "the isolated provider process could not be started",
            )
        finally:
            child_control.close()
            _close(stdout_write)
            _close(stderr_write)
            _close(confinement_status_write)
            if confinement_status_read is not None:
                # The status record must be the first line.  Any later writer
                # inherits a descriptor with no reader and cannot alter it.
                try:
                    os.close(confinement_status_read)
                except OSError:
                    pass
            if normalized_protection is not None and confinement_application is not None:
                confinement = _confinement_evidence(
                    normalized_protection,
                    command or [],
                    confinement_application,
                )

        if process is not None:
            stdout_thread = threading.Thread(
                target=_reader_loop,
                args=(stdout_read, stdout_buffer),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_reader_loop,
                args=(stderr_read, stderr_buffer),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()

            control_open = True
            if capture_error is None:
                try:
                    capture_data, capture_truncated = _read_capture(
                        parent_control.fileno(),
                        MAX_CAPTURE_BYTES,
                        deadline,
                        process,
                        cancel_marker=cancel_marker,
                    )
                    control_reason = capture_control_reason()
                    if control_reason is not None:
                        raise _CaptureControlInterrupted(control_reason)
                    if capture_truncated:
                        raise ProviderError(
                            "credential_capture_unavailable",
                            "provider wrapper capture exceeded its size limit",
                        )
                    definition, environment = parse_capture_stream(
                        capture_data, str(profile.get("provider"))
                    )
                    spec = parse_wrapper_definition(
                        definition, str(profile.get("provider"))
                    )
                    redactor = Redactor(
                        capture_sensitive_values(spec, environment)
                    )
                    # Control remains authoritative through redactor setup: the
                    # provider is never released with an acknowledgement after
                    # the whole-run deadline or an explicit cancellation.
                    control_reason = capture_control_reason()
                    if control_reason is not None:
                        raise _CaptureControlInterrupted(control_reason)
                    os.write(parent_control.fileno(), CAPTURE_ACK)
                    parent_control.close()
                    control_open = False
                    if on_event is not None:
                        try:
                            on_event(
                                "provider_captured",
                                {"provider_capability": capability},
                            )
                        except OSError:
                            pass
                except _CaptureControlInterrupted as exc:
                    apply_capture_control(exc.reason)
                except ProviderError as exc:
                    control_reason = capture_control_reason()
                    if control_reason is not None:
                        apply_capture_control(control_reason)
                    else:
                        capture_error = exc
                except (subprocess.TimeoutExpired, OSError):
                    control_reason = capture_control_reason()
                    if control_reason is not None:
                        apply_capture_control(control_reason)
                    else:
                        capture_error = ProviderError(
                            "credential_capture_unavailable",
                            "provider wrapper capture could not complete",
                        )
            if control_open:
                parent_control.close()

            if capture_error is not None:
                _terminate_group(process.pid)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _terminate_group(process.pid, force=True)
                    process.wait()
            else:
                last_scope_check = 0.0
                last_heartbeat = 0.0
                while process.poll() is None:
                    now = time.monotonic()
                    if now >= deadline:
                        timed_out = True
                        _terminate_group(process.pid)
                        break
                    if cancel_marker.exists():
                        cancelled = True
                        _terminate_group(process.pid)
                        break
                    if stdout_buffer.overflow.is_set() or stderr_buffer.overflow.is_set():
                        _terminate_group(process.pid)
                        break
                    if on_heartbeat is not None and now - last_heartbeat >= 2.0:
                        last_heartbeat = now
                        try:
                            on_heartbeat(
                                {
                                    "worker_pid": os.getpid(),
                                    "child_pid": process.pid,
                                }
                            )
                        except OSError:
                            pass
                    if scope_check is not None and now - last_scope_check >= 2.0:
                        last_scope_check = now
                        try:
                            scope_violations = scope_check()
                        except Exception:
                            scope_violations = [
                                "workspace scope attribution became unavailable"
                            ]
                        if scope_violations:
                            _terminate_group(process.pid)
                            break
                    time.sleep(0.1)
                if timed_out or cancelled or scope_violations or (
                    stdout_buffer.overflow.is_set()
                    or stderr_buffer.overflow.is_set()
                ):
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        _terminate_group(process.pid, force=True)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                try:
                    exit_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _terminate_group(process.pid, force=True)
                    exit_code = process.wait()
            for thread in (stdout_thread, stderr_thread):
                if thread is not None:
                    thread.join(timeout=6)
            # Unblock any reader still waiting on a pipe held by a surviving
            # descendant; the PID namespace should make this unnecessary.
            _close(stdout_read)
            _close(stderr_read)
            for thread in (stdout_thread, stderr_thread):
                if thread is not None:
                    thread.join(timeout=2)
            if not timed_out and cancel_marker.exists():
                cancelled = True
            if process.poll() is not None:
                exit_code = process.returncode
    finally:
        try:
            parent_control.close()
        except OSError:
            pass
        try:
            child_control.close()
        except OSError:
            pass
        _close(stdout_read)
        _close(stdout_write)
        _close(stderr_read)
        _close(stderr_write)
        if process is not None and process.poll() is None:
            _terminate_group(process.pid)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_group(process.pid, force=True)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

    stdout_bytes = sanitize_capture(stdout_buffer, redactor)
    stderr_bytes = sanitize_capture(stderr_buffer, redactor)
    envelope: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    payload_sha256: str | None = None
    error: ProviderError | None = capture_error
    if error is None and scope_violations:
        error = ProviderError(
            "execution_failed", "provider modified workspace scope outside its contract"
        )
    if error is None and timed_out:
        error = ProviderError("timeout", "provider execution reached its timeout")
    if error is None and cancelled:
        error = ProviderError("cancelled", "provider execution was cancelled")
    if error is None and (
        stdout_buffer.truncated or stderr_buffer.truncated
    ):
        error = ProviderError(
            "output_limit", "provider output exceeded the bounded capture limit"
        )
    if error is None and exit_code != 0:
        error = classify_failure(
            stdout_bytes + b"\n" + stderr_bytes, exit_code
        )
    if error is None:
        try:
            validated = validate_completion(
                stdout_bytes, operation, context=stderr_bytes
            )
            # Revalidate the decoded structure after the second redaction pass
            # so sanitized strings keep the exact persisted schema.
            payload = validate_payload(
                operation,
                sanitize_structure(redactor, validated["payload"]),
            )
            envelope = sanitize_structure(redactor, validated["envelope"])
            payload_sha256 = hashlib.sha256(
                _canonical_bytes(payload)
            ).hexdigest()
        except ProviderError as exc:
            error = exc
    diagnostics: dict[str, Any] = {
        "stdout_bytes": stdout_buffer.total,
        "stderr_bytes": stderr_buffer.total,
        "stdout_truncated": stdout_buffer.truncated,
        "stderr_truncated": stderr_buffer.truncated,
    }
    tail = _sanitized_diagnostic_tail(stderr_bytes)
    if tail:
        diagnostics["stderr_tail"] = tail
    result = _provider_result(
        binding,
        capture_error=error,
        exit_code=exit_code,
        timed_out=timed_out,
        cancelled=cancelled,
        scope_violations=scope_violations,
        envelope=envelope,
        payload=payload,
        payload_sha256=payload_sha256,
        diagnostics=diagnostics,
        confinement=confinement,
    )
    return ProviderRun(
        exit_code=exit_code,
        timed_out=timed_out,
        cancelled=cancelled,
        scope_violations=scope_violations,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        stdout_total=stdout_buffer.total,
        stderr_total=stderr_buffer.total,
        stdout_truncated=stdout_buffer.truncated,
        stderr_truncated=stderr_buffer.truncated,
        result=result,
        error=error.as_dict() if error else None,
        child_pid=child_pid,
        capture_error=capture_error.as_dict() if capture_error else None,
    )


def _provider_result(
    binding: Mapping[str, Any],
    *,
    capture_error: ProviderError | None,
    exit_code: int,
    timed_out: bool,
    cancelled: bool,
    scope_violations: list[str],
    envelope: dict[str, Any] | None,
    payload: dict[str, Any] | None,
    payload_sha256: str | None,
    diagnostics: dict[str, Any],
    confinement: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "result_version": RESULT_VERSION,
        "provider": binding.get("provider"),
        "profile": binding.get("profile"),
        "operation": binding.get("operation"),
        "capability": binding.get("capability"),
        "binding": dict(binding),
        "binding_sha256": binding.get("binding_sha256"),
        "capability_table_version": CAPABILITY_TABLE_VERSION,
        "capability_table_sha256": CAPABILITY_TABLE_SHA256,
        "validated": capture_error is None
        and payload is not None
        and envelope is not None,
        "envelope": envelope,
        "payload": payload,
        "payload_sha256": payload_sha256,
        "error": capture_error.as_dict() if capture_error is not None else None,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "scope_violations": list(scope_violations),
        "diagnostics": diagnostics,
        "captured_at": _now(),
    }
    if confinement is not None:
        result["confinement"] = dict(confinement)
    return result


def error_result(
    binding: Mapping[str, Any],
    error: ProviderError,
    *,
    exit_code: int = 127,
) -> dict[str, Any]:
    """Build a normalized failure result when no provider process ran."""
    return _provider_result(
        binding,
        capture_error=error,
        exit_code=exit_code,
        timed_out=False,
        cancelled=False,
        scope_violations=[],
        envelope=None,
        payload=None,
        payload_sha256=None,
        diagnostics={},
    )


def persist_provider_result(
    job_dir: Path,
    result: Mapping[str, Any],
    write_json: Callable[[Path, dict[str, Any]], None],
) -> Path:
    """Persist the normalized result independently of provider-writable state."""
    path = Path(job_dir) / "provider-result.json"
    write_json(path, dict(result))
    os.chmod(path, 0o600)
    return path


def provider_result_summary(
    result: Mapping[str, Any], path: Path, digest: str
) -> dict[str, Any]:
    envelope = result.get("envelope") or {}
    return {
        "result_version": result.get("result_version"),
        "provider": result.get("provider"),
        "operation": result.get("operation"),
        "capability": result.get("capability"),
        "validated": bool(result.get("validated")),
        "error": result.get("error"),
        "binding_sha256": result.get("binding_sha256"),
        "capability_table_version": result.get("capability_table_version"),
        "capability_table_sha256": result.get("capability_table_sha256"),
        "usage": envelope.get("usage"),
        "total_cost_usd": envelope.get("total_cost_usd"),
        "result_path": str(path),
        "result_sha256": digest,
    }


def provider_result_sha256(result: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(result)).hexdigest()
