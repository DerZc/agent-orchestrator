from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
RUNNER = SCRIPTS / "cli_agent_job.py"
PROVIDER_MODULE = SCRIPTS / "c_providers.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("agent_orchestrator_runner_c_tests", RUNNER)
c = runner.c_module()
ISOLATION_OK, ISOLATION_REASON = c.isolation_status()


def clean_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not c.is_sensitive_name(key)
    }
    env.pop("ANTHROPIC_BASE_URL", None)
    env.pop("CLAUDE_CODE_AUTO_COMPACT_WINDOW", None)
    return env


def git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "tests@example.invalid"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Tests"], cwd=path, check=True
    )
    (path / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=path, check=True)
    return path


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def write_rcfile(
    path: Path,
    function: str,
    statements: list[str] | None = None,
    *,
    startup: str = "",
    command: str = 'claude "$@"',
) -> Path:
    lines = statements or [
        "export ANTHROPIC_AUTH_TOKEN='test-token-canary-0123456789'",
        "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
        "export ANTHROPIC_MODEL='test-model'",
    ]
    content = startup
    content += f"{function} () {{\n"
    for line in lines:
        content += f"    {line}\n"
    content += f"    {command}\n"
    content += "}\n"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def valid_payload(operation: str) -> dict:
    if operation == "proposal":
        return {
            "approach": "Use the frozen provider primitives.",
            "rationale": "It preserves the configured wrapper exactly.",
            "assumptions": ["The wrapper exports static literals."],
            "problems": ["Dynamic wrappers cannot be captured safely."],
            "alternatives": ["A PATH relay was rejected."],
            "feasibility": "Feasible with bubblewrap isolation.",
            "testing": ["Run the C provider suite."],
        }
    if operation == "cross_examination":
        return {
            "objections": [
                {"objection": "Bound the startup output.", "severity": "high"}
            ],
            "responses": ["Startup output is discarded before persistence."],
            "revisions": ["Document the supported wrapper grammar."],
        }
    if operation == "consensus":
        return {
            "decision": "AGREE",
            "candidate_sha256": "a" * 64,
            "rationale": "The frozen candidate is accepted.",
        }
    return {
        "changed_paths": ["plugins/agent-orchestrator/scripts/example.py"],
        "validation_commands": ["python3 -m unittest"],
        "validation_outcomes": ["all tests passed"],
        "remaining_issues": [],
    }


def result_text(operation: str, payload: dict | None = None, fenced: bool = False) -> str:
    document = {
        "result_version": 1,
        "operation": operation,
        "payload": payload if payload is not None else valid_payload(operation),
    }
    text = json.dumps(document)
    if fenced:
        return "```json\n" + text + "\n```"
    return text


def envelope_line(
    operation: str,
    *,
    payload: dict | None = None,
    fenced: bool = False,
    subtype: str = "success",
    is_error: bool = False,
    text: str | None = None,
) -> str:
    return json.dumps(
        {
            "type": "result",
            "subtype": subtype,
            "is_error": is_error,
            "result": text
            if text is not None
            else result_text(operation, payload, fenced=fenced),
            "num_turns": 1,
            "duration_ms": 12,
            "session_id": "00000000-0000-4000-8000-000000000000",
            "total_cost_usd": 0.01,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    )


def escaped_result_line(secret: str, mixed: bool) -> bytes:
    """Native envelope whose inner rationale uses escaped unicode spellings."""
    document = {
        "result_version": 1,
        "operation": "proposal",
        "payload": {
            **valid_payload("proposal"),
            "rationale": "@@RATIONALE@@",
        },
    }
    if mixed:
        escaped = "".join(
            ("\\u%04x" % ord(char)) if index % 2 == 0 else char
            for index, char in enumerate(secret)
        )
    else:
        escaped = "".join("\\u%04x" % ord(char) for char in secret)
    inner = json.dumps(document).replace(
        '"@@RATIONALE@@"', '"' + escaped + '"', 1
    )
    envelope = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": inner,
        "num_turns": 1,
        "duration_ms": 5,
        "session_id": "00000000-0000-4000-8000-000000000000",
        "total_cost_usd": 0.02,
        "usage": {"input_tokens": 9, "output_tokens": 4},
    }
    return (json.dumps(envelope) + "\n").encode("utf-8")


def completion_stream(operation: str, **kwargs) -> bytes:
    return (
        json.dumps({"type": "system", "subtype": "init"})
        + "\n"
        + envelope_line(operation, **kwargs)
        + "\n"
    ).encode("utf-8")


def provider_profile(name: str, rcfile: Path | None = None) -> dict:
    profile = dict(runner.load_profiles(None)[name])
    if rcfile is not None:
        profile["provider_rcfile"] = str(rcfile)
    return profile


FAKE_CLAUDE = r'''#!{python}
import hashlib
import json
import os
import subprocess
import sys
import time

mode = os.environ.get("C_FAKE_MODE", "success")
operation = os.environ.get("C_FAKE_OPERATION", "proposal")
if mode == "sleep":
    sys.stderr.write("sleeping\n")
    sys.stderr.flush()
    time.sleep(30)
    raise SystemExit(0)
if mode == "oversized":
    chunk = b"x" * 65536
    for _ in range(80):
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
    raise SystemExit(0)
prompt = sys.stdin.read()
if mode == "invalid":
    sys.stdout.write("not a JSON stream\n")
    raise SystemExit(0)
if mode == "invalid_echo":
    sys.stdout.write("not-json " + os.environ.get("ANTHROPIC_AUTH_TOKEN", "") + " {{")
    sys.stdout.flush()
    raise SystemExit(0)
if mode == "truncated_echo":
    line = json.dumps({{"type": "result", "subtype": "success", "is_error": False, "result": "partial " + os.environ.get("ANTHROPIC_AUTH_TOKEN", "")}})
    sys.stdout.write(line[:-12])
    sys.stdout.flush()
    raise SystemExit(0)
if mode == "empty":
    raise SystemExit(0)
if mode in ("unicode_escape_payload", "mixed_escape_payload"):
    token_value = os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
    if mode == "unicode_escape_payload":
        escaped_value = "".join("\\u%04x" % ord(ch) for ch in token_value)
    else:
        escaped_value = "".join(
            ("\\u%04x" % ord(ch)) if index % 2 == 0 else ch
            for index, ch in enumerate(token_value)
        )
    document = json.loads(os.environ["C_FAKE_RESULT"])
    document["payload"]["rationale"] = "@@RATIONALE@@"
    inner_text = json.dumps(document)
    inner_text = inner_text.replace(
        '"@@RATIONALE@@"', '"' + escaped_value + '"', 1
    )
    print(
        json.dumps(
            {{
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": inner_text,
                "num_turns": 1,
                "duration_ms": 5,
                "session_id": "00000000-0000-4000-8000-000000000000",
                "total_cost_usd": 0.02,
                "usage": {{"input_tokens": 9, "output_tokens": 4}},
            }}
        )
    )
    raise SystemExit(0)
if mode == "auth":
    sys.stderr.write("401 Unauthorized\n")
    raise SystemExit(1)
if mode == "rate":
    sys.stderr.write("429 rate limit exceeded\n")
    raise SystemExit(1)
if mode == "quota":
    sys.stderr.write("insufficient_quota: billing exhausted\n")
    raise SystemExit(1)
if mode == "exec_fail":
    sys.stderr.write("provider crashed\n")
    raise SystemExit(2)
if mode == "envelope_error_auth":
    print(json.dumps({{"type": "result", "subtype": "error_during_execution", "is_error": True, "result": "401 unauthorized"}}))
    raise SystemExit(0)
writes = {{}}
for key, target in json.loads(os.environ.get("C_FAKE_WRITES", "{{}}")).items():
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("tampered")
    except OSError:
        writes[key] = "denied"
    else:
        writes[key] = "wrote"
if mode == "descendant":
    subprocess.Popen(["sleep", "2971"])
sys.stderr.write("FAKE_ARGV=" + json.dumps(sys.argv[1:]) + "\n")
sys.stderr.write("FAKE_STDIN_SHA=" + hashlib.sha256(prompt.encode("utf-8")).hexdigest() + "\n")
sys.stderr.write("FAKE_WRITES=" + json.dumps(writes, sort_keys=True) + "\n")
token = os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
if os.environ.get("C_FAKE_ECHO_VALUE"):
    for index in range(0, len(token), 3):
        sys.stderr.write(token[index:index + 3])
        sys.stderr.flush()
    sys.stderr.write("\n")
if os.environ.get("C_FAKE_EXPECT_VALUE") is not None:
    sys.stderr.write(
        "FAKE_TOKEN_IS_EXPECTED="
        + ("true" if token == os.environ["C_FAKE_EXPECT_VALUE"] else "false")
        + "\n"
    )
document = json.loads(os.environ["C_FAKE_RESULT"])
if os.environ.get("C_FAKE_ECHO_IN_PAYLOAD") and isinstance(document.get("payload"), dict):
    document["payload"]["rationale"] = (
        document["payload"].get("rationale", "") + " " + os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
    )
text = json.dumps(document)
if os.environ.get("C_FAKE_FENCE"):
    text = "```json\n" + text + "\n```"
print(json.dumps({{"type": "system", "subtype": "init"}}))
print(json.dumps({{"type": "result", "subtype": "success", "is_error": False, "result": text, "num_turns": 1, "duration_ms": 5, "session_id": "00000000-0000-4000-8000-000000000000", "total_cost_usd": 0.02, "usage": {{"input_tokens": 9, "output_tokens": 4}}}}))
'''


def write_fake_bwrap(bin_dir: Path, capture_mode: str = "exec") -> Path:
    """Install a transport-only bwrap shim for non-confinement test coverage.

    Real confinement tests are the ``CProviderSandboxTests`` class and skip
    unless the host bubblewrap probe actually succeeds.  This shim exists only
    to exercise the launch/worker/capture/validation pipeline on hosts where
    namespaces are blocked; it provides no isolation and is never used by the
    product.  ``capture_mode="malformed"`` writes an invalid capture record on
    the inherited control socket instead of starting the shell, while the
    isolation probe still succeeds so the pipeline reaches capture.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    executable = bin_dir / "bwrap"
    executable.write_text(
        f"""#!{sys.executable}
import os
import stat
import sys

args = sys.argv[1:]
command = None
for index, value in enumerate(args):
    if value == "bash" or value.endswith("/bash"):
        command = args[index:]
        break
if command is None:
    command = args[-1:]
if {capture_mode!r} == "malformed" and "c-provider" in command:
    for name in os.listdir("/proc/self/fd"):
        if not name.isdigit():
            continue
        fd = int(name)
        if fd <= 2:
            continue
        try:
            if stat.S_ISSOCK(os.fstat(fd).st_mode):
                os.write(fd, b"BOGUS" + bytes([0]))
                break
        except OSError:
            continue
    raise SystemExit(0)
os.execv(command[0], command)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def write_fake_claude(bin_dir: Path) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    executable = bin_dir / "claude"
    executable.write_text(
        FAKE_CLAUDE.format(python=sys.executable), encoding="utf-8"
    )
    executable.chmod(0o755)
    return executable


def run_capture_shell(
    root: Path,
    rcfile_content: str,
    *,
    provider: str = "deepseek",
    env_path: str | None = None,
) -> tuple[bytes, int]:
    """Run the pre-acknowledgement capture wrapper in a real Bash context.

    Returns the bytes written on the private control channel and the shell exit
    status.  This helper is only for guard/failure cases: a supported wrapper
    blocks for the acknowledgement, which is exercised by the full handshake
    tests instead.
    """
    rcfile = root / "guard-rc"
    rcfile.write_text(rcfile_content, encoding="utf-8")
    rcfile.chmod(0o600)
    prompt = root / "guard-prompt.md"
    prompt.write_text("guard prompt\n", encoding="utf-8")
    profile = provider_profile(provider, rcfile)
    parent_control, child_control = socket.socketpair()
    command = c.shell_command(
        profile,
        prompt,
        child_control.fileno(),
        c.provider_argv("proposal", "readonly"),
    )
    env = clean_env()
    if env_path is not None:
        env["PATH"] = env_path
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        close_fds=True,
        pass_fds=(child_control.fileno(),),
    )
    child_control.close()
    parent_control.settimeout(10)
    capture = b""
    try:
        while True:
            chunk = parent_control.recv(65536)
            if not chunk:
                break
            capture += chunk
    finally:
        parent_control.close()
    process.wait(timeout=10)
    return capture, process.returncode


def persisted_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return [path for path in root.rglob("*") if path.is_file()]


def write_job_meta(
    state_home: Path,
    repo: Path,
    job_id: str,
    binding: dict,
    profile: dict,
    *,
    capability: str,
    lease: dict | None,
    worker_pid: int | None,
    extra: dict | None = None,
) -> tuple[Path, dict]:
    path = state_home / "jobs" / job_id
    path.mkdir(parents=True, exist_ok=True)
    (path / "channel").mkdir(exist_ok=True)
    (path / "scratch").mkdir(exist_ok=True)
    (path / "task.md").write_text("task\n", encoding="utf-8")
    meta = {
        "job_id": job_id,
        "agent": profile["provider"],
        "cli": profile["provider"],
        "workspace": str(repo),
        "canonical_workspace": str(repo),
        "profile": profile,
        "prompt_transport": "stdin",
        "state": "running",
        "timeout_seconds": 5,
        "notify": False,
        "provider_binding": {**binding, "capability": capability},
        "operation": binding["operation"],
        "provider_scratch": str(path / "scratch"),
        "git_baseline": {"is_git": True},
        "scope": {},
        "workspace_lease": lease,
        "worker_pid": worker_pid,
        "child_pid": None,
    }
    if extra:
        meta.update(extra)
    (path / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return path, meta


def pid_cmdline_matches(marker: str) -> list[int]:
    matches: list[int] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return matches
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            data = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if marker.encode("utf-8") in data:
            matches.append(int(entry.name))
    return matches


class CProviderUnitTests(unittest.TestCase):
    def test_capability_table_is_versioned_and_glm_cannot_write(self) -> None:
        self.assertEqual(c.CAPABILITY_TABLE_VERSION, 1)
        self.assertEqual(len(c.CAPABILITY_TABLE_SHA256), 64)
        deepseek = provider_profile("deepseek")
        glm = provider_profile("glm")
        for operation in c.OPERATIONS:
            binding = c.build_binding("deepseek", deepseek, operation)
            self.assertEqual(
                binding["capability"],
                "workspace_write"
                if operation in c.WRITER_OPERATIONS
                else "readonly",
            )
            self.assertEqual(
                binding["capability_table_sha256"], c.CAPABILITY_TABLE_SHA256
            )
        for operation in ("proposal", "cross_examination", "consensus"):
            self.assertEqual(
                c.build_binding("glm", glm, operation)["capability"], "readonly"
            )
        for operation in c.WRITER_OPERATIONS:
            with self.assertRaises(c.ProviderError) as raised:
                c.build_binding("glm", glm, operation)
            self.assertEqual(raised.exception.code, "unauthorized_role")

    def test_binding_revalidation_rejects_tampering_and_spoofing(self) -> None:
        profile = provider_profile("deepseek")
        binding = c.build_binding("deepseek", profile, "proposal")
        meta = {
            "agent": "deepseek",
            "cli": "deepseek",
            "profile": profile,
            "provider_binding": binding,
            "workspace_lease": None,
        }
        self.assertEqual(c.binding_from_meta(meta)["operation"], "proposal")

        tampered = json.loads(json.dumps(meta))
        tampered["provider_binding"]["operation"] = "implementation"
        with self.assertRaises(c.ProviderError) as raised:
            c.binding_from_meta(tampered)
        self.assertEqual(raised.exception.code, "unauthorized_role")

        readonly_with_lease = dict(meta)
        readonly_with_lease["workspace_lease"] = {"epoch": "00" * 16}
        with self.assertRaises(c.ProviderError):
            c.binding_from_meta(readonly_with_lease)

        writer_profile = provider_profile("deepseek")
        writer_binding = c.build_binding(
            "deepseek", writer_profile, "implementation"
        )
        writer_meta = {
            "agent": "deepseek",
            "cli": "deepseek",
            "profile": writer_profile,
            "provider_binding": writer_binding,
            "workspace_lease": None,
        }
        with self.assertRaises(c.ProviderError):
            c.binding_from_meta(writer_meta)
        writer_meta["workspace_lease"] = {"epoch": "11" * 16}
        self.assertEqual(
            c.binding_from_meta(writer_meta)["capability"], "workspace_write"
        )

        spoof = json.loads(json.dumps(meta))
        spoof["provider_binding"]["provider"] = "glm"
        with self.assertRaises(c.ProviderError):
            c.binding_from_meta(spoof)

    def test_static_wrapper_grammar_accepts_current_shape(self) -> None:
        deepseek_lines = [
            f"export VAR_{index}='literal value {index}; with semicolon'"
            for index in range(9)
        ]
        body = "deepseek () \n{ \n"
        for line in deepseek_lines:
            body += f"    {line}\n"
        body += '    claude "$@"\n}\n'
        spec = c.parse_wrapper_definition(body, "deepseek")
        self.assertEqual(spec.function, "deepseek")
        self.assertEqual(spec.command, ("claude", '"$@"'))
        self.assertEqual(len(spec.assignments), 9)
        self.assertTrue(all(exported for _, _, exported in spec.assignments))

        quoted = '''glm ()
{
    export ANTHROPIC_AUTH_TOKEN="quote \\" and dollar \\$ literal"
    export ANTHROPIC_MODEL=model-with-dashes
    export URL='single quoted with spaces and ;'
    export MULTILINE="line one
line two"
    claude "$@"
}
'''
        spec = c.parse_wrapper_definition(quoted, "glm")
        values = spec.exported_values()
        self.assertEqual(values["ANTHROPIC_MODEL"], "model-with-dashes")
        self.assertEqual(values["URL"], "single quoted with spaces and ;")
        self.assertEqual(values["MULTILINE"], "line one\nline two")
        self.assertIn('quote " and dollar $ literal', values["ANTHROPIC_AUTH_TOKEN"])

    def test_static_wrapper_grammar_rejects_unsupported_capture(self) -> None:
        cases = {
            "expansion": 'deepseek () { export A="$OTHER"; claude "$@"; }',
            "command-substitution": "deepseek () { export A=$(cat /tmp/x); claude \"$@\"; }",
            "backtick": "deepseek () { export A=`id`; claude \"$@\"; }",
            "eval": 'deepseek () { eval "claude \\"$@\\""; }',
            "exec": 'deepseek () { exec claude "$@"; }',
            "command-prefix": 'deepseek () { command claude "$@"; }',
            "extra-arg": 'deepseek () { export A=1; claude "$@" --dangerously-skip-permissions; }',
            "extra-command": 'deepseek () { export A=1; claude "$@"; rm -rf /tmp/x; }',
            "wrong-command": 'deepseek () { export A=1; deepseek "$@"; }',
            "redirection": 'deepseek () { export A=1; claude "$@" > /tmp/out; }',
            "missing-call": "deepseek () { export A=1; }",
            "tilde": "deepseek () { export A=~/secret; claude \"$@\"; }",
        }
        for label, body in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(c.ProviderError) as raised:
                    c.parse_wrapper_definition(body, "deepseek")
                self.assertEqual(
                    raised.exception.code, "credential_capture_unavailable"
                )
                self.assertNotIn("OTHER", raised.exception.message)
                self.assertNotIn("/tmp/x", raised.exception.message)

    def test_capture_stream_nul_framing_and_sensitive_values(self) -> None:
        definition = 'deepseek () { export API_KEY="canary"; claude "$@"; }'
        data = (
            b"C1\x00deepseek\x00"
            + definition.encode()
            + b"\x00E\x00ANTHROPIC_AUTH_TOKEN\x00token-from-env\x00"
            + b"E\x00ANTHROPIC_MODEL\x00benign-model\x00END\x00"
        )
        parsed_definition, environment = c.parse_capture_stream(
            data, "deepseek"
        )
        self.assertEqual(parsed_definition, definition)
        self.assertEqual(environment["ANTHROPIC_MODEL"], b"benign-model")
        spec = c.parse_wrapper_definition(parsed_definition, "deepseek")
        values = c.capture_sensitive_values(spec, environment)
        self.assertIn(b"canary", values)
        self.assertIn(b"token-from-env", values)
        self.assertNotIn(b"benign-model", values)
        for malformed in (b"", b"C1\x00deepseek", b"ERR\x00missing_function\x00"):
            with self.assertRaises(c.ProviderError):
                c.parse_capture_stream(malformed, "deepseek")

    def test_capture_error_records_classify_backend_resolution(self) -> None:
        accepted = (
            (b"ERR\x00missing_function\x00", "provider_unavailable", None),
            (b"ERR\x00missing_function\x00END\x00", "provider_unavailable", None),
            (
                b"ERR\x00missing_backend\x00",
                "provider_unavailable",
                c.SAFE_BACKEND_ERROR,
            ),
            (
                b"ERR\x00missing_backend\x00END\x00",
                "provider_unavailable",
                c.SAFE_BACKEND_ERROR,
            ),
            (
                b"ERR\x00unsupported_delegation\x00",
                "credential_capture_unavailable",
                c.SAFE_DELEGATION_ERROR,
            ),
            (
                b"ERR\x00unsupported_delegation\x00END\x00",
                "credential_capture_unavailable",
                c.SAFE_DELEGATION_ERROR,
            ),
        )
        for record, code, message in accepted:
            with self.subTest(record=record):
                with self.assertRaises(c.ProviderError) as raised:
                    c.parse_capture_stream(record, "deepseek")
                self.assertEqual(raised.exception.code, code)
                if message is not None:
                    self.assertEqual(raised.exception.message, message)
        # A truncated, extended or unknown error record is a capture failure;
        # it is never reinterpreted as a trustworthy guard reason.
        rejected = (
            b"ERR\x00missing_backend",
            b"ERR\x00",
            b"ERR\x00missing_backend\x00BOGUS\x00",
            b"ERR\x00missing_backend\x00END\x00BOGUS\x00",
            b"ERR\x00missing_function\x00BOGUS\x00",
            b"ERR\x00unknown_reason\x00END\x00",
            b"BOGUS\x00",
        )
        for record in rejected:
            with self.subTest(record=record):
                with self.assertRaises(c.ProviderError) as raised:
                    c.parse_capture_stream(record, "deepseek")
                self.assertEqual(
                    raised.exception.code, "credential_capture_unavailable"
                )
                self.assertEqual(raised.exception.message, c.SAFE_CAPTURE_ERROR)

    def test_capture_framer_recognizes_end_only_in_tag_position(self) -> None:
        definition = (
            'deepseek () { export APP_COMPONENT=BACKEND; claude "$@"; }'
        )
        stream = (
            b"C1\x00deepseek\x00"
            + definition.encode()
            + b"\x00"
            + b"E\x00APP_COMPONENT\x00BACKEND\x00"
            + b"E\x00TRAILING_TAG\x00END\x00"
            + b"END\x00"
        )
        for split in range(len(stream)):
            with self.subTest(split=split):
                framer = c.CaptureFramer()
                self.assertFalse(framer.feed(bytearray(stream[:split])))
                self.assertFalse(framer.terminated)
                self.assertFalse(framer.malformed)
                self.assertTrue(framer.feed(bytearray(stream)))
                self.assertTrue(framer.terminated)
                self.assertFalse(framer.malformed)
        parsed_definition, environment = c.parse_capture_stream(
            stream, "deepseek"
        )
        self.assertEqual(parsed_definition, definition)
        self.assertEqual(environment["APP_COMPONENT"], b"BACKEND")
        self.assertEqual(environment["TRAILING_TAG"], b"END")

    def test_capture_framer_terminates_error_records_across_split_reads(
        self,
    ) -> None:
        expected = {
            b"missing_function": "provider_unavailable",
            b"missing_backend": "provider_unavailable",
            b"unsupported_delegation": "credential_capture_unavailable",
        }
        for reason, code in expected.items():
            stream = b"ERR\x00" + reason + b"\x00END\x00"
            with self.subTest(reason=reason):
                # ``feed`` consumes a growing accumulated buffer, matching the
                # read loop; one byte per call is the worst-case split.
                framer = c.CaptureFramer()
                buffer = bytearray()
                for index, byte in enumerate(stream):
                    buffer.append(byte)
                    done = framer.feed(buffer)
                    self.assertFalse(framer.malformed)
                    if index < len(stream) - 1:
                        self.assertFalse(done)
                self.assertTrue(framer.terminated)
                self.assertFalse(framer.malformed)
                for split in range(len(stream) + 1):
                    split_framer = c.CaptureFramer()
                    prefix_done = split_framer.feed(bytearray(stream[:split]))
                    self.assertFalse(split_framer.malformed)
                    self.assertEqual(prefix_done, split == len(stream))
                    if split < len(stream):
                        self.assertTrue(split_framer.feed(bytearray(stream)))
                    self.assertTrue(split_framer.terminated)
                    self.assertFalse(split_framer.malformed)
                with self.assertRaises(c.ProviderError) as raised:
                    c.parse_capture_stream(stream, "deepseek")
                self.assertEqual(raised.exception.code, code)

    def test_capture_reader_waits_for_real_end_tag_across_split_reads(self) -> None:
        definition = (
            'deepseek () { export APP_COMPONENT=BACKEND; claude "$@"; }'
        )
        prefix = (
            b"C1\x00deepseek\x00"
            + definition.encode()
            + b"\x00"
            + b"E\x00APP_COMPONENT\x00BACKEND\x00"
            + b"E\x00TRAILING_TAG\x00END\x00"
        )
        reader, writer = socket.socketpair()

        def write_capture() -> None:
            try:
                writer.sendall(prefix)
                time.sleep(0.2)
                writer.sendall(b"END\x00")
            finally:
                writer.close()

        class NoExit:
            def poll(self) -> None:
                return None

        thread = threading.Thread(target=write_capture, daemon=True)
        thread.start()
        started = time.monotonic()
        try:
            capture, truncated = c._read_capture(
                reader.fileno(),
                c.MAX_CAPTURE_BYTES,
                time.monotonic() + 5,
                NoExit(),  # type: ignore[arg-type]
            )
            elapsed = time.monotonic() - started
        finally:
            reader.close()
            thread.join(timeout=5)
        self.assertFalse(truncated)
        self.assertGreaterEqual(elapsed, 0.1)
        self.assertTrue(capture.endswith(b"END\x00"))
        parsed_definition, environment = c.parse_capture_stream(
            capture, "deepseek"
        )
        self.assertEqual(parsed_definition, definition)
        self.assertEqual(environment["APP_COMPONENT"], b"BACKEND")
        self.assertEqual(environment["TRAILING_TAG"], b"END")

    def test_capture_reader_interrupts_on_deadline_and_cancellation(self) -> None:
        class NoExit:
            def poll(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "cancel-requested"
            reader, writer = socket.socketpair()
            try:
                started = time.monotonic()
                with self.assertRaises(c._CaptureControlInterrupted) as raised:
                    c._read_capture(
                        reader.fileno(),
                        c.MAX_CAPTURE_BYTES,
                        time.monotonic() + 0.2,
                        NoExit(),  # type: ignore[arg-type]
                        cancel_marker=marker,
                    )
                self.assertEqual(raised.exception.reason, "timeout")
                self.assertLess(time.monotonic() - started, 2.0)
            finally:
                reader.close()
                writer.close()

            # An explicit cancellation is polled while the capture is still
            # incomplete instead of waiting for the whole-run deadline.
            marker.write_text("cancel\n", encoding="utf-8")
            reader, writer = socket.socketpair()
            try:
                started = time.monotonic()
                with self.assertRaises(c._CaptureControlInterrupted) as raised:
                    c._read_capture(
                        reader.fileno(),
                        c.MAX_CAPTURE_BYTES,
                        time.monotonic() + 30,
                        NoExit(),  # type: ignore[arg-type]
                        cancel_marker=marker,
                    )
                self.assertEqual(raised.exception.reason, "cancelled")
                self.assertLess(time.monotonic() - started, 2.0)
            finally:
                reader.close()
                writer.close()

    def test_capture_reader_deadline_wins_over_simultaneous_cancel(self) -> None:
        class NoExit:
            def poll(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "cancel-requested"
            marker.write_text("cancel\n", encoding="utf-8")
            reader, writer = socket.socketpair()
            try:
                with self.assertRaises(c._CaptureControlInterrupted) as raised:
                    c._read_capture(
                        reader.fileno(),
                        c.MAX_CAPTURE_BYTES,
                        time.monotonic() - 1,
                        NoExit(),  # type: ignore[arg-type]
                        cancel_marker=marker,
                    )
                self.assertEqual(raised.exception.reason, "timeout")
            finally:
                reader.close()
                writer.close()

    def test_capture_reader_leaves_malformed_capture_to_classification(self) -> None:
        class NoExit:
            def poll(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "cancel-requested"
            reader, writer = socket.socketpair()
            try:
                writer.sendall(b"BOGUS\x00")
                writer.close()
                data, truncated = c._read_capture(
                    reader.fileno(),
                    c.MAX_CAPTURE_BYTES,
                    time.monotonic() + 5,
                    NoExit(),  # type: ignore[arg-type]
                    cancel_marker=marker,
                )
            finally:
                reader.close()
            self.assertFalse(truncated)
            with self.assertRaises(c.ProviderError) as raised:
                c.parse_capture_stream(data, "deepseek")
            self.assertEqual(
                raised.exception.code, "credential_capture_unavailable"
            )

    def test_capture_reader_marks_oversized_and_missing_without_control(self) -> None:
        class NoExit:
            def poll(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "cancel-requested"
            reader, writer = socket.socketpair()
            try:
                writer.sendall(b"123456789\x00")
                writer.close()
                data, truncated = c._read_capture(
                    reader.fileno(),
                    4,
                    time.monotonic() + 5,
                    NoExit(),  # type: ignore[arg-type]
                    cancel_marker=marker,
                )
            finally:
                reader.close()
            self.assertTrue(truncated)
            self.assertEqual(data, b"1234")

            # A shell that exits without writing anything stays a capture
            # failure, not a timeout or cancellation.
            reader, writer = socket.socketpair()
            try:
                writer.close()
                data, truncated = c._read_capture(
                    reader.fileno(),
                    c.MAX_CAPTURE_BYTES,
                    time.monotonic() + 5,
                    NoExit(),  # type: ignore[arg-type]
                    cancel_marker=marker,
                )
            finally:
                reader.close()
            self.assertFalse(truncated)
            with self.assertRaises(c.ProviderError) as raised:
                c.parse_capture_stream(data, "deepseek")
            self.assertEqual(
                raised.exception.code, "credential_capture_unavailable"
            )

    def test_sensitive_capture_seeds_plain_and_reassigned_assignments(self) -> None:
        definition = (
            "deepseek ()\n{\n"
            "    export ANTHROPIC_AUTH_TOKEN=prior_fixture_value\n"
            "    ANTHROPIC_AUTH_TOKEN=reassigned_fixture_value\n"
            "    PLAIN_API_KEY=plain_fixture_value\n"
            "    export ANTHROPIC_MODEL=benign-model\n"
            '    claude "$@"\n'
            "}\n"
        )
        spec = c.parse_wrapper_definition(definition, "deepseek")
        values = c.capture_sensitive_values(
            spec, {"INHERITED_PASSWORD": b"inherited_fixture_value"}
        )
        self.assertIn(b"prior_fixture_value", values)
        self.assertIn(b"reassigned_fixture_value", values)
        self.assertIn(b"plain_fixture_value", values)
        self.assertIn(b"inherited_fixture_value", values)
        self.assertNotIn(b"benign-model", values)

        # Bash preserves an existing export attribute across plain
        # reassignment, so this is the value the provider actually receives.
        completed = subprocess.run(
            [
                "bash",
                "-c",
                "export ANTHROPIC_AUTH_TOKEN=prior_fixture_value; "
                "ANTHROPIC_AUTH_TOKEN=reassigned_fixture_value; "
                + sys.executable
                + " -c "
                + shell_quote(
                    'import os; print(os.environ.get("ANTHROPIC_AUTH_TOKEN", ""))'
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "reassigned_fixture_value")

    def test_redactor_handles_nested_json_escaped_credentials(self) -> None:
        secret = 'canary-"quoted"\\backslash-café-é-0123456789abc'
        raw = secret.encode("utf-8")
        document = {
            "result_version": 1,
            "operation": "proposal",
            "payload": {
                **valid_payload("proposal"),
                "rationale": "prefix " + secret + " suffix",
            },
        }
        wire = (
            json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": json.dumps(document),
                    "num_turns": 1,
                    "session_id": "s",
                    "usage": {},
                }
            )
            + "\n"
        ).encode("utf-8")
        # The literal credential never appears; it exists only in nested
        # JSON-escaped spellings, which the previous redactor missed.
        self.assertNotIn(raw, wire)
        redactor = c.Redactor([raw])
        sanitized = redactor.sanitize(wire)
        self.assertNotIn(raw, sanitized)
        for variant in c._redaction_variants(raw):
            self.assertNotIn(variant, sanitized)
        envelope = json.loads(sanitized.decode("utf-8").strip())
        inner = json.loads(envelope["result"])
        rationale = inner["payload"]["rationale"]
        self.assertNotIn(secret, rationale)
        self.assertIn("[REDACTED]", rationale)
        validated = c.validate_completion(sanitized, "proposal")
        self.assertNotIn(secret, validated["payload"]["rationale"])
        self.assertIn("[REDACTED]", validated["payload"]["rationale"])

    def test_persisted_stream_blocks_arbitrary_unicode_escapes(self) -> None:
        secret = "token-canary-unicode-0123456789abcdef"
        redactor = c.Redactor([secret.encode("utf-8")])
        for mixed in (False, True):
            with self.subTest(mixed=mixed):
                line = escaped_result_line(secret, mixed)
                self.assertNotIn(secret.encode("utf-8"), line)
                buffer = c.CaptureBuffer(1_000_000)
                buffer.feed(line)
                sanitized = c.sanitize_capture(buffer, redactor)
                self.assertNotIn(secret.encode("utf-8"), sanitized)
                event = json.loads(sanitized.decode("utf-8").strip())
                self.assertEqual(event["type"], "result")
                inner = json.loads(event["result"])
                self.assertNotIn(secret, json.dumps(inner))
                self.assertIn("[REDACTED]", inner["payload"]["rationale"])
                validated = c.validate_completion(sanitized, "proposal")
                self.assertNotIn(secret, validated["payload"]["rationale"])
                self.assertIn("[REDACTED]", validated["payload"]["rationale"])
        withheld = c.sanitize_persisted_stream(
            redactor, b"\xff\\u0074\xff\n"
        )
        self.assertEqual(withheld, c.WITHHELD_LINE + b"\n")

    def test_sanitize_structure_redacts_decoded_values(self) -> None:
        secret = 'decoded-"canary"\\café-0123456789'
        redactor = c.Redactor([secret.encode("utf-8")])
        structure = {
            "rationale": "prefix " + secret + " suffix",
            "nested": [secret, {"value": secret}],
            "count": 1,
        }
        sanitized = c.sanitize_structure(redactor, structure)
        rendered = json.dumps(sanitized, ensure_ascii=False)
        self.assertNotIn(secret, rendered)
        self.assertEqual(sanitized["count"], 1)
        self.assertIn("[REDACTED]", sanitized["rationale"])

    def test_redactor_truncation_handles_escaped_representations(self) -> None:
        secret = 'truncate-"quoted"\\café-0123456789abcdef'
        raw = secret.encode("utf-8")
        redactor = c.Redactor([raw])
        longest = max(c._redaction_variants(raw), key=len)
        partial = b"prefix " + longest[: max(1, len(longest) - 3)]
        stripped = redactor.strip_partial_suffix(partial)
        self.assertNotIn(longest[: len(longest) - 3], stripped)
        self.assertIn(b"[REDACTED]", stripped)
        buffer = c.CaptureBuffer(max(1, len(longest) - 2))
        buffer.feed(longest)
        self.assertTrue(buffer.truncated)
        sanitized = c.sanitize_capture(buffer, redactor)
        self.assertNotIn(raw, sanitized)
        for variant in c._redaction_variants(raw):
            self.assertNotIn(variant, sanitized)

    def test_redactor_handles_split_values_and_token_patterns(self) -> None:
        secret = b"split-secret-canary-0123456789"
        redactor = c.Redactor([secret])
        buffer = c.CaptureBuffer(1024)
        for chunk in (b"before split-sec", b"ret-canary-0123", b"456789 after"):
            buffer.feed(chunk)
        sanitized = c.sanitize_capture(buffer, redactor)
        self.assertNotIn(secret, sanitized)
        self.assertIn(b"[REDACTED]", sanitized)
        pattern = c.Redactor([]).sanitize(
            b"sk-ant-abcdefghijklmnopqrstuvwxyz Bearer abcdefghijklmnopqrstuvwxyz"
        )
        self.assertNotIn(b"sk-ant-abcdefghijklmnopqrstuvwxyz", pattern)
        self.assertNotIn(b"Bearer abcdefghijklmnopqrstuvwxyz", pattern)
        benign = c.Redactor([]).sanitize(b"deepseek-chat claude-opus glm")
        self.assertEqual(benign, b"deepseek-chat claude-opus glm")
        self.assertFalse(c.is_sensitive_name("TOKENIZERS_PARALLELISM"))
        self.assertFalse(c.is_sensitive_name("ANTHROPIC_MODEL"))
        for name in (
            "ANTHROPIC_AUTH_TOKEN",
            "CLIPROXY_API_KEY",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "CLIENT_SECRET",
        ):
            self.assertTrue(c.is_sensitive_name(name), name)

    def test_redactor_truncation_never_emits_partial_secret(self) -> None:
        secret = b"0123456789abcdef" * 4
        redactor = c.Redactor([secret])
        buffer = c.CaptureBuffer(len(secret) // 2)
        buffer.feed(secret)
        self.assertTrue(buffer.truncated)
        sanitized = c.sanitize_capture(buffer, redactor)
        self.assertNotIn(secret[: len(secret) // 2], sanitized)

    def test_completion_envelope_and_all_payload_schemas(self) -> None:
        for operation in c.OPERATIONS:
            with self.subTest(operation=operation):
                validated = c.validate_completion(
                    completion_stream(operation), operation
                )
                self.assertEqual(validated["payload"], valid_payload(operation))
                self.assertEqual(len(validated["payload_sha256"]), 64)
        fenced = c.validate_completion(
            completion_stream("proposal", fenced=True), "proposal"
        )
        self.assertEqual(fenced["envelope"]["subtype"], "success")

    def test_completion_rejects_invalid_envelopes_and_payloads(self) -> None:
        cases: list[tuple[str, bytes, str, str]] = [
            ("empty", b"", "proposal", "invalid_output"),
            ("not-json", b"not json\n", "proposal", "invalid_output"),
            (
                "no-result",
                json.dumps({"type": "system"}).encode() + b"\n",
                "proposal",
                "invalid_output",
            ),
            (
                "two-results",
                completion_stream("proposal")
                + envelope_line("proposal").encode()
                + b"\n",
                "proposal",
                "invalid_output",
            ),
            (
                "empty-result",
                completion_stream("proposal", text="   "),
                "proposal",
                "invalid_output",
            ),
            (
                "error-envelope",
                completion_stream(
                    "proposal",
                    subtype="error_during_execution",
                    is_error=True,
                    text="execution failed",
                ),
                "proposal",
                "execution_failed",
            ),
            (
                "wrong-operation",
                completion_stream("consensus"),
                "proposal",
                "invalid_output",
            ),
            (
                "bad-version",
                completion_stream(
                    "proposal",
                    text=json.dumps(
                        {
                            "result_version": 2,
                            "operation": "proposal",
                            "payload": valid_payload("proposal"),
                        }
                    ),
                ),
                "proposal",
                "invalid_output",
            ),
            (
                "float-version",
                completion_stream(
                    "proposal",
                    text=json.dumps(
                        {
                            "result_version": 1.0,
                            "operation": "proposal",
                            "payload": valid_payload("proposal"),
                        }
                    ),
                ),
                "proposal",
                "invalid_output",
            ),
            (
                "bad-payload-keys",
                completion_stream(
                    "proposal",
                    payload={"approach": "only one"},
                ),
                "proposal",
                "invalid_output",
            ),
            (
                "empty-list",
                completion_stream(
                    "proposal",
                    payload={**valid_payload("proposal"), "testing": []},
                ),
                "proposal",
                "invalid_output",
            ),
            (
                "bad-consensus-digest",
                completion_stream(
                    "consensus",
                    payload={
                        **valid_payload("consensus"),
                        "candidate_sha256": "A" * 64,
                    },
                ),
                "consensus",
                "invalid_output",
            ),
            (
                "escaping-path",
                completion_stream(
                    "implementation",
                    payload={
                        **valid_payload("implementation"),
                        "changed_paths": ["../outside"],
                    },
                ),
                "implementation",
                "invalid_output",
            ),
        ]
        for label, stdout, operation, code in cases:
            with self.subTest(label=label):
                with self.assertRaises(c.ProviderError) as raised:
                    c.validate_completion(stdout, operation)
                self.assertEqual(raised.exception.code, code)
        with self.assertRaises(c.ProviderError) as raised:
            c.validate_completion(
                completion_stream(
                    "proposal",
                    payload={**valid_payload("proposal"), "approach": "x" * 9000},
                ),
                "proposal",
            )
        self.assertEqual(raised.exception.code, "output_limit")

    def test_completion_envelope_error_classification(self) -> None:
        for text, code in (
            ("401 unauthorized", "auth_failed"),
            ("429 rate limit", "rate_limited"),
            ("insufficient_quota", "quota_exceeded"),
            ("provider crashed", "execution_failed"),
        ):
            with self.subTest(code=code):
                stream = completion_stream(
                    "proposal",
                    subtype="error_during_execution",
                    is_error=True,
                    text=text,
                )
                with self.assertRaises(c.ProviderError) as raised:
                    c.validate_completion(stream, "proposal")
                self.assertEqual(raised.exception.code, code)

    def test_failure_classification_categories(self) -> None:
        for text, exit_code, code in (
            (b"401 Unauthorized", 1, "auth_failed"),
            (b"invalid api key", 1, "auth_failed"),
            (b"429 too many requests", 1, "rate_limited"),
            (b"rate limit exceeded", 1, "rate_limited"),
            (b"quota exhausted", 1, "quota_exceeded"),
            (b"payment required", 1, "quota_exceeded"),
            (b"boom", 2, "execution_failed"),
            (b"claude: command not found", 127, "provider_unavailable"),
        ):
            with self.subTest(code=code, text=text):
                self.assertEqual(
                    c.classify_failure(text, exit_code).code, code
                )

    def test_provider_argv_enforces_readonly_and_writer_tools(self) -> None:
        readonly = c.provider_argv("proposal", "readonly")
        writer = c.provider_argv("implementation", "workspace_write")
        joined_readonly = " ".join(readonly)
        joined_writer = " ".join(writer)
        self.assertIn("--permission-mode plan", joined_readonly)
        self.assertIn("--tools Read,Glob,Grep", joined_readonly)
        self.assertIn("--allowedTools Read,Glob,Grep", joined_readonly)
        self.assertNotIn("--tools Read,Glob,Grep,Bash", joined_readonly)
        self.assertIn("--permission-mode acceptEdits", joined_writer)
        self.assertIn("Read,Write,Edit,Glob,Grep,Bash", joined_writer)
        for args in (readonly, writer):
            joined = " ".join(args)
            self.assertIn("--strict-mcp-config", joined)
            self.assertIn('{"mcpServers":{}}', joined)
            self.assertIn("--disable-slash-commands", joined)
            self.assertIn("--no-session-persistence", joined)
            self.assertNotIn("bypassPermissions", joined)
            self.assertNotIn("dangerously-skip-permissions", joined)
            self.assertNotIn("--add-dir", " ".join(readonly))

    def test_bwrap_command_mounts_workspace_and_protects_git(self) -> None:
        if not c.bwrap_executable():
            self.skipTest("bwrap is not installed")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = git_repo(root / "repo")
            job = root / "job"
            scratch = job / "scratch"
            channel = job / "channel"
            scratch.mkdir(parents=True)
            channel.mkdir()
            shell = ["bash", "-ic", "true"]
            readonly = c.bwrap_command(
                workspace, "readonly", shell
            )
            writer = c.bwrap_command(
                workspace,
                "workspace_write",
                shell,
                scratch=scratch,
                channel=channel,
                git_dir=workspace / ".git",
                git_common_dir=workspace / ".git",
            )

            def robind_destinations(command: list[str]) -> list[str]:
                return [
                    command[index + 2]
                    for index, value in enumerate(command)
                    if value == "--ro-bind" and index + 2 < len(command)
                ]

            self.assertIn("--ro-bind", readonly)
            self.assertNotIn("--bind", readonly)
            for flag in ("--unshare-pid", "--die-with-parent", "--cap-drop"):
                self.assertIn(flag, writer)
            self.assertNotIn("--sync-fd", writer)
            self.assertEqual(
                writer.index("--bind") + 1, writer.index(str(workspace))
            )
            self.assertIn(str(workspace / ".git"), writer)
            self.assertIn(str(scratch), writer)
            self.assertIn(str(channel), writer)
            self.assertIn(
                str(workspace / ".git"), robind_destinations(writer)
            )
            self.assertLess(
                writer.index("--bind"),
                writer.index(str(workspace / ".git"), writer.index("--bind")),
            )

            worktree = root / "linked"
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(workspace),
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "linked-test",
                    str(worktree),
                ],
                check=True,
            )
            identity = runner.canonical_workspace(worktree)
            common = Path(identity["git_common_dir"])
            self.assertNotEqual(common, worktree / ".git")
            self.assertTrue((worktree / ".git").is_file())
            # Call the C boundary the way an independent caller does: only the
            # resolved administrative directories are supplied.  The linked
            # worktree marker must still be remounted read-only.
            resolved = subprocess.run(
                [
                    "git",
                    "-C",
                    str(worktree),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-dir",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            resolved_git_dir = Path(resolved.stdout.strip())
            linked = c.bwrap_command(
                worktree,
                "workspace_write",
                shell,
                scratch=scratch,
                channel=channel,
                git_dir=resolved_git_dir,
                git_common_dir=common,
            )
            self.assertIn(str(worktree / ".git"), linked)
            self.assertIn(str(common), linked)
            self.assertLess(
                linked.index("--bind"),
                linked.index(str(common)),
            )
            destinations = robind_destinations(linked)
            self.assertIn(str(worktree / ".git"), destinations)
            self.assertIn(str(common), destinations)
            self.assertIn(str(resolved_git_dir), destinations)
            self.assertLess(
                linked.index("--bind"),
                linked.index(str(worktree / ".git"), linked.index("--bind")),
            )

    def test_isolation_status_is_reported_not_assumed(self) -> None:
        self.assertIsInstance(ISOLATION_OK, bool)
        if not ISOLATION_OK:
            self.assertTrue(ISOLATION_REASON)
            self.assertIn("bubblewrap", ISOLATION_REASON or "")

    def test_path_layout_rejects_overlap_and_symlink_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = git_repo(root / "repo")
            job = root / "job"
            job.mkdir()
            scratch = job / "scratch"
            channel = job / "channel"
            scratch.mkdir()
            channel.mkdir()
            c.validate_path_layout(
                workspace, job, scratch, channel, [root / "state"]
            )
            with self.assertRaises(c.ProviderError):
                c.validate_path_layout(
                    workspace, workspace / "job", scratch, channel, []
                )
            outside = root / "outside"
            outside.mkdir()
            link = job / "link"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(c.ProviderError):
                c.validate_path_layout(
                    workspace, job, link, channel, []
                )
            with self.assertRaises(c.ProviderError):
                c.validate_path_layout(
                    workspace, job, scratch, channel, [workspace]
                )

    def test_reserved_profile_override_is_narrow(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rcfile = write_rcfile(root / "rc", "deepseek")
            config = root / "agents.json"
            config.write_text(
                json.dumps(
                    {"agents": {"deepseek": {"provider_rcfile": str(rcfile)}}}
                ),
                encoding="utf-8",
            )
            profiles = runner.load_profiles(config)
            self.assertEqual(profiles["deepseek"]["provider"], "deepseek")
            self.assertEqual(
                profiles["deepseek"]["provider_rcfile"], str(rcfile)
            )
            self.assertIn("deepseek-harness", profiles)
            self.assertNotEqual(
                profiles["deepseek-harness"]["argv"], profiles["deepseek"]["argv"]
            )
            for override in (
                {"argv": ["claude"]},
                {"prompt_transport": "arg"},
                {"provider": "glm"},
                {"model_args": ["--model", "{model}"]},
            ):
                config.write_text(
                    json.dumps({"agents": {"deepseek": override}}),
                    encoding="utf-8",
                )
                with self.assertRaises(runner.RunnerError):
                    runner.load_profiles(config)

    def test_launch_rejects_role_and_operation_overrides_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = root / "task.md"
            task.write_text("task\n", encoding="utf-8")
            rcfile = write_rcfile(
                root / "rc", "glm", startup="touch /tmp/c-provider-should-not-run\n"
            )
            config = root / "agents.json"
            config.write_text(
                json.dumps({"agents": {"glm": {"provider_rcfile": str(rcfile)}}}),
                encoding="utf-8",
            )
            env = clean_env()
            env["AGENT_ORCHESTRATOR_HOME"] = str(root / "state")
            marker = Path("/tmp/c-provider-should-not-run")
            marker.unlink(missing_ok=True)

            def run(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, str(RUNNER), "launch", *args],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30,
                    check=False,
                )

            base = [
                "--workspace",
                str(root),
                "--task-file",
                str(task),
                "--config",
                str(config),
                "--allow-unstructured-task",
                "--no-notify",
                "--json",
            ]
            result = run(
                "--cli", "glm", "--operation", "implementation",
                "--approved-executor", "glm", *base,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized_role", result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse((root / "state" / "jobs").exists())

            result = run(
                "--cli", "glm", "--approved-executor", "glm", *base,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--operation", result.stderr)

            result = run(
                "--cli", "glm", "--operation", "proposal",
                "--approved-executor", "glm", "--model", "x", *base,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("widening invocation flags", result.stderr)
            self.assertFalse(marker.exists())

    def test_launch_without_isolation_never_executes_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = git_repo(root / "repo")
            task = root / "task.md"
            task.write_text("do not run\n", encoding="utf-8")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for executable in ("bash", "git", "python3"):
                found = shutil.which(executable)
                if found:
                    (bin_dir / executable).symlink_to(found)
            marker = root / "provider-ran"
            rcfile = write_rcfile(
                root / "rc",
                "deepseek",
                startup=f"touch {shell_quote(str(marker))}\n",
            )
            config = root / "agents.json"
            config.write_text(
                json.dumps(
                    {"agents": {"deepseek": {"provider_rcfile": str(rcfile)}}}
                ),
                encoding="utf-8",
            )
            env = clean_env()
            env["PATH"] = str(bin_dir)
            env["AGENT_ORCHESTRATOR_HOME"] = str(root / "state")
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "launch",
                    "--cli",
                    "deepseek",
                    "--operation",
                    "proposal",
                    "--approved-executor",
                    "deepseek",
                    "--workspace",
                    str(repo),
                    "--task-file",
                    str(task),
                    "--config",
                    str(config),
                    "--allow-unstructured-task",
                    "--no-notify",
                    "--json",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("isolation_unavailable", result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse((root / "state" / "jobs").exists())

    def test_named_worker_without_isolation_persists_safe_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = git_repo(root / "repo")
            state = root / "state"
            profile = provider_profile("deepseek")
            binding = c.build_binding("deepseek", profile, "proposal")
            job, _meta = write_job_meta(
                state,
                repo,
                "isolation-failure",
                binding,
                profile,
                capability="readonly",
                lease=None,
                worker_pid=None,
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for executable in ("bash", "git", "python3"):
                found = shutil.which(executable)
                if found:
                    (bin_dir / executable).symlink_to(found)
            env = clean_env()
            env["PATH"] = str(bin_dir)
            env["AGENT_ORCHESTRATOR_HOME"] = str(state)
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "_worker",
                    "--job-dir",
                    str(job),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            record = json.loads((job / "result.json").read_text())
            self.assertEqual(record["state"], "failed")
            self.assertEqual(
                record["provider_error"]["code"], "isolation_unavailable"
            )
            evidence = json.loads((job / "provider-result.json").read_text())
            self.assertFalse(evidence["validated"])
            self.assertEqual(evidence["result_version"], 1)
            self.assertEqual(
                evidence["capability_table_sha256"],
                c.CAPABILITY_TABLE_SHA256,
            )
            self.assertEqual((job / "stdout.log").read_bytes(), b"")
            self.assertEqual((job / "stderr.log").read_bytes(), b"")

    def test_admission_conflicts_distinguish_readers_and_writers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = git_repo(root / "repo")
            state = root / "state"
            env = clean_env()
            env["AGENT_ORCHESTRATOR_HOME"] = str(state)
            with mock.patch.dict(os.environ, env, clear=False):
                identity = runner.canonical_workspace(repo)
                deepseek = provider_profile("deepseek")
                readonly_binding = c.build_binding(
                    "deepseek", deepseek, "proposal"
                )
                writer_binding = c.build_binding(
                    "deepseek", deepseek, "implementation"
                )
                write_job_meta(
                    state,
                    repo,
                    "writer-live",
                    writer_binding,
                    deepseek,
                    capability="workspace_write",
                    lease={"epoch": "22" * 16},
                    worker_pid=os.getpid(),
                )
                conflicts = runner.provider_admission_conflicts(
                    identity, "readonly"
                )
                self.assertTrue(any("writer-live" in item for item in conflicts))
                self.assertFalse(
                    any("writer-live" in item for item in conflicts if "readonly" in item)
                )

                writer_dir, _ = write_job_meta(
                    state,
                    repo,
                    "reader-live",
                    readonly_binding,
                    deepseek,
                    capability="readonly",
                    lease=None,
                    worker_pid=os.getpid(),
                )
                _ = writer_dir
                # The live writer still conflicts with a readonly launch.
                conflicts = runner.provider_admission_conflicts(
                    identity, "readonly"
                )
                self.assertTrue(any("writer-live" in item for item in conflicts))
                # A writer launch conflicts with the active reader.
                conflicts = runner.provider_admission_conflicts(
                    identity, "workspace_write"
                )
                self.assertTrue(any("reader-live" in item for item in conflicts))
                self.assertFalse(any("writer-live" in item for item in conflicts))
                # Classify the reader as readonly and the legacy writer as a writer.
                self.assertEqual(
                    c.classify_job_capability(
                        runner.read_json(
                            state / "jobs" / "reader-live" / "meta.json"
                        )
                    ),
                    "readonly",
                )
                self.assertEqual(
                    c.classify_job_capability(
                        runner.read_json(
                            state / "jobs" / "writer-live" / "meta.json"
                        )
                    ),
                    "workspace_write",
                )
                self.assertEqual(
                    c.classify_job_capability({"workspace_lease": {"epoch": "x"}}),
                    "workspace_write",
                )
                self.assertEqual(c.classify_job_capability(None), "unknown")

    def test_readers_are_visible_across_state_homes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = git_repo(root / "repo")
            state_a = root / "state-a"
            state_b = root / "state-b"
            deepseek = provider_profile("deepseek")
            binding = c.build_binding("deepseek", deepseek, "proposal")
            job_a, _ = write_job_meta(
                state_a,
                repo,
                "reader-a",
                binding,
                deepseek,
                capability="readonly",
                lease=None,
                worker_pid=os.getpid(),
            )
            env_a = clean_env()
            env_a["AGENT_ORCHESTRATOR_HOME"] = str(state_a)
            with mock.patch.dict(os.environ, env_a, clear=False):
                identity = runner.canonical_workspace(repo)
                reservation = runner.b1_module().reserve_active_job(
                    identity, "reader-a", job_a, os.getpid()
                )
            self.assertTrue(reservation)
            env_b = clean_env()
            env_b["AGENT_ORCHESTRATOR_HOME"] = str(state_b)
            with mock.patch.dict(os.environ, env_b, clear=False):
                identity_b = runner.canonical_workspace(repo)
                conflicts = runner.provider_admission_conflicts(
                    identity_b, "workspace_write"
                )
            self.assertTrue(any("reader-a" in item for item in conflicts))
            self.assertFalse((state_b / "jobs").exists())

    def test_old_readonly_cancellation_cannot_release_writer_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = git_repo(root / "repo")
            state = root / "state"
            env = clean_env()
            env["AGENT_ORCHESTRATOR_HOME"] = str(state)
            with mock.patch.dict(os.environ, env, clear=False):
                identity = runner.canonical_workspace(repo)
                writer_dir = state / "jobs" / "writer-job"
                writer_dir.mkdir(parents=True)
                lease = runner.b2_module().acquire_writer_lease(
                    identity, "writer-job", writer_dir
                )
                try:
                    deepseek = provider_profile("deepseek")
                    binding = c.build_binding(
                        "deepseek", deepseek, "proposal"
                    )
                    readonly_dir, _ = write_job_meta(
                        state,
                        repo,
                        "old-reader",
                        binding,
                        deepseek,
                        capability="readonly",
                        lease=None,
                        worker_pid=os.getpid(),
                    )
                    namespace = argparse.Namespace(
                        job_id="old-reader", force=False, json=True
                    )
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(
                            runner.command_cancel(namespace), 0
                        )
                    self.assertTrue((readonly_dir / "cancel-requested").exists())
                    owner = runner.b2_module().read_owner(identity)
                    self.assertEqual(owner["job_id"], "writer-job")
                    self.assertEqual(owner["state"], "admission")
                    self.assertTrue(
                        runner.b2_module().probe_lock(identity)["held"]
                    )
                finally:
                    lease.abort("test cleanup")
                    lease.close_parent_copy()

    def test_wrapper_component_preserves_argv_stdin_and_discards_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            write_fake_claude(bin_dir)
            rcfile = write_rcfile(
                root / "rc",
                "deepseek",
                startup=(
                    "echo startup-stdout-canary\n"
                    "echo startup-stderr-canary >&2\n"
                    "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
                ),
            )
            profile = provider_profile("deepseek", rcfile)
            prompt = root / "prompt.md"
            injection_marker = root / "injected"
            prompt_text = (
                "prompt $(touch " + str(injection_marker) + ") `id`\n"
                'quoted "value" ; $HOME\n'
            )
            prompt.write_text(prompt_text, encoding="utf-8")
            parent_control, child_control = socket.socketpair()
            stdout_r, stdout_w = os.pipe()
            stderr_r, stderr_w = os.pipe()
            arguments = c.provider_argv("proposal", "readonly")
            command = c.shell_command(
                profile, prompt, child_control.fileno(), arguments
            )
            env = clean_env()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            env["C_FAKE_RESULT"] = result_text("proposal")
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_w,
                stderr=stderr_w,
                env=env,
                close_fds=True,
                pass_fds=(child_control.fileno(),),
            )
            child_control.close()
            os.close(stdout_w)
            os.close(stderr_w)
            capture = b""
            while not capture.endswith(b"END\x00"):
                chunk = parent_control.recv(65536)
                if not chunk:
                    break
                capture += chunk
            definition, environment = c.parse_capture_stream(
                capture, "deepseek"
            )
            spec = c.parse_wrapper_definition(definition, "deepseek")
            redactor = c.Redactor(
                c.capture_sensitive_values(spec, environment)
            )
            parent_control.sendall(b"1")
            parent_control.close()
            stdout_marker = c.MarkerCapture(10_000_000, c.STDOUT_MARKER)
            stderr_marker = c.MarkerCapture(10_000_000, c.STDERR_MARKER)
            raw_stderr = bytearray()
            pending = [stdout_r, stderr_r]
            while pending:
                ready, _, _ = select.select(pending, [], [], 10)
                if not ready:
                    break
                for descriptor in ready:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        pending.remove(descriptor)
                    elif descriptor == stdout_r:
                        stdout_marker.feed(chunk)
                    else:
                        raw_stderr.extend(chunk)
                        stderr_marker.feed(chunk)
            os.close(stdout_r)
            os.close(stderr_r)
            process.wait(timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertFalse(injection_marker.exists())
            validated = c.validate_completion(
                redactor.sanitize(bytes(stdout_marker.data)), "proposal"
            )
            self.assertEqual(validated["payload"], valid_payload("proposal"))
            sanitized_stderr = redactor.sanitize(bytes(stderr_marker.data))
            self.assertIn(b"FAKE_ARGV=", sanitized_stderr)
            self.assertNotIn(b"startup-stdout-canary", sanitized_stderr)
            self.assertNotIn(b"startup-stderr-canary", sanitized_stderr)
            self.assertNotIn(b"startup-stderr-canary", bytes(stdout_marker.data))
            self.assertNotIn(b"test-token-canary-0123456789", sanitized_stderr)
            self.assertIn(b"FAKE_STDIN_SHA=", sanitized_stderr)
            expected_sha = hashlib.sha256(
                prompt_text.encode("utf-8")
            ).hexdigest().encode()
            self.assertIn(expected_sha, sanitized_stderr)
            expected_args = json.dumps(arguments).encode()
            self.assertIn(expected_args, sanitized_stderr)
            self.assertTrue(stderr_marker.started)
            if b"startup-stderr-canary" not in raw_stderr:
                self.fail("the rcfile startup canary did not reach the startup stream")
            if b"job control" in raw_stderr.lower():
                self.assertNotIn(b"job control", sanitized_stderr.lower())
            self.assertNotIn(b"job control", capture.lower())

    def test_component_refuses_unsupported_capture_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            marker = root / "provider-ran"
            write_fake_claude(bin_dir)
            rcfile = write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    'export ANTHROPIC_AUTH_TOKEN="$(cat /tmp/nope)"',
                ],
                startup=(
                    "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
                ),
            )
            # The fake claude is replaced by a marker-writing command because
            # the unsupported wrapper must never reach it.
            (bin_dir / "claude").write_text(
                f"#!{sys.executable}\nimport pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            (bin_dir / "claude").chmod(0o755)
            profile = provider_profile("deepseek", rcfile)
            parent_control, child_control = socket.socketpair()
            command = c.shell_command(
                profile,
                root / "prompt-not-executed.md",
                child_control.fileno(),
                c.provider_argv("proposal", "readonly"),
            )
            env = clean_env()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                close_fds=True,
                pass_fds=(child_control.fileno(),),
            )
            child_control.close()
            capture = b""
            while not capture.endswith(b"END\x00"):
                chunk = parent_control.recv(65536)
                if not chunk:
                    break
                capture += chunk
            definition, _environment = c.parse_capture_stream(
                capture, "deepseek"
            )
            with self.assertRaises(c.ProviderError):
                c.parse_wrapper_definition(definition, "deepseek")
            parent_control.close()
            process.wait(timeout=10)
            time.sleep(0.1)
            self.assertFalse(marker.exists())

    def test_shell_guard_refuses_function_backend_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            write_fake_claude(bin_dir)
            marker = root / "delegated-ran"
            secret = "delegated-function-secret-0123456789"
            startup = (
                "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
            )
            wrapper = (
                "deepseek () {\n"
                "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'\n"
                '    claude "$@"\n'
                "}\n"
            )
            delegate = (
                "claude () {\n"
                f"    export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}\n"
                f"    builtin printf ran > {shell_quote(str(marker))}\n"
                f"    {shell_quote(str(bin_dir / 'claude'))} \"$@\"\n"
                "}\n"
            )
            for order in ("before", "after"):
                with self.subTest(order=order):
                    marker.unlink(missing_ok=True)
                    content = (
                        startup + delegate + wrapper
                        if order == "before"
                        else startup + wrapper + delegate
                    )
                    capture, status = run_capture_shell(root, content)
                    self.assertEqual(
                        capture, b"ERR\x00unsupported_delegation\x00END\x00"
                    )
                    self.assertEqual(status, 95)
                    self.assertFalse(marker.exists())
                    self.assertNotIn(secret.encode("utf-8"), capture)
                    with self.assertRaises(c.ProviderError) as raised:
                        c.parse_capture_stream(capture, "deepseek")
                    self.assertEqual(
                        raised.exception.code, "credential_capture_unavailable"
                    )
                    self.assertEqual(
                        raised.exception.message, c.SAFE_DELEGATION_ERROR
                    )

    def test_shell_guard_refuses_alias_backend_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            write_fake_claude(bin_dir)
            startup = (
                "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
            )
            wrapper = (
                "deepseek () {\n"
                "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'\n"
                '    claude "$@"\n'
                "}\n"
            )
            alias_line = (
                "alias claude=" + shell_quote(str(bin_dir / "claude")) + "\n"
            )
            for order in ("before", "after"):
                with self.subTest(order=order):
                    content = (
                        startup + alias_line + wrapper
                        if order == "before"
                        else startup + wrapper + alias_line
                    )
                    capture, status = run_capture_shell(root, content)
                    self.assertEqual(
                        capture, b"ERR\x00unsupported_delegation\x00END\x00"
                    )
                    self.assertEqual(status, 95)
                    with self.assertRaises(c.ProviderError) as raised:
                        c.parse_capture_stream(capture, "deepseek")
                    self.assertEqual(
                        raised.exception.code, "credential_capture_unavailable"
                    )
                    self.assertEqual(
                        raised.exception.message, c.SAFE_DELEGATION_ERROR
                    )

    def test_shell_guard_reports_missing_external_backend(self) -> None:
        wrapper = (
            "deepseek () {\n"
            "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'\n"
            '    claude "$@"\n'
            "}\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            empty = root / "empty-bin"
            empty.mkdir()
            nonexec = root / "nonexec-bin"
            nonexec.mkdir()
            (nonexec / "claude").write_text("not executable\n", encoding="utf-8")
            (nonexec / "claude").chmod(0o644)
            for label, directory in (
                ("missing", empty),
                ("nonexecutable", nonexec),
            ):
                with self.subTest(case=label):
                    content = (
                        "unset -f claude 2>/dev/null || true\n"
                        "unalias claude 2>/dev/null || true\n"
                        "export PATH=" + shell_quote(str(directory)) + "\n"
                        + wrapper
                    )
                    capture, status = run_capture_shell(
                        root, content, env_path=str(directory)
                    )
                    self.assertEqual(
                        capture, b"ERR\x00missing_backend\x00END\x00"
                    )
                    self.assertEqual(status, 94)
                    with self.assertRaises(c.ProviderError) as raised:
                        c.parse_capture_stream(capture, "deepseek")
                    self.assertEqual(
                        raised.exception.code, "provider_unavailable"
                    )
                    self.assertEqual(
                        raised.exception.message, c.SAFE_BACKEND_ERROR
                    )

    def test_shell_guard_accepts_external_symlink_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real_dir = root / "real"
            real_dir.mkdir()
            bin_dir = root / "bin"
            bin_dir.mkdir()
            record = root / "backend-record"
            target = real_dir / "fake-claude"
            target.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "import pathlib\n"
                "import sys\n"
                f"pathlib.Path({str(record)!r}).write_text("
                "\"|\".join([os.environ.get('ANTHROPIC_AUTH_TOKEN', ''), "
                "*sys.argv[1:]]))\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            (bin_dir / "claude").symlink_to(target)
            rcfile = root / "rc"
            rcfile.write_text(
                "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
                "deepseek () {\n"
                "    export ANTHROPIC_AUTH_TOKEN='symlink-secret-0123456789'\n"
                '    claude "$@"\n'
                "}\n",
                encoding="utf-8",
            )
            prompt = root / "prompt.md"
            prompt.write_text("symlink prompt\n", encoding="utf-8")
            profile = provider_profile("deepseek", rcfile)
            arguments = ["-p", "argument with spaces", "second"]
            parent_control, child_control = socket.socketpair()
            command = c.shell_command(
                profile, prompt, child_control.fileno(), arguments
            )
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=clean_env(),
                close_fds=True,
                pass_fds=(child_control.fileno(),),
            )
            child_control.close()
            capture = b""
            while not capture.endswith(b"END\x00"):
                chunk = parent_control.recv(65536)
                if not chunk:
                    break
                capture += chunk
            definition, environment = c.parse_capture_stream(
                capture, "deepseek"
            )
            spec = c.parse_wrapper_definition(definition, "deepseek")
            self.assertEqual(spec.command, ("claude", '"$@"'))
            self.assertIn(
                b"symlink-secret-0123456789",
                c.capture_sensitive_values(spec, environment),
            )
            parent_control.sendall(b"1")
            parent_control.close()
            process.wait(timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(
                record.read_text(encoding="utf-8"),
                "symlink-secret-0123456789|-p|argument with spaces|second",
            )


@unittest.skipUnless(
    ISOLATION_OK,
    f"bubblewrap isolation blocked in this environment: {ISOLATION_REASON}",
)
class CProviderSandboxTests(unittest.TestCase):
    def make_environment(
        self, root: Path, provider: str = "deepseek"
    ) -> tuple[Path, Path, Path, dict, Path]:
        repo = git_repo(root / "repo")
        state = root / "state"
        bin_dir = root / "bin"
        write_fake_claude(bin_dir)
        rcfile = write_rcfile(
            root / "rc",
            provider,
            startup=(
                "echo startup-stdout-canary\n"
                "echo startup-stderr-canary >&2\n"
                "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
            ),
        )
        config = root / "agents.json"
        config.write_text(
            json.dumps(
                {"agents": {provider: {"provider_rcfile": str(rcfile)}}}
            ),
            encoding="utf-8",
        )
        env = clean_env()
        env["AGENT_ORCHESTRATOR_HOME"] = str(state)
        return repo, state, rcfile, env, config

    def task_file(self, root: Path) -> Path:
        task = root / "task.md"
        task.write_text(
            "Read the repository and return the required result contract.\n",
            encoding="utf-8",
        )
        return task

    def launch(
        self,
        repo: Path,
        task: Path,
        config: Path,
        env: dict[str, str],
        provider: str,
        operation: str,
        *,
        timeout_seconds: int = 10,
        extra: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "launch",
                "--cli",
                provider,
                "--operation",
                operation,
                "--approved-executor",
                provider,
                "--workspace",
                str(repo),
                "--task-file",
                str(task),
                "--config",
                str(config),
                "--timeout-seconds",
                str(timeout_seconds),
                "--allow-unstructured-task",
                "--no-notify",
                "--json",
                *(extra or []),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )

    def wait(self, job_id: str, env: dict[str, str], timeout: float = 30) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "wait",
                    job_id,
                    "--timeout-seconds",
                    "3",
                    "--poll-seconds",
                    "0.2",
                    "--json",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
                check=False,
            )
            if result.returncode in (0, 1):
                return json.loads(result.stdout)
            time.sleep(0.2)
        self.fail(f"job {job_id} did not finish")

    def test_readonly_denies_workspace_git_state_and_outside_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            outside = root / "outside.txt"
            git_config = repo / ".git" / "config"
            before = git_config.read_bytes()
            job_id = "readonly-denies"
            job_dir = state / "jobs" / job_id
            markers = {
                "workspace": str(repo / "tamper.txt"),
                "git": str(git_config),
                "state": str(state / "tamper.txt"),
                "outside": str(outside),
                "scratch": str(job_dir / "scratch" / "tamper.txt"),
                "channel": str(job_dir / "channel" / "tamper.txt"),
            }
            env["C_FAKE_WRITES"] = json.dumps(markers)
            env["C_FAKE_RESULT"] = result_text("proposal")
            task = self.task_file(root)
            result = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                extra=["--job-id", job_id],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "succeeded", status)
            self.assertFalse(Path(markers["workspace"]).exists())
            self.assertEqual(git_config.read_bytes(), before)
            self.assertFalse(Path(markers["state"]).exists())
            self.assertFalse(Path(markers["outside"]).exists())
            self.assertFalse(Path(markers["scratch"]).exists())
            self.assertFalse(Path(markers["channel"]).exists())
            stderr = (job_dir / "stderr.log").read_text()
            writes = json.loads(
                stderr.split("FAKE_WRITES=", 1)[1].splitlines()[0]
            )
            self.assertEqual(set(writes.values()), {"denied"})

    def test_deepseek_writer_can_write_workspace_but_not_git_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            git_config = repo / ".git" / "config"
            before = git_config.read_bytes()
            job_id = "writer-workspace"
            job_dir = state / "jobs" / job_id
            markers = {
                "workspace": str(repo / "written.txt"),
                "git": str(git_config),
                "state": str(state / "tamper.txt"),
                "outside": str(root / "outside.txt"),
                "scratch": str(job_dir / "scratch" / "scratch.txt"),
                "channel": str(job_dir / "channel" / "channel.txt"),
            }
            env["C_FAKE_WRITES"] = json.dumps(markers)
            env["C_FAKE_RESULT"] = result_text("implementation")
            task = self.task_file(root)
            result = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "implementation",
                extra=["--job-id", job_id],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "succeeded", status)
            self.assertTrue(Path(markers["workspace"]).is_file())
            self.assertEqual(git_config.read_bytes(), before)
            self.assertFalse(Path(markers["state"]).exists())
            self.assertFalse(Path(markers["outside"]).exists())
            self.assertTrue(Path(markers["scratch"]).is_file())
            self.assertTrue(Path(markers["channel"]).is_file())
            evidence = json.loads(
                (job_dir / "provider-result.json").read_text()
            )
            self.assertTrue(evidence["validated"])
            self.assertEqual(evidence["capability"], "workspace_write")

    def test_linked_worktree_marker_and_admin_dirs_are_readonly(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = git_repo(root / "main")
            worktree = root / "linked"
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(main),
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "linked-writer",
                    str(worktree),
                ],
                check=True,
            )
            self.assertTrue((worktree / ".git").is_file())
            bin_dir = root / "bin"
            write_fake_claude(bin_dir)
            rcfile = write_rcfile(
                root / "rc",
                "deepseek",
                startup=(
                    "echo startup-stdout-canary\n"
                    "echo startup-stderr-canary >&2\n"
                    "export PATH="
                    + shell_quote(str(bin_dir))
                    + ':"$PATH"\n'
                ),
            )
            config = root / "agents.json"
            config.write_text(
                json.dumps(
                    {"agents": {"deepseek": {"provider_rcfile": str(rcfile)}}}
                ),
                encoding="utf-8",
            )
            env = clean_env()
            env["AGENT_ORCHESTRATOR_HOME"] = str(root / "state")
            resolved = subprocess.run(
                [
                    "git",
                    "-C",
                    str(worktree),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-dir",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            admin_dir = Path(resolved.stdout.strip())
            marker = worktree / ".git"
            admin_head = admin_dir / "HEAD"
            common_config = main / ".git" / "config"
            marker_before = marker.read_bytes()
            head_before = admin_head.read_bytes()
            config_before = common_config.read_bytes()
            job_id = "linked-worktree-writer"
            job_dir = root / "state" / "jobs" / job_id
            markers = {
                "workspace": str(worktree / "written.txt"),
                "marker": str(marker),
                "admin": str(admin_head),
                "common": str(common_config),
            }
            env["C_FAKE_WRITES"] = json.dumps(markers)
            env["C_FAKE_RESULT"] = result_text("implementation")
            task = self.task_file(root)
            result = self.launch(
                worktree,
                task,
                config,
                env,
                "deepseek",
                "implementation",
                extra=["--job-id", job_id],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "succeeded", status)
            self.assertTrue(Path(markers["workspace"]).is_file())
            self.assertEqual(marker.read_bytes(), marker_before)
            self.assertEqual(admin_head.read_bytes(), head_before)
            self.assertEqual(common_config.read_bytes(), config_before)
            stderr = (job_dir / "stderr.log").read_text()
            writes = json.loads(
                stderr.split("FAKE_WRITES=", 1)[1].splitlines()[0]
            )
            self.assertEqual(writes["workspace"], "wrote")
            self.assertEqual(writes["marker"], "denied")
            self.assertEqual(writes["admin"], "denied")
            self.assertEqual(writes["common"], "denied")

    def test_invalid_and_truncated_output_never_persist_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            secret = 'token-canary-output-"quoted"\\café-0123456789abcdef'
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            task = self.task_file(root)
            for mode in ("invalid_echo", "truncated_echo"):
                with self.subTest(mode=mode):
                    env2 = dict(env)
                    env2["C_FAKE_MODE"] = mode
                    env2["C_FAKE_RESULT"] = result_text("proposal")
                    result = self.launch(
                        repo, task, config, env2, "deepseek", "proposal"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    job_id = json.loads(result.stdout)["job_id"]
                    status = self.wait(job_id, env2)
                    self.assertEqual(status["state"], "failed", status)
                    self.assertEqual(
                        status["provider_error"]["code"], "invalid_output"
                    )
                    for path in persisted_files(state / "jobs" / job_id):
                        data = path.read_bytes()
                        self.assertNotIn(secret.encode("utf-8"), data, str(path))
                        for variant in c._redaction_variants(
                            secret.encode("utf-8")
                        ):
                            self.assertNotIn(variant, data, str(path))
                    evidence = json.loads(
                        (
                            state
                            / "jobs"
                            / job_id
                            / "provider-result.json"
                        ).read_text()
                    )
                    self.assertFalse(evidence["validated"])

    def test_glm_cannot_write_even_with_configured_rcfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(
                root, provider="glm"
            )
            env["C_FAKE_RESULT"] = result_text("proposal")
            env["C_FAKE_WRITES"] = json.dumps(
                {"workspace": str(repo / "glm-tamper.txt")}
            )
            task = self.task_file(root)
            result = self.launch(
                repo, task, config, env, "glm", "proposal"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            job_id = json.loads(result.stdout)["job_id"]
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "succeeded", status)
            self.assertFalse((repo / "glm-tamper.txt").exists())
            self.assertEqual(status["provider_result"]["capability"], "readonly")

    def test_split_secrets_and_startup_canaries_never_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            prior = "token-canary-prior-0123456789abcdef"
            secret = 'token-canary-"split"\\café-0123456789abcdef'
            rcfile = root / "rc"
            write_rcfile(
                rcfile,
                "deepseek",
                statements=[
                    # A plain reassignment inherits the export attribute; the
                    # provider receives the reassigned value.
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(prior)}",
                    f"ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "echo startup-stdout-canary\n"
                    "echo startup-stderr-canary >&2\n"
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            env["C_FAKE_RESULT"] = result_text("proposal")
            env["C_FAKE_ECHO_VALUE"] = "1"
            env["C_FAKE_ECHO_IN_PAYLOAD"] = "1"
            env["C_FAKE_EXPECT_VALUE"] = secret
            task = self.task_file(root)
            result = self.launch(
                repo, task, config, env, "deepseek", "proposal"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            job_id = json.loads(result.stdout)["job_id"]
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "succeeded", status)
            self.assertIn(
                "FAKE_TOKEN_IS_EXPECTED=true",
                (state / "jobs" / job_id / "stderr.log").read_text(),
            )
            for path in persisted_files(state):
                data = path.read_bytes()
                self.assertNotIn(secret.encode(), data, str(path))
                for variant in c._redaction_variants(secret.encode("utf-8")):
                    self.assertNotIn(variant, data, str(path))
                self.assertNotIn(prior.encode(), data, str(path))
                self.assertNotIn(b"startup-stdout-canary", data, str(path))
                self.assertNotIn(b"startup-stderr-canary", data, str(path))
                self.assertNotIn(b"job control", data.lower(), str(path))
            provider_result = json.loads(
                (state / "jobs" / job_id / "provider-result.json").read_text()
            )
            self.assertIn(
                "[REDACTED]", provider_result["payload"]["rationale"]
            )

    def test_unicode_escaped_payload_never_persists_native_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            secret = "token-canary-unicode-0123456789abcdef"
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            task = self.task_file(root)
            for mode in ("unicode_escape_payload", "mixed_escape_payload"):
                with self.subTest(mode=mode):
                    env2 = dict(env)
                    env2["C_FAKE_MODE"] = mode
                    env2["C_FAKE_RESULT"] = result_text("proposal")
                    result = self.launch(
                        repo, task, config, env2, "deepseek", "proposal"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    job_id = json.loads(result.stdout)["job_id"]
                    status = self.wait(job_id, env2)
                    self.assertEqual(status["state"], "succeeded", status)
                    job_dir = state / "jobs" / job_id
                    evidence = json.loads(
                        (job_dir / "provider-result.json").read_text()
                    )
                    self.assertTrue(evidence["validated"])
                    self.assertIn(
                        "[REDACTED]", evidence["payload"]["rationale"]
                    )
                    stdout_log = (job_dir / "stdout.log").read_text()
                    result_lines = 0
                    for line in stdout_log.splitlines():
                        if not line.strip():
                            continue
                        event = json.loads(line)
                        if event.get("type") != "result":
                            continue
                        result_lines += 1
                        inner = json.loads(event["result"])
                        self.assertNotIn(secret, json.dumps(inner))
                        self.assertIn(
                            "[REDACTED]", inner["payload"]["rationale"]
                        )
                    self.assertEqual(result_lines, 1)
                    for path in persisted_files(job_dir):
                        data = path.read_bytes()
                        self.assertNotIn(
                            secret.encode("utf-8"), data, str(path)
                        )

    def test_invalid_empty_error_oversized_and_failure_categories(self) -> None:
        cases = (
            ("invalid", "proposal", "invalid_output"),
            ("empty", "proposal", "invalid_output"),
            ("envelope_error_auth", "proposal", "auth_failed"),
            ("auth", "proposal", "auth_failed"),
            ("rate", "proposal", "rate_limited"),
            ("quota", "proposal", "quota_exceeded"),
            ("exec_fail", "proposal", "execution_failed"),
            ("oversized", "proposal", "output_limit"),
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            task = self.task_file(root)
            for mode, operation, code in cases:
                with self.subTest(mode=mode):
                    env2 = dict(env)
                    env2["C_FAKE_MODE"] = mode
                    env2["C_FAKE_RESULT"] = result_text(operation)
                    result = self.launch(
                        repo, task, config, env2, "deepseek", operation
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    job_id = json.loads(result.stdout)["job_id"]
                    status = self.wait(job_id, env2)
                    self.assertEqual(status["state"], "failed", status)
                    self.assertEqual(
                        status["provider_error"]["code"], code, status
                    )

    def test_timeout_and_cancellation_categories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            task = self.task_file(root)
            env["C_FAKE_MODE"] = "sleep"
            result = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                timeout_seconds=1,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            job_id = json.loads(result.stdout)["job_id"]
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "timed_out", status)
            self.assertEqual(status["provider_error"]["code"], "timeout")

            result = self.launch(
                repo, task, config, env, "deepseek", "proposal"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            job_id = json.loads(result.stdout)["job_id"]
            time.sleep(0.5)
            cancelled = subprocess.run(
                [sys.executable, str(RUNNER), "cancel", job_id, "--json"],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
                check=False,
            )
            self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "cancelled", status)
            self.assertEqual(status["provider_error"]["code"], "cancelled")

    def test_no_descendants_survive_pid_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            env["C_FAKE_MODE"] = "descendant"
            env["C_FAKE_RESULT"] = result_text("proposal")
            task = self.task_file(root)
            result = self.launch(
                repo, task, config, env, "deepseek", "proposal"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            job_id = json.loads(result.stdout)["job_id"]
            status = self.wait(job_id, env)
            self.assertEqual(status["state"], "succeeded", status)
            time.sleep(0.5)
            self.assertEqual(pid_cmdline_matches("sleep 2971"), [])

    def test_readonly_launch_refused_while_writer_lease_live(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            with mock.patch.dict(os.environ, env, clear=False):
                identity = runner.canonical_workspace(repo)
                writer_dir = state / "jobs" / "writer-hidden"
                writer_dir.mkdir(parents=True)
                lease = runner.b2_module().acquire_writer_lease(
                    identity, "writer-hidden", writer_dir
                )
                try:
                    task = self.task_file(root)
                    result = self.launch(
                        repo, task, config, env, "deepseek", "proposal"
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("readonly", result.stderr.casefold())
                    self.assertFalse(
                        any(
                            path.name.startswith("deepseek-")
                            for path in (state / "jobs").glob("*")
                        )
                    )
                    owner = runner.b2_module().read_owner(identity)
                    self.assertEqual(owner["job_id"], "writer-hidden")
                    self.assertEqual(owner["state"], "admission")
                finally:
                    lease.abort("test cleanup")
                    lease.close_parent_copy()

    def test_writer_launch_refused_while_reader_active(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, _rcfile, env, config = self.make_environment(root)
            with mock.patch.dict(os.environ, env, clear=False):
                identity = runner.canonical_workspace(repo)
                deepseek = provider_profile("deepseek")
                binding = c.build_binding("deepseek", deepseek, "proposal")
                reader_dir, _ = write_job_meta(
                    state,
                    repo,
                    "reader-hidden",
                    binding,
                    deepseek,
                    capability="readonly",
                    lease=None,
                    worker_pid=os.getpid(),
                )
                runner.b1_module().reserve_active_job(
                    identity, "reader-hidden", reader_dir, os.getpid()
                )
                task = self.task_file(root)
                result = self.launch(
                    repo, task, config, env, "deepseek", "implementation"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("readonly", result.stderr.casefold())
                self.assertFalse(
                    (state / "jobs" / "reader-hidden" / "cancel-requested").exists()
                )


class CProviderTransportShimTests(unittest.TestCase):
    """Pipeline coverage with a non-isolating bwrap shim.

    These tests prove launch/worker/capture/validation behavior only.  They do
    not claim confinement; the real confinement tests skip when namespaces are
    unavailable and never use this shim.
    """

    def make_environment(
        self,
        root: Path,
        provider: str = "deepseek",
        *,
        capture_mode: str = "exec",
    ) -> tuple[Path, Path, dict, Path]:
        repo = git_repo(root / "repo")
        state = root / "state"
        bin_dir = root / "bin"
        write_fake_claude(bin_dir)
        write_fake_bwrap(bin_dir, capture_mode=capture_mode)
        rcfile = write_rcfile(
            root / "rc",
            provider,
            startup=(
                "echo startup-stdout-canary\n"
                "echo startup-stderr-canary >&2\n"
                "export PATH=" + shell_quote(str(bin_dir)) + ':"$PATH"\n'
            ),
        )
        config = root / "agents.json"
        config.write_text(
            json.dumps(
                {"agents": {provider: {"provider_rcfile": str(rcfile)}}}
            ),
            encoding="utf-8",
        )
        env = clean_env()
        env["AGENT_ORCHESTRATOR_HOME"] = str(state)
        env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
        return repo, state, env, config

    def task_file(self, root: Path) -> Path:
        task = root / "task.md"
        task.write_text("Return the required role payload.\n", encoding="utf-8")
        return task

    def launch(
        self,
        repo: Path,
        task: Path,
        config: Path,
        env: dict[str, str],
        provider: str,
        operation: str,
        job_id: str,
        *,
        timeout_seconds: int = 10,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "launch",
                "--cli",
                provider,
                "--operation",
                operation,
                "--approved-executor",
                provider,
                "--workspace",
                str(repo),
                "--task-file",
                str(task),
                "--config",
                str(config),
                "--timeout-seconds",
                str(timeout_seconds),
                "--job-id",
                job_id,
                "--allow-unstructured-task",
                "--no-notify",
                "--json",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )

    def wait(
        self, job_id: str, env: dict[str, str], timeout: float = 30
    ) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "wait",
                    job_id,
                    "--timeout-seconds",
                    "3",
                    "--poll-seconds",
                    "0.2",
                    "--json",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
                check=False,
            )
            if result.returncode in (0, 1):
                return json.loads(result.stdout)
            time.sleep(0.2)
        self.fail(f"job {job_id} did not finish")

    def test_pipeline_validates_and_redacts_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            secret = "token-canary-split-0123456789abcdef"
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "echo startup-stdout-canary\n"
                    "echo startup-stderr-canary >&2\n"
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            env["C_FAKE_RESULT"] = result_text("proposal")
            env["C_FAKE_ECHO_VALUE"] = "1"
            env["C_FAKE_ECHO_IN_PAYLOAD"] = "1"
            task = self.task_file(root)
            launched = self.launch(
                repo, task, config, env, "deepseek", "proposal", "pipeline-ok"
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("pipeline-ok", env)
            self.assertEqual(status["state"], "succeeded", status)
            job_dir = state / "jobs" / "pipeline-ok"
            evidence = json.loads((job_dir / "provider-result.json").read_text())
            self.assertTrue(evidence["validated"])
            expected_payload = valid_payload("proposal")
            self.assertEqual(
                evidence["payload"]["approach"], expected_payload["approach"]
            )
            self.assertEqual(
                evidence["payload"]["assumptions"],
                expected_payload["assumptions"],
            )
            self.assertIn("[REDACTED]", evidence["payload"]["rationale"])
            for path in persisted_files(state):
                data = path.read_bytes()
                self.assertNotIn(secret.encode(), data, str(path))
                self.assertNotIn(b"startup-stdout-canary", data, str(path))
                self.assertNotIn(b"startup-stderr-canary", data, str(path))
            for command in (
                ["status", "pipeline-ok", "--json"],
                ["logs", "pipeline-ok", "--stream", "both"],
                ["list", "--json"],
                ["dashboard", "--json"],
            ):
                surfaced = subprocess.run(
                    [sys.executable, str(RUNNER), *command],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30,
                    check=False,
                )
                combined = surfaced.stdout + surfaced.stderr
                self.assertNotIn(secret, combined, command)
                self.assertNotIn("startup-stdout-canary", combined, command)
                self.assertNotIn("startup-stderr-canary", combined, command)
            stderr_log = (job_dir / "stderr.log").read_text()
            self.assertIn("FAKE_ARGV=", stderr_log)
            self.assertIn("--permission-mode", stderr_log)
            self.assertIn("plan", stderr_log)
            self.assertNotIn(secret, stderr_log)

    def test_capture_survives_end_like_environment_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    "export ANTHROPIC_AUTH_TOKEN='test-token-canary-0123456789'",
                    "export APP_COMPONENT=BACKEND",
                    "export TRAILING_TAG=END",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            env["C_FAKE_RESULT"] = result_text("proposal")
            task = self.task_file(root)
            launched = self.launch(
                repo, task, config, env, "deepseek", "proposal", "end-env"
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("end-env", env)
            self.assertEqual(status["state"], "succeeded", status)

    def test_plain_reassignment_and_nested_json_escaping_never_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            prior = "prior-fixture-token-0123456789"
            secret = 'reassigned-"canary"\\café-0123456789abcdef'
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(prior)}",
                    f"ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "echo startup-stdout-canary\n"
                    "echo startup-stderr-canary >&2\n"
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            env["C_FAKE_RESULT"] = result_text("proposal")
            env["C_FAKE_ECHO_VALUE"] = "1"
            env["C_FAKE_ECHO_IN_PAYLOAD"] = "1"
            # Deliberately not a sensitive name: the reassigned assignment is
            # the only source from which the redactor can learn this value.
            env["C_FAKE_EXPECT_VALUE"] = secret
            task = self.task_file(root)
            launched = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                "reassigned-nested",
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("reassigned-nested", env)
            self.assertEqual(status["state"], "succeeded", status)
            job_dir = state / "jobs" / "reassigned-nested"
            evidence = json.loads((job_dir / "provider-result.json").read_text())
            self.assertTrue(evidence["validated"])
            self.assertIn("[REDACTED]", evidence["payload"]["rationale"])
            stderr_log = (job_dir / "stderr.log").read_text()
            self.assertIn("FAKE_TOKEN_IS_EXPECTED=true", stderr_log)
            self.assertIn("[REDACTED]", stderr_log)
            variants = c._redaction_variants(secret.encode("utf-8"))
            for path in persisted_files(state):
                data = path.read_bytes()
                self.assertNotIn(secret.encode("utf-8"), data, str(path))
                for variant in variants:
                    self.assertNotIn(variant, data, str(path))
                self.assertNotIn(prior.encode(), data, str(path))
                self.assertNotIn(b"startup-stdout-canary", data, str(path))
                self.assertNotIn(b"startup-stderr-canary", data, str(path))
            for command in (
                ["status", "reassigned-nested", "--json"],
                ["logs", "reassigned-nested", "--stream", "both"],
                ["list", "--json"],
                ["dashboard", "--json"],
            ):
                surfaced = subprocess.run(
                    [sys.executable, str(RUNNER), *command],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30,
                    check=False,
                )
                combined = surfaced.stdout + surfaced.stderr
                self.assertNotIn(secret, combined, command)
                for variant in variants:
                    self.assertNotIn(
                        variant.decode("utf-8", errors="replace"), combined, command
                    )

    def test_unicode_and_mixed_escaped_payloads_never_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            secret = "token-canary-unicode-0123456789abcdef"
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            task = self.task_file(root)
            for mode in ("unicode_escape_payload", "mixed_escape_payload"):
                with self.subTest(mode=mode):
                    env2 = dict(env)
                    env2["C_FAKE_MODE"] = mode
                    env2["C_FAKE_RESULT"] = result_text("proposal")
                    job_id = f"escaped-{mode}"
                    launched = self.launch(
                        repo, task, config, env2, "deepseek", "proposal", job_id
                    )
                    self.assertEqual(launched.returncode, 0, launched.stderr)
                    status = self.wait(job_id, env2)
                    self.assertEqual(status["state"], "succeeded", status)
                    job_dir = state / "jobs" / job_id
                    evidence = json.loads(
                        (job_dir / "provider-result.json").read_text()
                    )
                    self.assertTrue(evidence["validated"])
                    self.assertIn(
                        "[REDACTED]", evidence["payload"]["rationale"]
                    )
                    for path in persisted_files(job_dir):
                        data = path.read_bytes()
                        self.assertNotIn(
                            secret.encode("utf-8"), data, str(path)
                        )
                    stdout_log = (job_dir / "stdout.log").read_text()
                    result_lines = 0
                    for line in stdout_log.splitlines():
                        if not line.strip():
                            continue
                        event = json.loads(line)
                        if event.get("type") != "result":
                            continue
                        result_lines += 1
                        inner = json.loads(event["result"])
                        self.assertNotIn(secret, json.dumps(inner))
                        self.assertIn(
                            "[REDACTED]", inner["payload"]["rationale"]
                        )
                    self.assertEqual(result_lines, 1)

    def test_invalid_and_truncated_output_never_persist_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            secret = 'token-canary-output-"quoted"\\café-0123456789abcdef'
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    f"export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}",
                    "export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
                ],
                startup=(
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            task = self.task_file(root)
            variants = c._redaction_variants(secret.encode("utf-8"))
            for mode in ("invalid_echo", "truncated_echo"):
                with self.subTest(mode=mode):
                    env2 = dict(env)
                    env2["C_FAKE_MODE"] = mode
                    env2["C_FAKE_RESULT"] = result_text("proposal")
                    job_id = f"bad-output-{mode}"
                    launched = self.launch(
                        repo, task, config, env2, "deepseek", "proposal", job_id
                    )
                    self.assertEqual(launched.returncode, 0, launched.stderr)
                    status = self.wait(job_id, env2)
                    self.assertEqual(status["state"], "failed", status)
                    self.assertEqual(
                        status["provider_error"]["code"], "invalid_output"
                    )
                    job_dir = state / "jobs" / job_id
                    for path in persisted_files(job_dir):
                        data = path.read_bytes()
                        self.assertNotIn(secret.encode("utf-8"), data, str(path))
                        for variant in variants:
                            self.assertNotIn(variant, data, str(path))
                    evidence = json.loads(
                        (job_dir / "provider-result.json").read_text()
                    )
                    self.assertFalse(evidence["validated"])

    def test_unsupported_capture_never_executes_the_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            marker = root / "provider-ran"
            (root / "bin" / "claude").write_text(
                f"#!{sys.executable}\n"
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            (root / "bin" / "claude").chmod(0o755)
            write_rcfile(
                root / "rc",
                "deepseek",
                statements=[
                    'export ANTHROPIC_AUTH_TOKEN="$(cat /tmp/not-allowed)"',
                ],
                startup=(
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            env["C_FAKE_RESULT"] = result_text("proposal")
            task = self.task_file(root)
            launched = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                "unsupported-capture",
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("unsupported-capture", env)
            self.assertEqual(status["state"], "failed", status)
            self.assertEqual(
                status["provider_error"]["code"],
                "credential_capture_unavailable",
            )
            self.assertFalse(marker.exists())
            self.assertEqual(
                (state / "jobs" / "unsupported-capture" / "stdout.log").read_bytes(),
                b"",
            )

    def test_delegated_backend_never_executes_or_persists_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            secret = "delegated-pipeline-secret-0123456789abcdef"
            marker = root / "delegated-ran"
            fake_claude = root / "bin" / "claude"
            startup = (
                "export PATH=" + shell_quote(str(root / "bin")) + ':"$PATH"\n'
            )
            wrapper = (
                "deepseek () {\n"
                "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'\n"
                '    claude "$@"\n'
                "}\n"
            )
            delegate = (
                "claude () {\n"
                f"    export ANTHROPIC_AUTH_TOKEN={shell_quote(secret)}\n"
                f"    builtin printf ran > {shell_quote(str(marker))}\n"
                f"    {shell_quote(str(fake_claude))} \"$@\"\n"
                "}\n"
            )
            cases = {
                "delegated-function-before": startup + delegate + wrapper,
                "delegated-function-after": startup + wrapper + delegate,
                "delegated-alias-after": (
                    startup
                    + wrapper
                    + "alias claude="
                    + shell_quote(str(fake_claude))
                    + "\n"
                ),
            }
            # If the delegated body ever ran, the fake CLI would echo the
            # synthetic value into stdout, stderr and the accepted payload.
            env["C_FAKE_RESULT"] = result_text("proposal")
            env["C_FAKE_ECHO_VALUE"] = "1"
            env["C_FAKE_ECHO_IN_PAYLOAD"] = "1"
            task = self.task_file(root)
            for job_id, content in cases.items():
                with self.subTest(job_id=job_id):
                    marker.unlink(missing_ok=True)
                    (root / "rc").write_text(content, encoding="utf-8")
                    launched = self.launch(
                        repo, task, config, env, "deepseek", "proposal", job_id
                    )
                    self.assertEqual(launched.returncode, 0, launched.stderr)
                    status = self.wait(job_id, env)
                    self.assertEqual(status["state"], "failed", status)
                    self.assertEqual(
                        status["provider_error"]["code"],
                        "credential_capture_unavailable",
                        status,
                    )
                    self.assertEqual(
                        status["provider_error"]["message"],
                        c.SAFE_DELEGATION_ERROR,
                    )
                    self.assertFalse(marker.exists())
                    job_dir = state / "jobs" / job_id
                    self.assertEqual(
                        (job_dir / "stdout.log").read_bytes(), b""
                    )
                    self.assertEqual(
                        (job_dir / "stderr.log").read_bytes(), b""
                    )
                    evidence = json.loads(
                        (job_dir / "provider-result.json").read_text()
                    )
                    self.assertFalse(evidence["validated"])
                    self.assertEqual(
                        evidence["error"]["code"],
                        "credential_capture_unavailable",
                    )
                    for path in persisted_files(state):
                        self.assertNotIn(
                            secret.encode("utf-8"),
                            path.read_bytes(),
                            str(path),
                        )

    def test_missing_external_backend_is_provider_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            empty = root / "empty-bin"
            empty.mkdir()
            content = (
                "unset -f claude 2>/dev/null || true\n"
                "unalias claude 2>/dev/null || true\n"
                "export PATH=" + shell_quote(str(empty)) + "\n"
                "deepseek () {\n"
                "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'\n"
                '    claude "$@"\n'
                "}\n"
            )
            (root / "rc").write_text(content, encoding="utf-8")
            env["C_FAKE_RESULT"] = result_text("proposal")
            task = self.task_file(root)
            launched = self.launch(
                repo, task, config, env, "deepseek", "proposal", "missing-backend"
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("missing-backend", env)
            self.assertEqual(status["state"], "failed", status)
            self.assertEqual(
                status["provider_error"]["code"], "provider_unavailable", status
            )
            self.assertEqual(
                status["provider_error"]["message"], c.SAFE_BACKEND_ERROR
            )
            job_dir = state / "jobs" / "missing-backend"
            self.assertEqual((job_dir / "stdout.log").read_bytes(), b"")
            self.assertEqual((job_dir / "stderr.log").read_bytes(), b"")

    def test_pipeline_failure_categories_and_output_limit(self) -> None:
        cases = (
            ("invalid", "invalid_output"),
            ("empty", "invalid_output"),
            ("envelope_error_auth", "auth_failed"),
            ("auth", "auth_failed"),
            ("rate", "rate_limited"),
            ("quota", "quota_exceeded"),
            ("exec_fail", "execution_failed"),
            ("oversized", "output_limit"),
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            task = self.task_file(root)
            for index, (mode, code) in enumerate(cases):
                with self.subTest(mode=mode):
                    env2 = dict(env)
                    env2["C_FAKE_MODE"] = mode
                    env2["C_FAKE_RESULT"] = result_text("proposal")
                    job_id = f"category-{index}"
                    launched = self.launch(
                        repo,
                        task,
                        config,
                        env2,
                        "deepseek",
                        "proposal",
                        job_id,
                    )
                    self.assertEqual(launched.returncode, 0, launched.stderr)
                    status = self.wait(job_id, env2)
                    self.assertEqual(status["state"], "failed", status)
                    self.assertEqual(
                        status["provider_error"]["code"], code, status
                    )

    def test_pipeline_timeout_and_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            task = self.task_file(root)
            env["C_FAKE_MODE"] = "sleep"
            launched = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                "timeout-job",
                timeout_seconds=1,
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("timeout-job", env)
            self.assertEqual(status["state"], "timed_out", status)
            self.assertEqual(status["provider_error"]["code"], "timeout")

            launched = self.launch(
                repo, task, config, env, "deepseek", "proposal", "cancel-job"
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            time.sleep(0.5)
            cancelled = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "cancel",
                    "cancel-job",
                    "--json",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
                check=False,
            )
            self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
            status = self.wait("cancel-job", env)
            self.assertEqual(status["state"], "cancelled", status)
            self.assertEqual(status["provider_error"]["code"], "cancelled")

    def test_slow_startup_timeout_before_ack_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            write_rcfile(
                root / "rc",
                "deepseek",
                startup=(
                    # Worker-only startup cost: the availability probe uses
                    # c-probe as $0, so only the real capture shell sleeps.
                    'if [ "$0" = c-provider ]; then sleep 3; fi\n'
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            task = self.task_file(root)
            launched = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                "slow-startup-timeout",
                timeout_seconds=1,
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("slow-startup-timeout", env)
            self.assertEqual(status["state"], "timed_out", status)
            self.assertEqual(status["provider_error"]["code"], "timeout", status)
            self.assertTrue(status["timed_out"], status)
            evidence = json.loads(
                (
                    state
                    / "jobs"
                    / "slow-startup-timeout"
                    / "provider-result.json"
                ).read_text()
            )
            self.assertFalse(evidence["validated"])
            self.assertTrue(evidence["timed_out"])
            self.assertFalse(evidence["cancelled"])
            self.assertEqual(evidence["error"]["code"], "timeout")

    def test_cancellation_before_ack_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            write_rcfile(
                root / "rc",
                "deepseek",
                startup=(
                    'if [ "$0" = c-provider ]; then sleep 10; fi\n'
                    "export PATH="
                    + shell_quote(str(root / "bin"))
                    + ':"$PATH"\n'
                ),
            )
            task = self.task_file(root)
            launched = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                "slow-startup-cancel",
                timeout_seconds=30,
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            time.sleep(0.5)
            cancelled = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "cancel",
                    "slow-startup-cancel",
                    "--json",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
                check=False,
            )
            self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
            status = self.wait("slow-startup-cancel", env)
            self.assertEqual(status["state"], "cancelled", status)
            self.assertEqual(status["provider_error"]["code"], "cancelled", status)
            self.assertFalse(status["timed_out"], status)
            evidence = json.loads(
                (
                    state
                    / "jobs"
                    / "slow-startup-cancel"
                    / "provider-result.json"
                ).read_text()
            )
            self.assertFalse(evidence["validated"])
            self.assertFalse(evidence["timed_out"])
            self.assertTrue(evidence["cancelled"])
            self.assertEqual(evidence["error"]["code"], "cancelled")

    def test_malformed_capture_stays_capture_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(
                root, capture_mode="malformed"
            )
            task = self.task_file(root)
            launched = self.launch(
                repo,
                task,
                config,
                env,
                "deepseek",
                "proposal",
                "malformed-capture",
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            status = self.wait("malformed-capture", env)
            self.assertEqual(status["state"], "failed", status)
            self.assertEqual(
                status["provider_error"]["code"],
                "credential_capture_unavailable",
                status,
            )
            self.assertFalse(status["timed_out"], status)
            job_dir = state / "jobs" / "malformed-capture"
            evidence = json.loads((job_dir / "provider-result.json").read_text())
            self.assertFalse(evidence["validated"])
            self.assertFalse(evidence["timed_out"])
            self.assertFalse(evidence["cancelled"])
            self.assertEqual(
                evidence["error"]["code"], "credential_capture_unavailable"
            )
            # A malformed capture must never release the provider.
            self.assertNotIn("FAKE_ARGV=", (job_dir / "stderr.log").read_text())

    def test_pipeline_serializes_readers_and_writers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, state, env, config = self.make_environment(root)
            task = self.task_file(root)
            sleeping = dict(env)
            sleeping["C_FAKE_MODE"] = "sleep"
            launched = self.launch(
                repo,
                task,
                config,
                sleeping,
                "deepseek",
                "implementation",
                "writer-live",
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            time.sleep(0.5)
            refused = self.launch(
                repo, task, config, sleeping, "deepseek", "proposal", "reader-1"
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("readonly", refused.stderr.casefold())
            self.assertFalse((state / "jobs" / "reader-1").exists())
            subprocess.run(
                [sys.executable, str(RUNNER), "cancel", "writer-live", "--json"],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
                check=False,
            )
            status = self.wait("writer-live", env)
            self.assertEqual(status["state"], "cancelled", status)

            launched = self.launch(
                repo, task, config, sleeping, "deepseek", "proposal", "reader-live"
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            time.sleep(0.5)
            refused = self.launch(
                repo,
                task,
                config,
                sleeping,
                "deepseek",
                "implementation",
                "writer-2",
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("readonly", refused.stderr.casefold())
            self.assertFalse((state / "jobs" / "writer-2").exists())
            subprocess.run(
                [sys.executable, str(RUNNER), "cancel", "reader-live", "--json"],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
                check=False,
            )
            self.wait("reader-live", env)


if __name__ == "__main__":
    unittest.main()
