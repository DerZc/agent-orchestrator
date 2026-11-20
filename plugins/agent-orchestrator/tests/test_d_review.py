from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
RUNNER = SCRIPTS / "cli_agent_job.py"
D_REVIEW = SCRIPTS / "d_review.py"

RUNNER_SPEC = importlib.util.spec_from_file_location(
    "agent_orchestrator_runner_d2", RUNNER
)
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


def shq(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


FAKE_PROVIDER = r'''#!{python}
import base64
import json
import os
import sys
import time

prompt = sys.stdin.read()
delay = os.environ.get("C_FAKE_SLEEP")
if delay:
    time.sleep(float(delay))
if os.environ.get("C_FAKE_IMPLEMENT"):
    for entry in json.loads(os.environ.get("C_FAKE_WRITES", "[]")):
        path, content = entry
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(base64.b64decode(content))
    for path in json.loads(os.environ.get("C_FAKE_DELETES", "[]")):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    document = {{
        "result_version": 1,
        "operation": os.environ.get("C_FAKE_OPERATION", "implementation"),
        "payload": {{
            "changed_paths": json.loads(os.environ.get("C_FAKE_CHANGED", "[]")),
            "validation_commands": ["python3 -m unittest discover"],
            "validation_outcomes": ["mock validation recorded by the provider"],
            "remaining_issues": [],
        }},
    }}
else:
    document = json.loads(os.environ["C_FAKE_RESULT"])
text = json.dumps(document)
print(json.dumps({{"type": "system", "subtype": "init"}}))
print(json.dumps({{"type": "result", "subtype": "success", "is_error": False, "result": text, "num_turns": 1, "duration_ms": 5, "session_id": "00000000-0000-4000-8000-000000000000", "total_cost_usd": 0.02, "usage": {{"input_tokens": 9, "output_tokens": 4}}}}))
'''

FAKE_BWRAP = r'''#!{python}
import os
import sys

args = sys.argv[1:]
command = None
for index, value in enumerate(args):
    if value == "bash" or value.endswith("/bash"):
        command = args[index:]
        break
if command is None:
    command = args[-1:]
os.execv(command[0], command)
'''

_SANDBOX_COMMAND_PROBE_SOURCE = r'''
import errno, json, os, sys
host_marker, adapter_path, secret_path, workspace_path = sys.argv[1:5]
checks = {}
checks["host_tmp_hidden"] = not os.path.exists(host_marker)
checks["legacy_scratch_absent"] = not os.path.exists("/d2scratch")
# A plain command_check declares no adapter grant, so the masked coordinator
# state must actually hide the pinned adapter here. Exact adapter visibility is
# a structured_unittest-only mount and is asserted from that invocation's
# recorded literal_adapter_ro layout and its successful run.
try:
    with open(adapter_path, "rb") as handle:
        checks["adapter_readable"] = bool(handle.read(64))
except OSError as exc:
    checks["adapter_readable"] = False
    checks["adapter_errno"] = errno.errorcode.get(exc.errno, str(exc.errno))
checks["adapter_hidden"] = not checks["adapter_readable"]
checks["secret_hidden"] = not os.path.exists(secret_path)
scratch_env = ("HOME", "TMPDIR", "XDG_CACHE_HOME")
checks["scratch_env_consistent"] = all(
    os.environ.get(name, "").startswith("/tmp/d2scratch/") for name in scratch_env
)
try:
    for name in scratch_env:
        target = os.path.join(os.environ[name], "command-check-marker")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(os.path.basename(os.environ[name]))
    checks["scratch_writable"] = True
except OSError:
    checks["scratch_writable"] = False
try:
    with open(os.path.join(os.getcwd(), "command-check-write"), "w") as handle:
        handle.write("must not succeed")
except OSError as exc:
    checks["source_errno"] = errno.errorcode.get(exc.errno, str(exc.errno))
else:
    checks["source_errno"] = "WROTE"
checks["cwd_is_workspace"] = os.path.realpath(os.getcwd()) == os.path.realpath(
    workspace_path
)
print(json.dumps(checks, sort_keys=True))
required = (
    "host_tmp_hidden",
    "legacy_scratch_absent",
    "adapter_hidden",
    "secret_hidden",
    "scratch_env_consistent",
    "scratch_writable",
    "cwd_is_workspace",
)
if not all(checks.get(name) for name in required):
    sys.exit(3)
if checks.get("source_errno") != "EROFS":
    sys.exit(4)
sys.exit(0)
'''.strip()

# The frozen validation policy forbids literal newlines in an argv element, so
# the probe travels as a single-line exec() expression with escaped newlines.
SANDBOX_COMMAND_PROBE = "exec(" + repr(_SANDBOX_COMMAND_PROBE_SOURCE) + ")"

CRITERIA = ["Structured tests pass", "Immutable evidence is retained"]

_REAL_BWRAP_SUPPORT: bool | None = None


def real_bwrap_supported() -> bool:
    """Prove this process can create a real mount namespace with EROFS.

    Native bootstrap writers run with dropped capabilities, so this positive
    case is skipped rather than replaced by a nonconfining shim. Host Codex runs
    it independently after all source processes stop.
    """
    global _REAL_BWRAP_SUPPORT
    if _REAL_BWRAP_SUPPORT is not None:
        return _REAL_BWRAP_SUPPORT
    executable = shutil.which("bwrap")
    if not executable:
        _REAL_BWRAP_SUPPORT = False
        return False
    script = (
        "import errno, os, sys\n"
        "try:\n"
        "    os.close(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | "
        "os.O_EXCL, 0o600))\n"
        "except OSError as exc:\n"
        "    sys.exit(0 if exc.errno == errno.EROFS else 3)\n"
        "sys.exit(2)\n"
    )
    with tempfile.TemporaryDirectory() as raw:
        marker = str(Path(raw) / "probe-marker")
        try:
            result = subprocess.run(
                [
                    executable,
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--unshare-pid",
                    "--cap-drop",
                    "ALL",
                    "--chdir",
                    raw,
                    "--",
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    script,
                    marker,
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except Exception:
            _REAL_BWRAP_SUPPORT = False
            return False
        _REAL_BWRAP_SUPPORT = result.returncode == 0 and not os.path.exists(marker)
    return _REAL_BWRAP_SUPPORT


REAL_BWRAP = unittest.skipUnless(
    real_bwrap_supported(),
    "real bubblewrap mount namespaces are unavailable in this capability-dropped "
    "native environment; the physical positive case is run by host Codex",
)


def result_text(operation: str, payload: dict) -> str:
    return json.dumps(
        {
            "result_version": 1,
            "operation": operation,
            "payload": payload,
        }
    )


def proposal_payload() -> dict:
    return {
        "approach": "Implement the approved managed execution journal carefully.",
        "rationale": "The frozen design requires immutable evidence and strict gates.",
        "assumptions": ["The local filesystem provides atomic rename semantics."],
        "problems": ["Crash recovery must remain evidence driven."],
        "alternatives": ["A separate scheduler was rejected by consensus."],
        "feasibility": "Feasible with the existing B1/B2/C/D1 modules.",
        "testing": ["Run the focused D2 test suite."],
    }


def cross_payload(objection: str) -> dict:
    return {
        "objections": [{"objection": objection, "severity": "high"}],
        "responses": ["The journal records explicit intent and claim facts."],
        "revisions": ["Keep every partial result immutable."],
    }


def consensus_payload(digest: str) -> dict:
    return {
        "decision": "AGREE",
        "candidate_sha256": digest,
        "rationale": "The candidate and its approved constraints are acceptable.",
    }


class D2ReviewRepairTests(unittest.TestCase):
    """D2 actual-entrypoint integration over mock CLIs and real B2 receipts."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self._previous_home = os.environ.get("AGENT_ORCHESTRATOR_HOME")
        os.environ["AGENT_ORCHESTRATOR_HOME"] = str(self.state)
        self.addCleanup(self._restore_home)
        self.repo = self.make_repo(self.root / "repo")
        # The pinned adapter bytes are copied into a fixture-owned private
        # runtime outside the candidate workspace before any ballot. The host
        # checkout may be 0750-owned by another uid, which a cap-dropped
        # ordinary validation child cannot traverse; the voted literal path and
        # SHA therefore name this fixture copy. No hidden argv rewriting.
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        shutil.copyfile(D_REVIEW, self.runtime / "d_review.py")
        shutil.copyfile(SCRIPTS / "c_providers.py", self.runtime / "c_providers.py")
        self.bin = self.root / "bin"
        self.write_provider_tools(self.bin)
        self.rcfile = self.root / "rc"
        self.write_rcfile(self.rcfile)
        self.config = self.root / "agents.json"
        self.config.write_text(
            json.dumps(
                {
                    "agents": {
                        "deepseek": {"provider_rcfile": str(self.rcfile)},
                        "glm": {"provider_rcfile": str(self.rcfile)},
                        "fake": {
                            "argv": [
                                sys.executable,
                                "-c",
                                "import sys; sys.stdin.read()",
                            ],
                            "prompt_transport": "stdin",
                        },
                    }
                }
            )
        )
        self.env = self.clean_env()
        self.env["AGENT_ORCHESTRATOR_HOME"] = str(self.state)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.manifest_path = self.root / "manifest.json"
        self.manifest = self.build_manifest()
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.plan_file = self.root / "plan.md"
        self.plan_file.write_text(
            "# Goal\nShip the strict managed review and repair feature.\n\n"
            "# Decisions and assumptions\nFollow the frozen candidate.\n\n"
            "# Constraints and guardrails\nDo not publish or change credentials.\n\n"
            "# Checklist\n- [ ] Implement the strict managed review feature.\n\n"
            "# Validation strategy\nRun the focused D2 tests.\n\n"
            "# Completion criteria\nAll evidence is immutable.\n"
        )
        self.run_cli(
            "preferences",
            "--workspace-mode",
            "project",
            "--json",
            env=self.env,
        )

    def _restore_home(self) -> None:
        if self._previous_home is None:
            os.environ.pop("AGENT_ORCHESTRATOR_HOME", None)
        else:
            os.environ["AGENT_ORCHESTRATOR_HOME"] = self._previous_home
        for name in list(os.environ):
            if name.startswith("C_FAKE_"):
                os.environ.pop(name, None)

    def clean_env(self) -> dict[str, str]:
        return {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ANTHROPIC")
            and key not in {"CLAUDE_CODE_AUTO_COMPACT_WINDOW"}
            and not key.startswith("C_FAKE_")
        }

    def git(self, cwd: Path, *args: str) -> None:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def make_repo(self, path: Path) -> Path:
        path.mkdir(parents=True)
        self.git(path, "init", "-q", "-b", "main")
        self.git(path, "config", "user.email", "tests@example.invalid")
        self.git(path, "config", "user.name", "Tests")
        (path / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        (path / "allowed").mkdir()
        (path / "allowed" / "old.txt").write_text("old\n", encoding="utf-8")
        (path / "tests").mkdir()
        (path / "tests" / "test_sample.py").write_text(
            "import unittest\n\n"
            "class SampleTests(unittest.TestCase):\n"
            "    def test_baseline(self):\n"
            "        self.assertEqual(1 + 1, 2)\n",
            encoding="utf-8",
        )
        self.git(
            path,
            "add",
            "tracked.txt",
            "allowed/old.txt",
            "tests/test_sample.py",
        )
        self.git(path, "commit", "-qm", "baseline")
        self.git(path, "checkout", "-qb", "feature/d2-tests")
        return path

    def write_provider_tools(self, bin_dir: Path) -> None:
        bin_dir.mkdir(parents=True)
        claude = bin_dir / "claude"
        claude.write_text(FAKE_PROVIDER.format(python=sys.executable))
        claude.chmod(0o755)
        # The mock provider path uses a transport shim for provider isolation.
        # D2 validation launches below use an explicit system PATH so this shim
        # can never supply read-only authority.
        bwrap = bin_dir / "bwrap"
        bwrap.write_text(FAKE_BWRAP.format(python=sys.executable))
        bwrap.chmod(0o755)

    def validation_env(self) -> dict[str, str]:
        """Host time PATH without the mock provider shims.

        The real bubblewrap (when the host supports it) and absolute Python are
        used by the validator. On the capability-dropped native bootstrap the
        positive chain test is skipped rather than supplied a fake wrapper.
        """
        local = dict(self.env)
        local["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        return local

    def write_rcfile(self, path: Path) -> None:
        lines = [
            f"export PATH={shq(str(self.bin))}:\"$PATH\"",
            "deepseek() {",
            "    export ANTHROPIC_AUTH_TOKEN='test-token-0123456789'",
            "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
            '    claude "$@"',
            "}",
            "glm() {",
            "    export ANTHROPIC_AUTH_TOKEN='test-token-0123456789'",
            "    export ANTHROPIC_BASE_URL='http://127.0.0.1:9'",
            '    claude "$@"',
            "}",
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def build_manifest(self, criteria: list[str] | None = None) -> dict:
        selected = criteria or CRITERIA
        return {
            "policy_version": 2,
            "steps": [
                {
                    "id": "step-one",
                    "objective": "Implement the strict managed review feature.",
                    "scope": ["allowed"],
                    "deliverables": ["review journal"],
                    "acceptance_criteria": selected,
                    "depends_on": [],
                    "brief": {
                        "original_objective": (
                            "Implement the strict managed review feature safely."
                        ),
                        "repository_context": (
                            "The existing agent orchestrator workspace."
                        ),
                        "constraints": ["No provider quota use in tests"],
                        "proposed_approach": (
                            "Reuse the B1 plan lock, B2 lease and D1 journal."
                        ),
                        "expected_changes": ["review journal", "CLI commands"],
                        "acceptance_criteria": selected,
                    },
                }
            ],
        }

    def run_cli(
        self,
        *args: str,
        expected: int = 0,
        env: dict[str, str] | None = None,
        timeout: float = 120,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(RUNNER), *args],
            capture_output=True,
            text=True,
            env=env or self.env,
            timeout=timeout,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            expected,
            (result.stderr or "") + (result.stdout or ""),
        )
        return result

    def json_cli(
        self,
        *args: str,
        env: dict[str, str] | None = None,
        expected: int = 0,
    ) -> dict:
        result = self.run_cli(*args, env=env, expected=expected)
        return json.loads(result.stdout)

    def create_plan(self, plan_id: str = "d2-plan") -> dict:
        return self.json_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.repo),
            "--title",
            "D2 managed plan",
            "--plan-id",
            plan_id,
            "--research-team",
            "--manifest-file",
            str(self.manifest_path),
            "--executor",
            "fake",
            "--strict-execution",
            "--json",
        )

    def checkpoint(self, plan_id: str = "d2-plan") -> dict:
        return self.json_cli("plan-checkpoint", plan_id, "--json")

    def plan_status(self, plan_id: str = "d2-plan") -> dict:
        return self.json_cli("plan-status", plan_id, "--json")

    # ------------------------------------------------------------------
    # Consensus helpers
    # ------------------------------------------------------------------

    def launch_discussion(
        self,
        role: str,
        round_number: int,
        operation: str,
        payload: dict,
        *,
        plan_id: str = "d2-plan",
        extra_env: dict[str, str] | None = None,
    ) -> str:
        task = self.root / f"task-{role}-{round_number}-{time.time_ns()}.md"
        task.write_text(
            f"Return the required {operation} payload for {role}.\n",
            encoding="utf-8",
        )
        local = dict(self.env)
        local["C_FAKE_RESULT"] = result_text(operation, payload)
        if extra_env:
            local.update(extra_env)
        launched = self.run_cli(
            "execution-discussion",
            "--plan-id",
            plan_id,
            "--step-id",
            "step-one",
            "--role",
            role,
            "--round",
            str(round_number),
            "--task-file",
            str(task),
            "--timeout-seconds",
            "60",
            "--config",
            str(self.config),
            "--json",
            env=local,
        )
        job_id = json.loads(launched.stdout)["job_id"]
        status = self.wait(job_id, env=local)
        self.assertEqual(status.get("state"), "succeeded", status)
        return job_id

    def wait(self, job_id: str, *, env: dict[str, str] | None = None) -> dict:
        result = self.run_cli(
            "wait",
            job_id,
            "--timeout-seconds",
            "90",
            "--poll-seconds",
            "0.2",
            "--json",
            env=env,
            timeout=150,
        )
        return json.loads(result.stdout)

    def normalize(self, operation: str, payload: dict) -> dict:
        return runner.b1_module().normalize_provider_mapping(operation, payload)

    def submit(
        self,
        role: str,
        round_number: int,
        operation: str,
        payload: dict,
        job_id: str | None,
    ) -> dict:
        submission = self.normalize(operation, payload)
        path = self.root / f"submission-{role}-{round_number}-{time.time_ns()}.json"
        path.write_text(json.dumps(submission), encoding="utf-8")
        args = [
            "consensus-submit",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--role",
            role,
            "--round",
            str(round_number),
            "--submission-file",
            str(path),
            "--json",
        ]
        if role == "codex":
            args.extend(["--leader", "codex-leader"])
        elif job_id is not None:
            args.extend(["--source-job", job_id])
        return self.json_cli(*args)

    def vote(
        self,
        role: str,
        digest: str,
        job_id: str | None,
        rationale: str = "The candidate and its approved constraints are acceptable.",
    ) -> dict:
        args = [
            "consensus-vote",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--role",
            role,
            "--digest",
            digest,
            "--vote",
            "AGREE",
            "--rationale",
            rationale,
            "--json",
        ]
        if role == "codex":
            args.extend(["--leader", "codex-leader"])
        elif job_id is not None:
            args.extend(["--source-job", job_id])
        return self.json_cli(*args)

    def adapter_identity(self) -> dict:
        adapter = self.runtime / "d_review.py"
        return {
            "id": "coordinator-stdlib-unittest",
            "version": 1,
            "path": str(adapter),
            "sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        }

    def constraints(self, *, ro_enforcement: str = "required") -> dict:
        adapter = self.adapter_identity()
        argv = [
            sys.executable,
            "-I",
            "-B",
            adapter["path"],
            "_unittest-adapter",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_*.py",
        ]
        entry = {
            "invocation_id": "V001",
            "label": "structured focused tests",
            "argv": argv,
            "cwd": ".",
            "context": "ordinary_ro",
            "purpose": "Execute the frozen structured unittest suite.",
            "mandatory": True,
            "expected_exit": 0,
            "timeout_seconds": 60,
            "capture_limit_bytes": 1_048_576,
            "environment_policy": "minimal_private",
            "ro_enforcement": ro_enforcement,
            "evidence": {
                "kind": "structured_unittest",
                "adapter": adapter,
                "report_env": "D2_STRUCTURED_REPORT",
                "min_collected": 1,
                "min_run": 1,
            },
        }
        return {
            "version": 2,
            "allowed_paths": ["allowed/**"],
            "denied_paths": [".env"],
            "criteria": [
                {
                    "id": f"C{index:03d}",
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                }
                for index, text in enumerate(CRITERIA, start=1)
            ],
            "required_validation": [{"argv": list(argv), "label": entry["label"]}],
            "max_changed_files": 8,
            "validation_policy": {"version": 1, "entries": [entry]},
        }

    def candidate(self, *, constraints: dict | None = None) -> dict:
        return {
            "final_design": (
                "Extend the existing journal with actual validation, active "
                "Codex review and bounded formal repair."
            ),
            "important_decisions": [
                "B1 remains the only discussion authority.",
                "D2 ends at REVIEW_APPROVED, never done.",
            ],
            "rejected_alternatives": [
                {
                    "alternative": "separate scheduler",
                    "reason": "rejected by consensus",
                }
            ],
            "objection_dispositions": [
                {
                    "objection_id": objection_id,
                    "disposition": "accepted",
                    "reason": "addressed by the frozen design",
                }
                for objection_id in ("O001", "O002", "O003")
            ],
            "remaining_risks": ["crash windows are tested explicitly"],
            "execution_constraints": constraints or self.constraints(),
        }

    def freeze_candidate(self, candidate: dict) -> str:
        path = self.root / f"candidate-{time.time_ns()}.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        result = self.json_cli(
            "consensus-freeze",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--candidate-file",
            str(path),
            "--json",
        )
        return str(result["frozen_digest"])

    def complete_consensus(
        self, candidate: dict | None = None
    ) -> tuple[str, dict]:
        selections = {
            "deepseek": (
                proposal_payload(),
                cross_payload("Recovery must never infer a no-start from wall time."),
            ),
            "glm": (
                proposal_payload(),
                cross_payload("Evidence must survive provider job cleanup."),
            ),
            "codex": (
                proposal_payload(),
                cross_payload("Strict source evidence must bind the candidate."),
            ),
        }
        for role in ("deepseek", "glm", "codex"):
            payload = selections[role][0]
            job = (
                self.launch_discussion(role, 1, "proposal", payload)
                if role != "codex"
                else None
            )
            self.submit(role, 1, "proposal", payload, job)
        for role in ("deepseek", "glm", "codex"):
            payload = selections[role][1]
            job = (
                self.launch_discussion(role, 2, "cross_examination", payload)
                if role != "codex"
                else None
            )
            self.submit(role, 2, "cross_examination", payload, job)
        document = candidate or self.candidate()
        digest = self.freeze_candidate(document)
        for role in ("deepseek", "glm", "codex"):
            payload = consensus_payload(digest)
            job = (
                self.launch_discussion(
                    role,
                    3,
                    "consensus",
                    payload,
                    extra_env={"C_FAKE_CANDIDATE": digest},
                )
                if role != "codex"
                else None
            )
            self.vote(role, digest, job, rationale=payload["rationale"])
        self.assertEqual(
            self.checkpoint()["consensus_state"], "CONSENSUS_REACHED"
        )
        return digest, document

    def contract_document(self, digest: str, constraints: dict) -> dict:
        state = runner.b1_module().replay_plan_state_unlocked("d2-plan")
        return {
            "version": 2,
            "plan_id": "d2-plan",
            "step_id": "step-one",
            "cycle": state["steps"]["step-one"]["cycle"],
            "candidate_sha256": digest,
            "plan_sha256": state["static"]["plan_sha256"],
            "manifest_digest": state["static"]["manifest_digest"],
            "objective": "Implement the approved strict review feature end to end.",
            "why": "Consensus requires validate, review, repair and evidence.",
            "relevant_modules": ["plugins/agent-orchestrator/scripts"],
            "allowed_paths": list(constraints["allowed_paths"]),
            "denied_paths": list(constraints["denied_paths"]),
            "required_behavior": [
                "Journal every D2 fact",
                "Reject unvalidated approval",
            ],
            "required_interfaces": ["execution-validate", "execution-review"],
            "tests": ["Run the focused D2 tests"],
            "acceptance_criteria": [
                {"id": item["id"], "text": CRITERIA[index]}
                for index, item in enumerate(constraints["criteria"])
            ],
            "required_validation": [
                dict(item) for item in constraints["required_validation"]
            ],
            "max_changed_files": constraints.get("max_changed_files"),
            "target_branch": "feature/d2-tests",
            "protected_branches": ["main"],
            "reporting": ["Return the complete changed path list"],
            "validation_policy": json.loads(
                json.dumps(constraints["validation_policy"])
            ),
        }

    def freeze_contract(self, document: dict) -> dict:
        path = self.root / f"contract-{time.time_ns()}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return self.json_cli(
            "execution-contract",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--contract-file",
            str(path),
            "--json",
        )

    def implementation_task(self) -> Path:
        path = self.root / f"impl-{time.time_ns()}.md"
        path.write_text("Implement the frozen contract.\n", encoding="utf-8")
        return path

    def implement(
        self, task: Path, env_overrides: dict[str, str]
    ) -> dict:
        local = dict(self.env)
        local.update(env_overrides)
        return self.json_cli(
            "execution-implement",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--task-file",
            str(task),
            "--timeout-seconds",
            "60",
            "--config",
            str(self.config),
            "--json",
            env=local,
        )

    def write_writes(
        self,
        writes: list[tuple[str, bytes]],
        deletes: list[str],
        changed: list[str],
        *,
        operation: str = "implementation",
    ) -> dict[str, str]:
        return {
            "C_FAKE_IMPLEMENT": "1",
            "C_FAKE_OPERATION": operation,
            "C_FAKE_WRITES": json.dumps(
                [
                    [path, base64.b64encode(content).decode("ascii")]
                    for path, content in writes
                ]
            ),
            "C_FAKE_DELETES": json.dumps(deletes),
            "C_FAKE_CHANGED": json.dumps(changed),
        }

    def run_validation(self) -> dict:
        env = self.validation_env()
        launched = self.json_cli(
            "execution-validate",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--timeout-seconds",
            "120",
            "--config",
            str(self.config),
            "--json",
            env=env,
        )
        job_id = launched["job_id"]
        status = self.wait(job_id, env=env)
        self.assertEqual(status.get("state"), "succeeded", status)
        return self.json_cli(
            "execution-validation-finalize",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            job_id,
            "--json",
            env=env,
        )

    def review_document(
        self,
        review_id: str,
        verdict: str,
        *,
        findings: list[dict] | None = None,
        dispositions: list[dict] | None = None,
        criteria: list[dict] | None = None,
    ) -> dict:
        if criteria is None:
            if verdict == "APPROVE":
                criteria = [
                    {
                        "id": f"C{index:03d}",
                        "disposition": "satisfied",
                        "evidence": "reviewed the exact source and tests",
                    }
                    for index in range(1, len(CRITERIA) + 1)
                ]
            else:
                criteria = [
                    {
                        "id": "C001",
                        "disposition": "unsatisfied",
                        "evidence": "the required behavior is missing",
                    },
                    {
                        "id": "C002",
                        "disposition": "satisfied",
                        "evidence": "immutable evidence is recorded",
                    },
                ]
        return {
            "version": 1,
            "review_id": review_id,
            "verdict": verdict,
            "leader": "codex-leader",
            "summary": (
                "The active leader inspected the objective, design, contract, "
                "cumulative diff, report and validation evidence."
            ),
            "findings": findings or [],
            "criteria": criteria,
            "prior_findings": dispositions or [],
        }

    def begin_review(self, purpose: str) -> tuple[str, Path]:
        session = self.root / f"session-{time.time_ns()}.json"
        result = self.json_cli(
            "execution-review-begin",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--purpose",
            purpose,
            "--leader",
            "codex-leader",
            "--session-file",
            str(session),
            "--json",
        )
        return str(result["review_id"]), session

    def record_review(
        self,
        review_id: str,
        session: Path,
        *,
        verdict: str,
        findings: list[dict] | None = None,
        dispositions: list[dict] | None = None,
        criteria: list[dict] | None = None,
        expect: int = 0,
    ):
        path = self.root / f"review-{review_id}-{time.time_ns()}.json"
        path.write_text(
            json.dumps(
                self.review_document(
                    review_id,
                    verdict,
                    findings=findings,
                    dispositions=dispositions,
                    criteria=criteria,
                )
            ),
            encoding="utf-8",
        )
        result = self.run_cli(
            "execution-review",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--review-file",
            str(path),
            "--session-file",
            str(session),
            "--leader",
            "codex-leader",
            "--json",
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def repair_contract_document(
        self, constraints: dict, finding_ids: list[str]
    ) -> dict:
        return {
            "version": 1,
            "objective": (
                "Repair the exact actionable finding inside the approved scope "
                "without widening the frozen contract."
            ),
            "why": (
                "The active Codex review rejected the source and a formal bounded "
                "repair is required before independent approval."
            ),
            "relevant_modules": ["allowed"],
            "allowed_paths": list(constraints["allowed_paths"]),
            "denied_paths": list(constraints["denied_paths"]),
            "finding_ids": list(finding_ids),
            "required_behavior": [
                "Address every actionable defect finding with tests",
                "Preserve immutable evidence and user bytes",
            ],
            "required_interfaces": ["execution-repair", "execution-finalize"],
            "tests": ["Run the frozen structured validation policy"],
            "acceptance_criteria": [
                {"id": item["id"], "text": CRITERIA[index]}
                for index, item in enumerate(constraints["criteria"])
            ],
            "required_validation": [
                dict(item) for item in constraints["required_validation"]
            ],
            "target_branch": "feature/d2-tests",
            "protected_branches": ["main"],
            "reporting": ["Return the complete changed path list"],
        }

    def freeze_repair_contract(
        self,
        constraints: dict,
        review_id: str,
        finding_ids: list[str],
        *,
        expect: int = 0,
    ):
        path = self.root / f"repair-contract-{time.time_ns()}.json"
        path.write_text(
            json.dumps(
                self.repair_contract_document(constraints, finding_ids)
            ),
            encoding="utf-8",
        )
        result = self.run_cli(
            "execution-repair-contract",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--review-id",
            review_id,
            "--contract-file",
            str(path),
            "--json",
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def allocate_repair(self, review_id: str, *, expect: int = 0):
        result = self.run_cli(
            "execution-repair-allocate",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--review-id",
            review_id,
            "--json",
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def repair(
        self,
        allocation_id: str,
        env_overrides: dict[str, str],
        *,
        config: str | None = None,
        expect: int = 0,
    ):
        local = dict(self.env)
        local.update(env_overrides)
        result = self.run_cli(
            "execution-repair",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--allocation-id",
            allocation_id,
            "--timeout-seconds",
            "60",
            "--config",
            config or str(self.config),
            "--json",
            env=local,
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def finalize_job(self, job_id: str) -> dict:
        return self.json_cli(
            "execution-finalize",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            job_id,
            "--json",
        )

    def journal(self) -> dict:
        return runner.d_module()._replay_journal("d2-plan")

    # ------------------------------------------------------------------
    # Repair-lineage and sandbox helpers
    # ------------------------------------------------------------------

    def defect(self, finding_id: str, path: str = "allowed/impl.txt") -> dict:
        return {
            "finding_id": finding_id,
            "kind": "defect",
            "severity": "high",
            "files": [path],
            "summary": f"The implementation still has defect {finding_id}.",
            "evidence": "The exact reviewed source does not satisfy the criterion.",
            "required_change": "Address the finding with a structured test.",
            "test_recommendation": "Run the frozen structured validation policy.",
        }

    def wait_failed(self, job_id: str) -> dict:
        result = self.run_cli(
            "wait",
            job_id,
            "--timeout-seconds",
            "90",
            "--poll-seconds",
            "0.2",
            "--json",
            expected=1,
            timeout=150,
        )
        return json.loads(result.stdout)

    def failed_claimed_repair(self, allocation_id: str, content: bytes) -> dict:
        """Run one claimed repair whose provider result is invalid on purpose."""
        launched = self.repair(
            allocation_id,
            self.write_writes(
                [("allowed/impl.txt", content)],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        status = self.wait_failed(job_id)
        self.assertNotEqual(status.get("state"), "succeeded", status)
        finalized = self.finalize_job(job_id)
        self.assertEqual(finalized["classification"], "drained_failure", finalized)
        self.assertFalse(finalized["completed"], finalized)
        return finalized

    def successful_repair(self, allocation_id: str, content: bytes) -> dict:
        launched = self.repair(
            allocation_id,
            self.write_writes(
                [("allowed/impl.txt", content)],
                [],
                ["allowed/impl.txt"],
                operation="repair",
            ),
        )
        job_id = launched["job_id"]
        status = self.wait(job_id)
        self.assertEqual(status.get("state"), "succeeded", status)
        finalized = self.finalize_job(job_id)
        self.assertTrue(finalized["completed"], finalized)
        self.assertEqual(finalized["state"], "REPAIR_APPLIED", finalized)
        return finalized

    def reject_current_source(
        self, finding_id: str, prior: list[str] | None = None
    ) -> str:
        review_id, session = self.begin_review(f"fresh rejection {finding_id}")
        self.record_review(
            review_id,
            session,
            verdict="REQUEST_CHANGES",
            findings=[self.defect(finding_id)],
            dispositions=[
                {
                    "finding_id": item,
                    "disposition": "carried",
                    "evidence": "The finding remains open for the next repair.",
                }
                for item in (prior or [])
            ],
        )
        return review_id

    def approval_document(self, review_id: str, prior: list[str]) -> dict:
        return self.review_document(
            review_id,
            "APPROVE",
            dispositions=[
                {
                    "finding_id": item,
                    "disposition": "resolved",
                    "evidence": "The repaired source and latest validation resolve it.",
                }
                for item in prior
            ],
        )

    def write_structured_review(
        self, review_id: str, document: dict, session: Path, *, expect: int = 0
    ):
        path = self.root / f"review-{review_id}-{time.time_ns()}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        result = self.run_cli(
            "execution-review",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--review-file",
            str(path),
            "--session-file",
            str(session),
            "--leader",
            "codex-leader",
            "--json",
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def install_pinned_adapter(self) -> tuple[Path, Path]:
        pinned = self.state / "pinned"
        pinned.mkdir(parents=True, exist_ok=True, mode=0o700)
        adapter = pinned / "d_review.py"
        shutil.copyfile(D_REVIEW, adapter)
        shutil.copyfile(SCRIPTS / "c_providers.py", pinned / "c_providers.py")
        secret = pinned / "coordinator-secret.txt"
        secret.write_text("must never be visible inside validation\n", encoding="utf-8")
        return adapter, secret

    def mixed_validation_constraints(
        self, adapter: Path, host_marker: Path, secret: Path
    ) -> dict:
        adapter_identity = {
            "id": "coordinator-stdlib-unittest",
            "version": 1,
            "path": str(adapter),
            "sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        }

        def structured(invocation_id: str, context: str, extra: list[str]) -> dict:
            argv = [
                sys.executable,
                "-I",
                "-B",
                str(adapter),
                "_unittest-adapter",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
                *extra,
            ]
            return {
                "invocation_id": invocation_id,
                "label": f"structured tests in {context}",
                "argv": argv,
                "cwd": ".",
                "context": context,
                "purpose": f"Execute the frozen suite in the {context} context.",
                "mandatory": True,
                "expected_exit": 0,
                "timeout_seconds": 60,
                "capture_limit_bytes": 1_048_576,
                "environment_policy": "minimal_private",
                "ro_enforcement": "required",
                "evidence": {
                    "kind": "structured_unittest",
                    "adapter": dict(adapter_identity),
                    "report_env": "D2_STRUCTURED_REPORT",
                    "min_collected": 1,
                    "min_run": 1,
                },
            }

        probe_argv = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            SANDBOX_COMMAND_PROBE,
            str(host_marker),
            str(adapter),
            str(secret),
            str(self.repo),
        ]
        command = {
            "invocation_id": "V003",
            "label": "private scratch and mask probe",
            "argv": probe_argv,
            "cwd": ".",
            "context": "ordinary_ro",
            "purpose": (
                "Prove the private scratch, private tmp, exact adapter exposure, "
                "known-state mask and canonical source read-only enforcement."
            ),
            "mandatory": True,
            "expected_exit": 0,
            "timeout_seconds": 60,
            "capture_limit_bytes": 1_048_576,
            "environment_policy": "minimal_private",
            "ro_enforcement": "required",
            "evidence": {"kind": "command_check"},
        }
        entries = [
            structured("V001", "ordinary_ro", []),
            structured("V002", "systems_trusted", ["-v"]),
            command,
        ]
        return {
            "version": 2,
            "allowed_paths": ["allowed/**"],
            "denied_paths": [".env"],
            "criteria": [
                {
                    "id": f"C{index:03d}",
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                }
                for index, text in enumerate(CRITERIA, start=1)
            ],
            "required_validation": [
                {"argv": list(entry["argv"]), "label": entry["label"]}
                for entry in entries
                if entry["mandatory"]
            ],
            "max_changed_files": 8,
            "validation_policy": {"version": 1, "entries": entries},
        }

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_executable_identity_resolves_against_entry_cwd(self) -> None:
        review = runner.review_module()
        work = self.root / "identity"
        entry_cwd = work / "allowed" / "pkg"
        entry_cwd.mkdir(parents=True)
        (entry_cwd / "bin").mkdir()
        root_tool = work / "tool"
        sub_tool = entry_cwd / "tool"
        root_tool.write_bytes(b"#!/bin/sh\nexit 0\n")
        sub_tool.write_bytes(b"#!/bin/sh\nexit 0\n# subdir bytes\n")
        root_tool.chmod(0o755)
        sub_tool.chmod(0o755)
        (work / "bin").mkdir()
        (work / "bin" / "runner").write_bytes(b"root runner\n")
        (entry_cwd / "bin" / "runner").write_bytes(b"entry-cwd runner\n")
        (work / "bin" / "runner").chmod(0o755)
        (entry_cwd / "bin" / "runner").chmod(0o755)
        env = {"PATH": "bin"}
        relative = review._executable_identity("./tool", env, cwd=entry_cwd)
        self.assertTrue(relative["available"], relative)
        self.assertEqual(
            relative["realpath"], str(sub_tool.resolve()), relative
        )
        self.assertEqual(
            relative["sha256"], hashlib.sha256(sub_tool.read_bytes()).hexdigest()
        )
        self.assertNotEqual(
            relative["sha256"],
            hashlib.sha256(root_tool.read_bytes()).hexdigest(),
        )
        searched = review._executable_identity("runner", env, cwd=entry_cwd)
        self.assertTrue(searched["available"], searched)
        self.assertEqual(
            searched["realpath"],
            str((entry_cwd / "bin" / "runner").resolve()),
            searched,
        )
        # An absolute argv0 stays exact and is never rewritten.
        absolute = review._executable_identity(str(root_tool), env, cwd=entry_cwd)
        self.assertEqual(absolute["realpath"], str(root_tool.resolve()))

    def test_optional_validation_entries_are_visible_not_mandatory(self) -> None:
        review = runner.review_module()
        workspace = self.root / "optional-workspace"
        workspace.mkdir()
        policy = {
            "entries": [
                {
                    "invocation_id": "V001",
                    "label": "mandatory negative command check",
                    "argv": ["python3", "-c", "raise SystemExit(3)"],
                    "cwd": ".",
                    "context": "ordinary_ro",
                    "purpose": "Mandatory command check with nonzero expected exit.",
                    "mandatory": True,
                    "expected_exit": 3,
                    "timeout_seconds": 10,
                    "capture_limit_bytes": 4096,
                    "environment_policy": "minimal_private",
                    "ro_enforcement": "required",
                    "evidence": {"kind": "command_check"},
                },
                {
                    "invocation_id": "V002",
                    "label": "optional passing probe",
                    "argv": ["python3", "-c", "pass"],
                    "cwd": ".",
                    "context": "ordinary_ro",
                    "purpose": "Optional context probe that may be skipped.",
                    "mandatory": False,
                    "expected_exit": 0,
                    "timeout_seconds": 10,
                    "capture_limit_bytes": 4096,
                    "environment_policy": "minimal_private",
                    "ro_enforcement": "required",
                    "evidence": {"kind": "command_check"},
                },
            ]
        }
        cwd = str(workspace.resolve())
        intent = {
            "payload": {
                "validation_id": "v" + "1" * 40,
                "batch_id": "v" + "1" * 40,
                "job_id": "val-" + "2" * 48,
                "source_attempt_id": "3" * 64,
                "source_job_id": "impl-" + "4" * 43,
                "source_evidence_digest": "5" * 64,
                "source_final_snapshot_digest": "6" * 64,
                "source_kind": "complete",
                "generation": 0,
                "candidate_sha256": "7" * 64,
                "contract_digest": "8" * 64,
                "policy_digest": review._policy_digest(policy),
            }
        }
        claim = {"payload": {"claim_digest": "9" * 64, "base_snapshot_digest": "a" * 64}}
        binding = {
            "source_attempt_id": intent["payload"]["source_attempt_id"],
            "source_job_id": intent["payload"]["source_job_id"],
            "source_evidence_digest": intent["payload"]["source_evidence_digest"],
            "source_final_snapshot_digest": intent["payload"][
                "source_final_snapshot_digest"
            ],
            "source_kind": "complete",
            "generation": 0,
            "candidate_sha256": intent["payload"]["candidate_sha256"],
            "contract_digest": intent["payload"]["contract_digest"],
            "policy_digest": intent["payload"]["policy_digest"],
            "validation_id": intent["payload"]["validation_id"],
            "batch_id": intent["payload"]["batch_id"],
            "claim_digest": claim["payload"]["claim_digest"],
            "base_snapshot_digest": claim["payload"]["base_snapshot_digest"],
        }

        def entry(
            invocation_id: str,
            exit_code: int,
            *,
            passed: bool,
            ro_mode: str = "kernel_ro",
        ) -> dict:
            return {
                "invocation_id": invocation_id,
                "argv": policy["entries"][
                    0 if invocation_id == "V001" else 1
                ]["argv"],
                "masked_argv_sha256": review._digest(
                    policy["entries"][
                        0 if invocation_id == "V001" else 1
                    ]["argv"]
                ),
                "cwd": cwd,
                "context": "ordinary_ro",
                "ro_enforcement": "required",
                "ro_mode": ro_mode,
                "environment_policy": "minimal_private",
                "evidence_kind": "command_check",
                "exit_code": exit_code,
                "expected_exit": 3 if invocation_id == "V001" else 0,
                "timed_out": False,
                "cancelled": False,
                "overflow": False,
                "counts": None,
                "structured": None,
                "passed": passed,
                "stdout": None,
                "stderr": None,
                "reasons": [],
            }

        def evaluate(entries: list[dict]) -> list[str]:
            evidence = {
                "version": review.VALIDATION_BATCH_VERSION,
                "validation_id": intent["payload"]["validation_id"],
                "batch_id": intent["payload"]["batch_id"],
                "job_id": intent["payload"]["job_id"],
                "binding": binding,
                "entries": entries,
                "cancelled": False,
                "blocked": False,
                "source_drift": False,
                "post_snapshot_digest": claim["payload"]["base_snapshot_digest"],
            }
            normalized = review._verify_validation_evidence(
                "optional-plan",
                evidence,
                intent=intent,
                claim=claim,
                policy=policy,
                final_check={
                    "state": "clean",
                    "report": {"supported": True},
                },
                meta={"workspace": str(workspace), "git_baseline": None},
            )
            return list(normalized["reasons"])

        # Optional probe did not pass (for example an unsupported skip); the
        # mandatory entry passed under kernel RO, so the batch has no reasons.
        okay = evaluate(
            [
                entry("V001", 3, passed=True),
                entry("V002", 1, passed=False),
            ]
        )
        self.assertEqual(okay, [])
        # Missing and duplicate declared entries remain global failures.
        missing = evaluate([entry("V001", 3, passed=True)])
        self.assertTrue(any("order or coverage" in reason for reason in missing), missing)
        with self.assertRaises(Exception):
            evaluate(
                [
                    entry("V001", 3, passed=True),
                    entry("V001", 3, passed=True),
                ]
            )
        with self.assertRaises(Exception):
            evaluate(
                [
                    entry("V001", 3, passed=True),
                    entry("V999", 0, passed=True),
                ]
            )
        # Contradictory pass claims and mandatory non-kernel/non-green records
        # are still refused.
        contradictory = evaluate(
            [
                entry("V001", 3, passed=True),
                entry("V002", 1, passed=True),
            ]
        )
        self.assertTrue(
            any("contradicts the actual exit" in reason for reason in contradictory),
            contradictory,
        )
        not_kernel = evaluate(
            [
                entry("V001", 3, passed=True, ro_mode="not_started"),
                entry("V002", 1, passed=False),
            ]
        )
        self.assertTrue(
            any("kernel read-only" in reason for reason in not_kernel), not_kernel
        )
        wrong_exit = evaluate(
            [
                entry("V001", 2, passed=True),
                entry("V002", 1, passed=False),
            ]
        )
        self.assertTrue(
            any("does not match the frozen expected exit" in reason for reason in wrong_exit),
            wrong_exit,
        )

    def test_adapter_structured_counts(self) -> None:
        work = self.root / "adapter"
        tests = work / "tests"
        tests.mkdir(parents=True)
        (tests / "test_pass.py").write_text(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_a(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        report = work / "report.json"
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "D2_STRUCTURED_REPORT": str(report),
            "D2_STRUCTURED_RUN_ID": "run-pass",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(D_REVIEW),
                "_unittest-adapter",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
            ],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(report.read_text())
        self.assertEqual(document["run_id"], "run-pass")
        self.assertEqual(document["counts"]["collected"], 1)
        self.assertEqual(document["counts"]["run"], 1)
        self.assertEqual(document["counts"]["passed"], 1)
        self.assertEqual(document["counts"]["skips"], 0)
        self.assertEqual(
            document["argv"][-5:],
            ["discover", "-s", "tests", "-p", "test_*.py"],
        )

    def test_version1_normalization_remains_exact(self) -> None:
        b1 = runner.b1_module()
        constraints = {
            "version": 1,
            "allowed_paths": ["allowed/**"],
            "denied_paths": [".env"],
            "criteria": [
                {"id": "C001", "text_sha256": "a" * 64},
            ],
            "required_validation": [
                {"argv": ["python3", "-m", "unittest", "discover"]}
            ],
            "max_changed_files": 8,
        }
        normalized = b1.validate_execution_constraints(constraints, None)
        self.assertEqual(
            normalized,
            {
                "version": 1,
                "allowed_paths": ["allowed/**"],
                "denied_paths": [".env"],
                "criteria": [{"id": "C001", "text_sha256": "a" * 64}],
                "required_validation": [
                    {"argv": ["python3", "-m", "unittest", "discover"]}
                ],
                "max_changed_files": 8,
            },
        )

    @REAL_BWRAP
    def test_full_validate_review_repair_approve(self) -> None:
        self.create_plan()
        constraints = self.constraints()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        contract = self.contract_document(digest, constraints)
        self.freeze_contract(contract)
        task = self.implementation_task()
        launched = self.implement(
            task,
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        status = self.wait(job_id)
        self.assertEqual(status.get("state"), "succeeded", status)
        finalized = self.finalize_job(job_id)
        self.assertTrue(finalized["completed"], finalized)
        self.assertEqual(finalized["state"], "IMPLEMENTATION_COMPLETE")
        self.assertEqual(
            self.checkpoint()["execution"]["d2"]["stage"],
            "AWAITING_VALIDATION",
        )

        validation = self.run_validation()
        self.assertEqual(validation["classification"], "passed", validation)
        self.assertGreaterEqual(validation["counts"]["run"], 1)
        self.assertEqual(validation["counts"]["skips"], 0)
        self.assertEqual(
            self.checkpoint()["execution"]["stage"], "AWAITING_REVIEW"
        )

        review_id, session = self.begin_review("reject the initial implementation")
        rejection = self.record_review(
            review_id,
            session,
            verdict="REQUEST_CHANGES",
            findings=[
                {
                    "finding_id": "F001",
                    "kind": "defect",
                    "severity": "high",
                    "files": ["allowed/impl.txt"],
                    "summary": "The initial implementation omits the required marker.",
                    "evidence": "allowed/impl.txt contains only a placeholder line.",
                    "required_change": "Write the required marker content.",
                    "test_recommendation": "Cover the marker with a structured test.",
                }
            ],
        )
        self.assertEqual(rejection["verdict"], "REQUEST_CHANGES")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "REPAIR_REQUIRED")
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["remaining"], 3
        )

        frozen = self.freeze_repair_contract(constraints, review_id, ["F001"])
        allocation = self.allocate_repair(review_id)
        self.assertEqual(allocation["generation"], 1)
        self.assertEqual(allocation["remaining"], 2)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "REPAIR_PREPARED")
        self.assertEqual(checkpoint["execution"]["formal_repair_budget"]["used"], 1)

        repair_launch = self.repair(
            allocation["allocation_id"],
            self.write_writes(
                [("allowed/impl.txt", b"required marker\n")],
                [],
                ["allowed/impl.txt"],
                operation="repair",
            ),
        )
        repair_job = repair_launch["job_id"]
        status = self.wait(repair_job)
        self.assertEqual(status.get("state"), "succeeded", status)
        repaired = self.finalize_job(repair_job)
        self.assertTrue(repaired["completed"], repaired)
        self.assertEqual(repaired["state"], "REPAIR_APPLIED")
        self.assertEqual(
            self.checkpoint()["execution"]["stage"], "AWAITING_VALIDATION"
        )

        fresh = self.run_validation()
        self.assertEqual(fresh["classification"], "passed", fresh)
        approve_id, approve_session = self.begin_review(
            "approve the repaired implementation"
        )
        approval = self.record_review(
            approve_id,
            approve_session,
            verdict="APPROVE",
            dispositions=[
                {
                    "finding_id": "F001",
                    "disposition": "resolved",
                    "evidence": "allowed/impl.txt now contains the required marker.",
                }
            ],
        )
        self.assertEqual(approval["verdict"], "APPROVE")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "REVIEW_APPROVED")
        self.assertTrue(checkpoint["execution"]["d2"]["approval"]["valid"])
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["used"], 1
        )
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["remaining"], 2
        )
        self.assertFalse(checkpoint["complete"])
        plan = self.plan_status()
        self.assertNotEqual(plan["items"][0].get("state"), "done")
        journal = self.journal()
        self.assertEqual(len(journal["validation_results"]), 2)
        self.assertEqual(len(journal["reviews"]), 2)
        self.assertEqual(len(journal["repair_allocations"]), 1)
        self.assertTrue(
            all("attempt_id" not in event["payload"] for event in journal["reviews"])
        )
        self.assertTrue(
            all(
                "attempt_id" not in event["payload"]
                for event in journal["validation_results"]
            )
        )
        # The session is single use: replaying the same document must fail.
        replay = self.record_review(
            approve_id,
            approve_session,
            verdict="APPROVE",
            dispositions=[
                {
                    "finding_id": "F001",
                    "disposition": "resolved",
                    "evidence": "allowed/impl.txt now contains the required marker.",
                }
            ],
            expect=2,
        )
        self.assertIn("single-use", replay.stderr)

    def drive_to_approval(self, constraints: dict) -> dict:
        """Actual normal-CLI green validation and active-Codex APPROVE."""
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        validation = self.run_validation()
        self.assertEqual(validation["classification"], "passed", validation)
        review_id, session = self.begin_review("approve the actual green source")
        approval = self.record_review(
            review_id, session, verdict="APPROVE"
        )
        self.assertEqual(approval["verdict"], "APPROVE")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "REVIEW_APPROVED")
        self.assertTrue(checkpoint["execution"]["d2"]["approval"]["valid"])
        return checkpoint

    def _drive_to_rejection(
        self, constraints: dict
    ) -> tuple[str, dict, Path]:
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self._first_digest = digest
        contract = self.contract_document(digest, constraints)
        self.freeze_contract(contract)
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        validation = self.run_validation()
        self.assertEqual(validation["classification"], "passed", validation)
        review_id, session = self.begin_review("reject for bounded repair tests")
        self.record_review(
            review_id,
            session,
            verdict="REQUEST_CHANGES",
            findings=[
                {
                    "finding_id": "F001",
                    "kind": "defect",
                    "severity": "high",
                    "files": ["allowed/impl.txt"],
                    "summary": "The implementation is incomplete.",
                    "evidence": "The required marker is absent.",
                    "required_change": "Write the required marker.",
                    "test_recommendation": "Cover the marker with a test.",
                }
            ],
        )
        return review_id, constraints, self.repo

    @REAL_BWRAP
    def test_current_source_drift_invalidates_derived_approval(self) -> None:
        constraints = self.constraints()
        self.drive_to_approval(constraints)
        impl = self.repo / "allowed" / "impl.txt"
        original = impl.read_bytes()
        base_head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        def blocked_after(label: str) -> dict:
            checkpoint = self.checkpoint()
            self.assertEqual(
                checkpoint["execution"]["stage"], "BLOCKED", (label, checkpoint)
            )
            self.assertEqual(
                checkpoint["execution"]["d2"]["stage"], "BLOCKED", label
            )
            self.assertFalse(
                checkpoint["execution"]["d2"]["approval"]["valid"], label
            )
            reasons = " ".join(
                checkpoint["execution"]["blocked_reasons"]
            ).lower()
            self.assertIn("no longer matches", reasons, label)
            return checkpoint

        def approved_again(label: str) -> None:
            checkpoint = self.checkpoint()
            self.assertEqual(
                checkpoint["execution"]["stage"],
                "REVIEW_APPROVED",
                (label, checkpoint),
            )
            self.assertTrue(
                checkpoint["execution"]["d2"]["approval"]["valid"], label
            )

        # Owned-source drift after a genuine approval invalidates only the
        # derived current approval; restoring the exact bytes regenerates it.
        impl.write_bytes(original + b"external unreviewed drift\n")
        try:
            blocked_after("owned")
        finally:
            impl.write_bytes(original)
        approved_again("owned-restore")

        # Unowned/untracked drift is equally current-source drift.
        rogue = self.repo / "unowned-note.txt"
        rogue.write_text("unknown residue\n", encoding="utf-8")
        try:
            blocked_after("unowned")
        finally:
            rogue.unlink()
        approved_again("unowned-restore")

        # Git index / staged user material drift. Restore the exact index bytes
        # afterwards: git may rewrite stat/extension data even when the tree is
        # unchanged, and the custody check is byte-exact by design.
        index_path = self.repo / ".git" / "index"
        index_bytes = index_path.read_bytes()
        staged = self.repo / "user-staged.txt"
        staged.write_text("user staged\n", encoding="utf-8")
        self.git(self.repo, "add", "user-staged.txt")
        try:
            blocked_after("index")
        finally:
            self.git(self.repo, "reset", "-q", "user-staged.txt")
            staged.unlink()
            index_path.write_bytes(index_bytes)
        approved_again("index-restore")

        # HEAD drift after the frozen base head.
        self.git(self.repo, "commit", "--allow-empty", "-qm", "external commit")
        try:
            blocked_after("head")
        finally:
            self.git(self.repo, "reset", "--soft", base_head)
        approved_again("head-restore")

    @REAL_BWRAP
    def test_review_cannot_drop_open_finding_but_explicit_resolution_passes(
        self,
    ) -> None:
        constraints = self.constraints()
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial placeholder\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        self.assertEqual(
            self.run_validation()["classification"], "passed"
        )
        reject_id, reject_session = self.begin_review(
            "actual review finds the required marker absent"
        )
        rejection = self.record_review(
            reject_id,
            reject_session,
            verdict="REQUEST_CHANGES",
            findings=[self.defect("F001")],
        )
        self.assertEqual(rejection["verdict"], "REQUEST_CHANGES")
        # A same-source fresh APPROVE cannot silently omit the open finding.
        approve_id, approve_session = self.begin_review(
            "attempt to approve the unchanged source silently"
        )
        refused = self.write_structured_review(
            approve_id,
            self.approval_document(approve_id, []),
            approve_session,
            expect=2,
        )
        self.assertIn(
            "dispose every prior actionable finding", refused.stderr
        )
        # An explicit, evidence-backed false-positive resolution is trusted
        # actual reviewer judgment and may approve without a code change.
        approval = self.write_structured_review(
            approve_id,
            self.approval_document(approve_id, ["F001"]),
            approve_session,
        )
        self.assertEqual(approval["verdict"], "APPROVE")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "REVIEW_APPROVED")
        self.assertTrue(checkpoint["execution"]["d2"]["approval"]["valid"])

    @REAL_BWRAP
    def test_sigkilled_claimed_validation_becomes_blocked_and_recovers(
        self,
    ) -> None:
        constraints = self.constraints()
        self.drive_to_approval(constraints)
        env = self.validation_env()
        launched = self.json_cli(
            "execution-validate",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--timeout-seconds",
            "120",
            "--config",
            str(self.config),
            "--json",
            env=env,
        )
        job_id = launched["job_id"]
        job_path = self.state / "jobs" / job_id
        meta = json.loads((job_path / "meta.json").read_text(encoding="utf-8"))
        pid = meta.get("worker_pid")
        start = meta.get("worker_start")
        self.assertIsInstance(pid, int, meta)
        self.assertEqual(
            runner.b2_module().process_start_identity(pid), start
        )
        os.kill(pid, signal.SIGKILL)
        self.run_cli(
            "wait",
            job_id,
            "--timeout-seconds",
            "90",
            "--poll-seconds",
            "0.2",
            "--json",
            expected=1,
            timeout=150,
        )
        first = self.json_cli(
            "execution-validation-finalize",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            job_id,
            "--json",
        )
        self.assertEqual(first["classification"], "blocked", first)
        reasons = " ".join(first["reasons"]).lower()
        self.assertIn("missing proof files", reasons)
        self.assertIn("validation-evidence.json", reasons)
        again = self.json_cli(
            "execution-validation-finalize",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            job_id,
            "--json",
        )
        self.assertTrue(again["idempotent"], again)
        self.assertEqual(again["classification"], "blocked", again)
        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["execution"]["stage"], "VALIDATION_BLOCKED", checkpoint
        )
        self.assertFalse(checkpoint["execution"]["d2"]["approval"]["valid"])
        self.assertEqual(
            checkpoint["execution"]["d2"]["validation"]["classification"],
            "blocked",
        )
        blocked = " ".join(checkpoint["execution"]["blocked_reasons"]).lower()
        self.assertIn("validation-evidence.json", blocked)
        # A fresh batch against the unchanged exact source is the supported
        # retry; it must pass and require a new actual review (no old approval).
        fresh = self.run_validation()
        self.assertEqual(fresh["classification"], "passed", fresh)
        self.assertEqual(
            self.checkpoint()["execution"]["stage"], "AWAITING_REVIEW"
        )
        review_id, session = self.begin_review(
            "approve fresh evidence after the dead batch"
        )
        approval = self.record_review(
            review_id, session, verdict="APPROVE"
        )
        self.assertEqual(approval["verdict"], "APPROVE")
        final = self.checkpoint()
        self.assertEqual(final["execution"]["stage"], "REVIEW_APPROVED")
        self.assertTrue(final["execution"]["d2"]["approval"]["valid"])

    @REAL_BWRAP
    def test_validation_skip_fails_and_blocks_approval(self) -> None:
        sample = self.repo / "tests" / "test_sample.py"
        sample.write_text(
            sample.read_text()
            + "\n@unittest.skip('intentional skip for D2 evidence')\n"
            "class SkippedTests(unittest.TestCase):\n"
            "    def test_skipped(self):\n"
            "        self.fail('must never run')\n",
            encoding="utf-8",
        )
        self.git(self.repo, "add", "tests/test_sample.py")
        self.git(self.repo, "commit", "-qm", "add skipped test")
        constraints = self.constraints()
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        validation = self.run_validation()
        self.assertNotEqual(validation["classification"], "passed")
        self.assertEqual(validation["counts"]["skips"], 1)
        self.assertTrue(
            any("skip" in reason.lower() for reason in validation["reasons"]),
            validation,
        )
        review_id, session = self.begin_review(
            "review the actually failed validation"
        )
        approval = self.record_review(
            review_id,
            session,
            verdict="APPROVE",
            expect=2,
        )
        self.assertIn("validation to pass", approval.stderr)
        rejection = self.record_review(
            review_id,
            session,
            verdict="REQUEST_CHANGES",
            findings=[
                {
                    "finding_id": "F001",
                    "kind": "defect",
                    "severity": "high",
                    "files": ["tests/test_sample.py"],
                    "summary": "A mandatory test is skipped.",
                    "evidence": "The structured report records one skip.",
                    "required_change": "Remove the skip or provide real coverage.",
                    "test_recommendation": "Run the required test unskipped.",
                }
            ],
        )
        self.assertEqual(rejection["verdict"], "REQUEST_CHANGES")
        blocked = self.run_cli(
            "execution-implement",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--task-file",
            str(self.implementation_task()),
            "--timeout-seconds",
            "60",
            "--config",
            str(self.config),
            "--json",
            expected=2,
        )
        self.assertIn("D2", blocked.stderr + blocked.stdout)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "REPAIR_REQUIRED")
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["used"], 0
        )

    @REAL_BWRAP
    def test_repair_allocation_idempotency_and_setup_limit(self) -> None:
        constraints = self.constraints()
        review_id, _, _repo = self._drive_to_rejection(constraints)
        frozen = self.freeze_repair_contract(constraints, review_id, ["F001"])
        allocation = self.allocate_repair(review_id)
        self.assertEqual(allocation["generation"], 1)
        again = self.allocate_repair(review_id)
        self.assertTrue(again["idempotent"])
        self.assertEqual(again["allocation_id"], allocation["allocation_id"])
        # Three pre-claim transport failures consume setup attempts only.
        bad_config = self.root / "bad-agents.json"
        bad_config.write_text("{not valid json", encoding="utf-8")
        for _ in range(3):
            self.repair(
                allocation["allocation_id"],
                {},
                config=str(bad_config),
                expect=2,
            )
        fourth = self.repair(
            allocation["allocation_id"],
            {},
            config=str(bad_config),
            expect=2,
        )
        self.assertIn("pre-claim setup attempts", fourth.stderr)
        # A second initial writer cannot escape after D2 ownership exists.
        blocked = self.run_cli(
            "execution-implement",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--task-file",
            str(self.implementation_task()),
            "--timeout-seconds",
            "60",
            "--config",
            str(self.config),
            "--json",
            expected=2,
        )
        self.assertIn("D2", blocked.stderr + blocked.stdout)
        # Close the never-started setup intent as a proven no-start before a
        # fresh review; the consumed slot is never refunded.
        journal = self.journal()
        pending = [
            event
            for event in journal["intents"]
            if event["payload"].get("repair_allocation_id")
            == allocation["allocation_id"]
        ]
        self.assertTrue(pending)
        self.json_cli(
            "execution-abort",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            pending[-1]["payload"]["job_id"],
            "--reason",
            "three pre-claim setup attempts failed with no durable start",
            "--json",
        )
        # Two fresh rejections consume generations 2 and 3, then the fourth
        # contract/allocation is refused and the budget remains used=3. No
        # source repair occurs anywhere in this budget fixture, so every
        # earlier actionable finding stays open and must be explicitly
        # carried in each later review and repair contract.
        open_findings = ["F001"]

        def carried_dispositions() -> list[dict[str, str]]:
            return [
                {
                    "finding_id": finding_id,
                    "disposition": "carried",
                    "evidence": (
                        "No source repair occurred, so this actionable defect "
                        "remains open for the formal repair budget."
                    ),
                }
                for finding_id in open_findings
            ]

        for generation, finding in ((2, "F002"), (3, "F003")):
            current_review, session = self.begin_review(
                f"reject again for generation {generation}"
            )
            self.record_review(
                current_review,
                session,
                verdict="REQUEST_CHANGES",
                dispositions=carried_dispositions(),
                findings=[
                    {
                        "finding_id": finding,
                        "kind": "defect",
                        "severity": "medium",
                        "files": ["allowed/impl.txt"],
                        "summary": "A further actionable defect remains.",
                        "evidence": "The required behavior is still incomplete.",
                        "required_change": "Address the remaining defect.",
                        "test_recommendation": "Add structured coverage.",
                    }
                ],
            )
            self.freeze_repair_contract(
                constraints, current_review, open_findings + [finding]
            )
            allocated = self.allocate_repair(current_review)
            self.assertEqual(allocated["generation"], generation)
            open_findings.append(finding)
        fourth_review, fourth_session = self.begin_review(
            "reject once more after the budget"
        )
        self.record_review(
            fourth_review,
            fourth_session,
            verdict="REQUEST_CHANGES",
            dispositions=carried_dispositions(),
            findings=[
                {
                    "finding_id": "F004",
                    "kind": "defect",
                    "severity": "high",
                    "files": ["allowed/impl.txt"],
                    "summary": "A fourth defect would exceed the budget.",
                    "evidence": "The step already consumed three slots.",
                    "required_change": "Require human guidance.",
                    "test_recommendation": "No further automatic repair.",
                }
            ],
        )
        refused = self.freeze_repair_contract(
            constraints,
            fourth_review,
            open_findings + ["F004"],
            expect=2,
        )
        self.assertIn("exhausted", refused.stderr)
        refused_allocate = self.allocate_repair(fourth_review, expect=2)
        self.assertTrue(refused_allocate.stderr)
        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["used"], 3
        )
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["remaining"], 0
        )
        self.assertEqual(checkpoint["execution"]["stage"], "REPAIR_REQUIRED")

    @REAL_BWRAP
    def test_new_design_cycle_does_not_reset_repair_budget(self) -> None:
        constraints = self.constraints()
        review_id, _, _repo = self._drive_to_rejection(constraints)
        self.freeze_repair_contract(constraints, review_id, ["F001"])
        first = self.allocate_repair(review_id)
        self.assertEqual(first["generation"], 1)
        reopened = self.json_cli(
            "consensus-new-cycle",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "codex",
            "--authorization",
            "Coordinator requests a fresh design cycle after review.",
            "--authorization-kind",
            "coordinator",
            "--json",
        )
        self.assertEqual(reopened["stage"], "PROPOSALS_OPEN")
        for role in ("deepseek", "glm", "codex"):
            payload = proposal_payload()
            job = (
                self.launch_discussion(role, 1, "proposal", payload)
                if role != "codex"
                else None
            )
            self.submit(role, 1, "proposal", payload, job)
        for role in ("deepseek", "glm", "codex"):
            payload = cross_payload(
                "A new design cycle must preserve the previous owned lineage."
            )
            job = (
                self.launch_discussion(role, 2, "cross_examination", payload)
                if role != "codex"
                else None
            )
            self.submit(role, 2, "cross_examination", payload, job)
        new_digest = self.freeze_candidate(
            self.candidate(constraints=constraints)
        )
        for role in ("deepseek", "glm", "codex"):
            payload = consensus_payload(new_digest)
            job = (
                self.launch_discussion(
                    role,
                    3,
                    "consensus",
                    payload,
                    extra_env={"C_FAKE_CANDIDATE": new_digest},
                )
                if role != "codex"
                else None
            )
            self.vote(role, new_digest, job, rationale=payload["rationale"])
        self.freeze_contract(self.contract_document(new_digest, constraints))
        # The design link must carry the proven owned delta and dispose the
        # open finding; the consumed repair slot is never refunded or reset.
        dispositions = self.root / "design-dispositions.json"
        dispositions.write_text(
            json.dumps(
                [
                    {
                        "finding_id": "F001",
                        "disposition": "carried",
                        "evidence": (
                            "The new design carries the same owned source and "
                            "keeps the finding open for a formal repair."
                        ),
                    }
                ]
            ),
            encoding="utf-8",
        )
        linked = self.json_cli(
            "execution-design-link",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--previous-candidate",
            self._first_digest,
            "--dispositions-file",
            str(dispositions),
            "--json",
        )
        self.assertEqual(linked["owned_paths"], ["allowed/impl.txt"])
        checkpoint = self.checkpoint()
        # A linked new design is not executable by this implementation: it must
        # never advertise READY_TO_IMPLEMENT while every permitted route
        # refuses. The truthful state is a precise BLOCKED with guidance.
        self.assertEqual(
            checkpoint["execution"]["stage"], "BLOCKED", checkpoint
        )
        self.assertEqual(
            checkpoint["execution"]["d2"]["stage"], "BLOCKED"
        )
        blocked = " ".join(checkpoint["execution"]["blocked_reasons"]).lower()
        self.assertIn("linked source", blocked)
        guidance = str(checkpoint["execution"]["next_action"]).lower()
        self.assertIn("guidance", guidance)
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["used"], 1
        )
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["remaining"], 2
        )
        # Every actual continuation route refuses; the old approval/result is
        # never relabeled as authority under the new design.
        attempts = [
            (
                "execution-implement",
                [
                    "--plan-id",
                    "d2-plan",
                    "--step-id",
                    "step-one",
                    "--task-file",
                    str(self.implementation_task()),
                    "--config",
                    str(self.config),
                    "--json",
                ],
                "D2",
            ),
            (
                "execution-validate",
                [
                    "--plan-id",
                    "d2-plan",
                    "--step-id",
                    "step-one",
                    "--config",
                    str(self.config),
                    "--json",
                ],
                "writer",
            ),
            (
                "execution-review-begin",
                [
                    "--plan-id",
                    "d2-plan",
                    "--step-id",
                    "step-one",
                    "--leader",
                    "codex-leader",
                    "--purpose",
                    "inspect an unsupported linked carry",
                    "--session-file",
                    str(self.root / "unsupported-carry-session.json"),
                    "--json",
                ],
                "writer",
            ),
        ]
        for command, arguments, needle in attempts:
            result = self.run_cli(command, *arguments, expected=2)
            self.assertIn(needle.lower(), (result.stderr + result.stdout).lower())
        # The old rejection is not a current rejection under the new design.
        stale = self.allocate_repair(review_id, expect=2)
        self.assertIn("review", stale.stderr.lower())

    def test_observed_unconfined_policy_is_rejected(self) -> None:
        b1 = runner.b1_module()
        observed = self.constraints(ro_enforcement="observed")
        with self.assertRaises(Exception) as caught:
            b1.validate_execution_constraints(observed, None)
        message = str(caught.exception)
        self.assertIn("required", message)
        self.assertIn("observed", message)
        # A version-2 constraints document without the field is equally invalid:
        # there is no default privilege context.
        missing = self.constraints()
        entry = missing["validation_policy"]["entries"][0]
        entry.pop("ro_enforcement")
        with self.assertRaises(Exception):
            b1.validate_execution_constraints(missing, None)

    def test_nonconfining_wrapper_blocks_validation(self) -> None:
        constraints = self.constraints()
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        local = dict(self.env)  # PATH includes the nonconfining bwrap shim
        validation_job = self.json_cli(
            "execution-validate",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--timeout-seconds",
            "120",
            "--config",
            str(self.config),
            "--json",
            env=local,
        )["job_id"]
        # The worker completes its own process lifetime, but the evidence is a
        # precise BLOCKED result: a forwarding shim never supplies authority.
        self.assertEqual(self.wait(validation_job).get("state"), "succeeded")
        final = self.json_cli(
            "execution-validation-finalize",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            validation_job,
            "--json",
        )
        self.assertEqual(final["classification"], "blocked", final)
        self.assertEqual(final["counts"]["run"], 0)
        self.assertTrue(
            any(
                "read-only" in reason.lower() or "not refused" in reason.lower()
                for reason in final["reasons"]
            ),
            final,
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "VALIDATION_BLOCKED")
        evidence = json.loads(
            (
                self.state
                / "jobs"
                / validation_job
                / "validation-evidence.json"
            ).read_text()
        )
        self.assertTrue(evidence["blocked"])
        self.assertEqual(evidence["entries"][0]["ro_mode"], "not_started")
        self.assertNotIn("observed_no_kernel", json.dumps(evidence))
        # Approval is impossible without a genuinely passing validation.
        review_id, session = self.begin_review(
            "attempt to approve a blocked validation"
        )
        refused = self.record_review(
            review_id, session, verdict="APPROVE", expect=2
        )
        self.assertIn("validation to pass", refused.stderr)

    def test_sandbox_mount_order_and_capability_policy(self) -> None:
        review = runner.review_module()
        workspace = self.root / "canonical-work"
        workspace.mkdir()
        scratch = self.root / "scratch"
        scratch.mkdir()
        self.state.mkdir(parents=True, exist_ok=True)
        adapter = self.state / "cache" / "pinned-adapter.py"
        adapter.parent.mkdir(parents=True)
        adapter.write_text("pinned\n", encoding="utf-8")
        ordinary, layout, reason = review._sandbox_prefix(
            {"context": "ordinary_ro"},
            workspace=workspace,
            scratch=scratch,
            extra_ro_paths=[adapter],
        )
        self.assertEqual(reason, "")
        self.assertIsNotNone(ordinary)
        self.assertEqual(layout["cap_drop"], "ALL")
        self.assertTrue(layout["unshare_pid"])
        self.assertIn("--cap-drop", ordinary)
        self.assertIn("ALL", ordinary)
        self.assertIn("--unshare-pid", ordinary)
        # Order: root read-only -> known masks -> private /tmp -> canonical
        # source -> exact adapter -> private scratch.
        tmpfs_tmp = ordinary.index("--tmpfs", ordinary.index("--ro-bind"))
        private_tmp = None
        for index, value in enumerate(ordinary):
            if value == "--tmpfs" and ordinary[index + 1] == "/tmp":
                private_tmp = index
                break
        self.assertIsNotNone(private_tmp)
        masked_state = any(
            ordinary[index + 1] == str(self.state)
            for index, value in enumerate(ordinary)
            if value == "--tmpfs"
        )
        self.assertTrue(masked_state)
        workspace_mount = [
            index
            for index in range(len(ordinary) - 1)
            if ordinary[index] == "--ro-bind"
            and ordinary[index + 1] == str(workspace)
        ]
        adapter_mount = [
            index
            for index in range(len(ordinary) - 1)
            if ordinary[index] == "--ro-bind"
            and ordinary[index + 1] == str(adapter)
        ]
        self.assertTrue(workspace_mount)
        self.assertTrue(adapter_mount)
        self.assertLess(private_tmp, workspace_mount[0])
        self.assertLess(workspace_mount[0], adapter_mount[0])
        scratch_mount = [
            index
            for index in range(len(ordinary) - 1)
            if ordinary[index] == "--bind"
            and ordinary[index + 1] == str(scratch)
        ]
        self.assertTrue(scratch_mount)
        self.assertLess(adapter_mount[0], scratch_mount[0])
        # The scratch destination must be created inside the private /tmp
        # tmpfs; the read-only root bind cannot mkdir a new top-level path.
        scratch_destination = ordinary[scratch_mount[0] + 2]
        self.assertEqual(scratch_destination, "/tmp/d2scratch")
        self.assertEqual(layout["private_scratch"], "/tmp/d2scratch")
        self.assertNotEqual(scratch_destination, "/d2scratch")
        self.assertLess(private_tmp, scratch_mount[0] + 2)
        self.assertFalse(
            any(
                ordinary[index] == "--ro-bind"
                and ordinary[index + 1] == "/d2scratch"
                for index in range(len(ordinary) - 1)
            )
        )
        # The whole coordinator root is not re-exposed: only the exact adapter.
        self.assertFalse(
            any(
                ordinary[index] == "--ro-bind"
                and ordinary[index + 1] == str(self.state)
                for index in range(len(ordinary) - 1)
            )
        )
        self.assertGreater(tmpfs_tmp, 0)
        systems, systems_layout, _ = review._sandbox_prefix(
            {"context": "systems_trusted"},
            workspace=workspace,
            scratch=scratch,
            extra_ro_paths=[adapter],
        )
        self.assertIsNotNone(systems)
        self.assertEqual(systems_layout["cap_drop"], "none")
        self.assertFalse(systems_layout["unshare_pid"])
        self.assertNotIn("--cap-drop", systems)
        self.assertNotIn("--unshare-pid", systems)
        self.assertTrue(
            any(
                systems[index] == "--ro-bind"
                and systems[index + 1] == str(workspace)
                for index in range(len(systems) - 1)
            )
        )
        systems_scratch = [
            index
            for index in range(len(systems) - 1)
            if systems[index] == "--bind"
            and systems[index + 1] == str(scratch)
        ]
        self.assertTrue(systems_scratch)
        self.assertEqual(systems[systems_scratch[0] + 2], "/tmp/d2scratch")
        self.assertEqual(systems_layout["private_scratch"], "/tmp/d2scratch")

    def test_capture_sanitizer_redacts_raw_escaped_and_fragmented_values(
        self,
    ) -> None:
        review = runner.review_module()
        c = runner.c_module()
        secret = 'synth-"quoted"-\\value-0123456789abcdef'
        previous = os.environ.get("GH_TOKEN")
        os.environ["GH_TOKEN"] = secret
        try:
            redactor = review._review_redactor()
        finally:
            if previous is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = previous
        encoded = secret.encode("utf-8")
        escaped = json.dumps({"payload": secret}).encode("utf-8")
        raw = b"before " + encoded + b" after"
        for data in (raw, escaped):
            clean = review._sanitize_capture(
                data, overflow=False, redactor=redactor
            )
            self.assertNotIn(encoded, clean)
            self.assertNotIn(secret.replace('"', '\\"').encode(), clean)
            self.assertIn(b"REDACTED", clean)
        # The same value split across real reader chunks is still removed
        # because sanitization runs over the complete bounded buffer.
        buffer = c.CaptureBuffer(4096)
        buffer.feed(b"chunk-one " + encoded[:12])
        buffer.feed(encoded[12:] + b" chunk-two")
        clean = c.sanitize_capture(buffer, redactor)
        self.assertNotIn(encoded, clean)
        self.assertIn(b"REDACTED", clean)
        # Overflow still removes the complete secret before truncation.
        overflowed = review._sanitize_capture(
            encoded + b"x" * 10_000, overflow=True, redactor=redactor
        )
        self.assertNotIn(encoded, overflowed)
        self.assertIn(b"truncated", overflowed)
        # Token-shaped values are redacted even without a known env value.
        pattern_only = review._review_redactor()
        token = b"ghp_" + b"A" * 24
        self.assertNotIn(
            token,
            review._sanitize_capture(
                b"token=" + token, overflow=False, redactor=pattern_only
            ),
        )

    def test_structured_identities_are_sanitized_before_persisting(self) -> None:
        review = runner.review_module()
        secret = "synth-structured-secret-0123456789"
        previous = os.environ.get("DEEPSEEK_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = secret
        try:
            redactor = review._review_redactor()
        finally:
            if previous is None:
                os.environ.pop("DEEPSEEK_API_KEY", None)
            else:
                os.environ["DEEPSEEK_API_KEY"] = previous
        argv = ["python3", "-m", "unittest"]
        report = self.root / "structured-report.json"
        document = {
            "version": 1,
            "adapter_id": "coordinator-stdlib-unittest",
            "adapter_version": 1,
            "run_id": "run-1",
            "argv": argv,
            "argv_sha256": hashlib.sha256(
                json.dumps(
                    argv,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
            "cwd": str(self.repo),
            "python": "3.12.0",
            "started_at": "start",
            "finished_at": "finish",
            "counts": {
                "collected": 1,
                "run": 1,
                "passed": 1,
                "failures": 0,
                "errors": 0,
                "skips": 0,
            },
            "identities": {
                "failures": [],
                "errors": [],
                "skips": [],
                "expected_failures": [],
                "unexpected_successes": [f"test_{secret}"],
            },
            "adapter_error": f"diagnostic included {secret}",
        }
        report.write_text(json.dumps(document), encoding="utf-8")
        entry = {
            "evidence": {
                "kind": "structured_unittest",
                "adapter": {
                    "id": "coordinator-stdlib-unittest",
                    "version": 1,
                    "path": str(D_REVIEW),
                    "sha256": hashlib.sha256(D_REVIEW.read_bytes()).hexdigest(),
                },
                "report_env": "D2_STRUCTURED_REPORT",
                "min_collected": 1,
                "min_run": 1,
            }
        }
        payload, reasons = review._structured_report(
            report,
            entry=entry,
            run_id="run-1",
            argv=argv,
            cwd=self.repo,
            actual_exit=0,
            redactor=redactor,
        )
        self.assertIsNotNone(payload, reasons)
        dumped = json.dumps(payload)
        self.assertNotIn(secret, dumped)
        self.assertIn("[REDACTED]", dumped)
        self.assertNotIn(secret, report.read_text())

    def test_validation_entry_schema_boundaries(self) -> None:
        review = runner.review_module()
        base = {
            "invocation_id": "V001",
            "evidence_kind": "command_check",
            "exit_code": 0,
            "timed_out": False,
            "cancelled": False,
            "overflow": False,
            "passed": True,
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "stdout_bytes": 1,
            "stderr_bytes": 1,
            "counts": None,
            "context": "ordinary_ro",
            "ro_enforcement": "required",
            "reasons": [],
        }
        review._validate_entry_summary(dict(base), "entry")
        observed = dict(base, ro_enforcement="observed")
        with self.assertRaises(Exception):
            review._validate_entry_summary(observed, "entry")
        invented = dict(
            base,
            counts={
                "collected": 1,
                "run": 1,
                "passed": 1,
                "failures": 0,
                "errors": 0,
                "skips": 0,
            },
        )
        with self.assertRaises(Exception) as caught:
            review._validate_entry_summary(invented, "entry")
        self.assertIn("cannot claim", str(caught.exception))
        with self.assertRaises(Exception):
            review._validate_entry_summary(
                dict(base, stdout_sha256="not-a-digest"), "entry"
            )
        with self.assertRaises(Exception):
            review._validate_entry_summary(dict(base, stdout_bytes=-1), "entry")
        with self.assertRaises(Exception):
            review._validate_entry_summary(
                dict(base, context="unconfined_host"), "entry"
            )

    def test_structured_counts_zero_skip_and_failure_block(self) -> None:
        review = runner.review_module()
        redactor = review._review_redactor()
        argv = ["python3", "-m", "unittest"]
        entry = {
            "evidence": {
                "kind": "structured_unittest",
                "adapter": {
                    "id": "coordinator-stdlib-unittest",
                    "version": 1,
                    "path": str(D_REVIEW),
                    "sha256": hashlib.sha256(D_REVIEW.read_bytes()).hexdigest(),
                },
                "report_env": "D2_STRUCTURED_REPORT",
                "min_collected": 2,
                "min_run": 2,
            }
        }
        identities = {
            "failures": [],
            "errors": [],
            "skips": [],
            "expected_failures": [],
            "unexpected_successes": [],
        }

        def audit(name: str, counts: dict, identities_value: dict, exit_code: int):
            path = self.root / f"counts-{name}.json"
            document = {
                "version": 1,
                "adapter_id": "coordinator-stdlib-unittest",
                "adapter_version": 1,
                "run_id": name,
                "argv": argv,
                "argv_sha256": hashlib.sha256(
                    json.dumps(
                        argv, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest(),
                "cwd": str(self.repo),
                "python": "3.12.0",
                "started_at": "start",
                "finished_at": "finish",
                "counts": counts,
                "identities": identities_value,
                "adapter_error": None,
            }
            path.write_text(json.dumps(document), encoding="utf-8")
            payload, reasons = review._structured_report(
                path,
                entry=entry,
                run_id=name,
                argv=argv,
                cwd=self.repo,
                actual_exit=exit_code,
                redactor=redactor,
            )
            return payload, reasons

        zero = {
            "collected": 0,
            "run": 0,
            "passed": 0,
            "failures": 0,
            "errors": 0,
            "skips": 0,
        }
        _payload, reasons = audit("zero", zero, identities, 0)
        self.assertTrue(any("fewer tests" in reason for reason in reasons), reasons)
        skipped_counts = {
            "collected": 2,
            "run": 2,
            "passed": 1,
            "failures": 0,
            "errors": 0,
            "skips": 1,
        }
        skipped_ids = dict(identities, skips=["test_a"])
        _payload, reasons = audit("skip", skipped_counts, skipped_ids, 0)
        self.assertTrue(any("skipped" in reason for reason in reasons), reasons)
        failed_counts = {
            "collected": 2,
            "run": 2,
            "passed": 1,
            "failures": 1,
            "errors": 0,
            "skips": 0,
        }
        failed_ids = dict(identities, failures=["test_a"])
        _payload, reasons = audit("failure", failed_counts, failed_ids, 0)
        self.assertTrue(
            any("failing" in reason for reason in reasons), reasons
        )
        self.assertTrue(
            any("exited 0" in reason for reason in reasons), reasons
        )
        mismatched_ids = dict(identities, failures=["test_a"])
        passing_counts = {
            "collected": 2,
            "run": 2,
            "passed": 2,
            "failures": 0,
            "errors": 0,
            "skips": 0,
        }
        _payload, reasons = audit(
            "identity-mismatch", passing_counts, mismatched_ids, 0
        )
        self.assertTrue(
            any("does not match the reported count" in reason for reason in reasons),
            reasons,
        )

    def test_review_normalization_rejects_contradictions(self) -> None:
        review = runner.review_module()
        contract = {
            "acceptance_criteria": [
                {"id": "C001", "text": "criterion one"},
                {"id": "C002", "text": "criterion two"},
            ]
        }
        finding = {
            "finding_id": "F001",
            "kind": "defect",
            "severity": "high",
            "files": ["allowed/impl.txt"],
            "summary": "The behavior is missing.",
            "evidence": "The file does not contain the marker.",
            "required_change": "Write the marker.",
            "test_recommendation": "Add a test.",
        }
        base = {
            "version": 1,
            "review_id": "r1",
            "verdict": "REQUEST_CHANGES",
            "leader": "codex-leader",
            "summary": "The active leader inspected the exact source and tests.",
            "findings": [finding],
            "criteria": [
                {
                    "id": "C001",
                    "disposition": "unsatisfied",
                    "evidence": "the behavior is missing",
                },
                {
                    "id": "C002",
                    "disposition": "satisfied",
                    "evidence": "the evidence is immutable",
                },
            ],
            "prior_findings": [],
        }
        normalized = review._normalize_review_document(
            json.loads(json.dumps(base)),
            review_id="r1",
            contract=contract,
            prior_findings=[],
        )
        self.assertEqual(normalized["verdict"], "REQUEST_CHANGES")
        duplicate = json.loads(json.dumps(base))
        duplicate["findings"].append(dict(finding))
        with self.assertRaises(Exception):
            review._normalize_review_document(
                duplicate,
                review_id="r1",
                contract=contract,
                prior_findings=[],
            )
        missing_criterion = json.loads(json.dumps(base))
        missing_criterion["criteria"] = missing_criterion["criteria"][:1]
        with self.assertRaises(Exception):
            review._normalize_review_document(
                missing_criterion,
                review_id="r1",
                contract=contract,
                prior_findings=[],
            )
        unverified_criterion = json.loads(json.dumps(base))
        unverified_criterion["criteria"][0]["disposition"] = "waived"
        with self.assertRaises(Exception):
            review._normalize_review_document(
                unverified_criterion,
                review_id="r1",
                contract=contract,
                prior_findings=[],
            )
        prior = [dict(finding, finding_id="F009")]
        missing_disposition = json.loads(json.dumps(base))
        with self.assertRaises(Exception):
            review._normalize_review_document(
                missing_disposition,
                review_id="r1",
                contract=contract,
                prior_findings=prior,
            )
        stale_review_id = json.loads(json.dumps(base))
        stale_review_id["review_id"] = "r2"
        with self.assertRaises(Exception):
            review._normalize_review_document(
                stale_review_id,
                review_id="r1",
                contract=contract,
                prior_findings=[],
            )

    def initial_complete_with_rejection(
        self, constraints: dict
    ) -> tuple[str, dict, dict]:
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        validation = self.run_validation()
        # Honest environment-dependent result: a capable host runs the real
        # positive validation; the capability-dropped native bootstrap records
        # a precise BLOCKED batch. Neither path forges a green result.
        self.assertIn(validation["classification"], {"passed", "blocked"}, validation)
        review_id = self.reject_current_source("F000")
        self.freeze_repair_contract(constraints, review_id, ["F000"])
        allocation = self.allocate_repair(review_id)
        self.assertEqual(allocation["generation"], 1)
        return review_id, allocation, validation

    def test_repair_admission_blocks_unknown_and_edited_residue(self) -> None:
        constraints = self.constraints()
        _review_id, allocation, _validation = self.initial_complete_with_rejection(
            constraints
        )
        # An entirely unknown allocation is refused before any setup fact.
        unknown = self.repair("ra" + "0" * 24, {}, expect=2)
        self.assertIn("Unknown repair allocation", unknown.stderr)
        # External residue that is not part of the exact rejected source.
        rogue = self.repo / "allowed" / "rogue.txt"
        rogue.write_text("unattributed external write\n", encoding="utf-8")
        try:
            blocked = self.repair(allocation["allocation_id"], {}, expect=2)
            self.assertIn("exact rejected source", blocked.stderr)
        finally:
            rogue.unlink()
        # User-edited bytes inside the owned path are equally unknown.
        impl = self.repo / "allowed" / "impl.txt"
        original = impl.read_bytes()
        impl.write_bytes(b"user edited this owned file\n")
        try:
            blocked = self.repair(allocation["allocation_id"], {}, expect=2)
            self.assertIn("exact rejected source", blocked.stderr)
        finally:
            impl.write_bytes(original)
        # Restoring the exact source keeps the same consumed slot usable for a
        # bounded pre-claim setup attempt; the negatives were not permanent.
        finalized = self.successful_repair(allocation["allocation_id"], b"repair ok\n")
        self.assertEqual(finalized["classification"], "drained_success", finalized)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["formal_repair_budget"]["used"], 1)

    def test_repair_admission_blocks_tampered_source_evidence(self) -> None:
        constraints = self.constraints()
        _review_id, allocation, _validation = self.initial_complete_with_rejection(
            constraints
        )
        journal = self.journal()
        result = journal["results"][-1]["payload"]
        blob_path = (
            runner.d_module()._blobs_dir("d2-plan") / result["evidence_blob_sha256"]
        )
        original = blob_path.read_bytes()
        blob_path.write_bytes(original + b" ")
        try:
            blocked = self.repair(allocation["allocation_id"], {}, expect=2)
            self.assertIn("evidence blob", blocked.stderr.lower())
            self.assertIn("corrupt", blocked.stderr.lower())
        finally:
            blob_path.write_bytes(original)
        # The restored immutable evidence admits the exact source again.
        finalized = self.successful_repair(allocation["allocation_id"], b"repair ok\n")
        self.assertEqual(finalized["classification"], "drained_success", finalized)

    def test_failed_claimed_repair_lineage_dispatches_and_budget(self) -> None:
        constraints = self.constraints()
        review0, allocation1, _validation = self.initial_complete_with_rejection(
            constraints
        )
        # Generation 1 is claimed and drains as a failure with owned residue.
        first = self.failed_claimed_repair(
            allocation1["allocation_id"], b"failed generation 1\n"
        )
        self.assertEqual(first["classification"], "drained_failure", first)
        validation1 = self.run_validation()
        self.assertIn(validation1["classification"], {"passed", "blocked"})
        review1 = self.reject_current_source("F001", prior=["F000"])
        self.freeze_repair_contract(constraints, review1, ["F000", "F001"])
        allocation2 = self.allocate_repair(review1)
        self.assertEqual(allocation2["generation"], 2)
        # This exact drained-failure parent must be able to hand ownership to
        # its approved allocated successor (the reviewed D2-R0-002 defect).
        second = self.failed_claimed_repair(
            allocation2["allocation_id"], b"failed generation 2\n"
        )
        self.assertEqual(second["classification"], "drained_failure", second)
        validation2 = self.run_validation()
        self.assertIn(validation2["classification"], {"passed", "blocked"})
        # A new review cannot drop the still-open F000 merely by carrying only
        # the newest parent finding.
        drop_id, drop_session = self.begin_review(
            "attempt to drop the still-open carried finding"
        )
        dropped = self.record_review(
            drop_id,
            drop_session,
            verdict="REQUEST_CHANGES",
            findings=[self.defect("F002")],
            dispositions=[
                {
                    "finding_id": "F001",
                    "disposition": "carried",
                    "evidence": "The finding remains open for the next repair.",
                }
            ],
            expect=2,
        )
        self.assertIn("F000", dropped.stderr)
        review2 = self.reject_current_source("F002", prior=["F000", "F001"])
        self.freeze_repair_contract(
            constraints, review2, ["F000", "F001", "F002"]
        )
        allocation3 = self.allocate_repair(review2)
        self.assertEqual(allocation3["generation"], 3)
        # Two accumulated failed ancestors: generation 3 still dispatches,
        # completes and receives a genuinely fresh validation batch.
        third = self.successful_repair(
            allocation3["allocation_id"], b"required marker\n"
        )
        self.assertEqual(third["classification"], "drained_success", third)
        validation3 = self.run_validation()
        self.assertIn(validation3["classification"], {"passed", "blocked"})
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["formal_repair_budget"]["used"], 3)
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["remaining"], 0
        )
        # A fresh rejection after the third consumed slot cannot allocate a
        # fourth formal generation, and no slot is refunded.
        review3 = self.reject_current_source(
            "F003", prior=["F000", "F001", "F002"]
        )
        refused = self.freeze_repair_contract(
            constraints,
            review3,
            ["F000", "F001", "F002", "F003"],
            expect=2,
        )
        self.assertIn("exhausted", refused.stderr)
        refused_allocation = self.allocate_repair(review3, expect=2)
        self.assertTrue(refused_allocation.stderr)
        self.assertEqual(
            self.checkpoint()["execution"]["formal_repair_budget"]["used"], 3
        )
        if validation3["classification"] == "passed":
            # Capable host: the successful repair reaches a fresh green batch
            # and actual Codex APPROVE, but D2 still never reaches done.
            approve_id, approve_session = self.begin_review(
                "approve the repaired implementation"
            )
            all_open = ["F000", "F001", "F002", "F003"]
            omitted = self.write_structured_review(
                approve_id,
                self.approval_document(approve_id, ["F000", "F001", "F002"]),
                approve_session,
                expect=2,
            )
            self.assertIn("F003", omitted.stderr)
            approval = self.write_structured_review(
                approve_id,
                self.approval_document(approve_id, all_open),
                approve_session,
            )
            self.assertEqual(approval["verdict"], "APPROVE")
            final = self.checkpoint()
            self.assertEqual(final["execution"]["stage"], "REVIEW_APPROVED")
            self.assertFalse(final["complete"])
        else:
            # Capability-dropped native bootstrap: approval must refuse to
            # invent a green batch and the derived stage must not approve.
            approve_id, approve_session = self.begin_review(
                "attempt approval without a real positive batch"
            )
            refused_approval = self.write_structured_review(
                approve_id,
                self.approval_document(
                    approve_id, ["F000", "F001", "F002", "F003"]
                ),
                approve_session,
                expect=2,
            )
            self.assertIn("validation to pass", refused_approval.stderr)
            self.assertNotEqual(
                self.checkpoint()["execution"]["stage"], "REVIEW_APPROVED"
            )

    def test_process_issuer_cmdline_digest_schema_and_audit(self) -> None:
        review = runner.review_module()
        identity = review._process_identity()
        self.assertEqual(identity["pid"], os.getpid())
        self.assertEqual(
            identity["cmdline_digest"], review._cmdline_digest(os.getpid())
        )
        self.assertEqual(
            review._validate_process(dict(identity), "issuer"), identity
        )
        review._require_process_cmdline(identity, "issuer")
        with self.assertRaises(Exception):
            review._validate_process(
                {"pid": identity["pid"], "start": identity["start"]}, "issuer"
            )
        with self.assertRaises(Exception):
            review._validate_process(
                dict(identity, cmdline_digest="not-a-digest"), "issuer"
            )
        mismatched = dict(identity, cmdline_digest="0" * 64)
        with self.assertRaises(Exception) as caught:
            review._require_process_cmdline(mismatched, "issuer")
        self.assertIn("recorded digest", str(caught.exception))
        # A drained issuer is unobservable; the recorded digest stays
        # provenance and no fabricated live match is asserted.
        review._require_process_cmdline(
            {
                "pid": 999_999_999,
                "start": "drained",
                "cmdline_digest": "0" * 64,
            },
            "issuer",
        )

    def test_review_findings_preserve_bounded_affected_lines(self) -> None:
        review = runner.review_module()
        contract = {
            "acceptance_criteria": [{"id": "C001", "text": "criterion one"}]
        }
        finding = {
            "finding_id": "F001",
            "kind": "defect",
            "severity": "high",
            "files": ["allowed/impl.txt"],
            "affected_lines": [
                {"path": "allowed/impl.txt", "start": 3, "end": 9}
            ],
            "summary": "The behavior is missing.",
            "evidence": "The file does not contain the marker.",
            "required_change": "Write the marker.",
            "test_recommendation": "Add a test.",
        }
        document = {
            "version": 1,
            "review_id": "r1",
            "verdict": "REQUEST_CHANGES",
            "leader": "codex-leader",
            "summary": "The active leader inspected the exact source and tests.",
            "findings": [finding],
            "criteria": [
                {
                    "id": "C001",
                    "disposition": "unsatisfied",
                    "evidence": "the behavior is missing",
                }
            ],
            "prior_findings": [],
        }
        normalized = review._normalize_review_document(
            json.loads(json.dumps(document)),
            review_id="r1",
            contract=contract,
            prior_findings=[],
        )
        self.assertEqual(
            normalized["findings"][0]["affected_lines"],
            [{"path": "allowed/impl.txt", "start": 3, "end": 9}],
        )
        self.assertIn(
            "allowed/impl.txt:3-9",
            review._render_finding(normalized["findings"][0]),
        )
        # Missing line data remains valid for older/coarse reviews, but
        # malformed or mismatched line data fails closed.
        missing = json.loads(json.dumps(document))
        missing["findings"][0].pop("affected_lines")
        normalized_missing = review._normalize_review_document(
            missing,
            review_id="r1",
            contract=contract,
            prior_findings=[],
        )
        self.assertEqual(normalized_missing["findings"][0]["affected_lines"], [])
        for invalid in (
            "not-a-list",
            [{"path": "allowed/impl.txt", "start": 9, "end": 3}],
            [{"path": "allowed/impl.txt", "start": 0, "end": 2}],
            [{"path": "allowed/other.txt", "start": 1, "end": 2}],
            [{"path": "/absolute", "start": 1, "end": 2}],
        ):
            broken = json.loads(json.dumps(document))
            broken["findings"][0]["affected_lines"] = invalid
            with self.assertRaises(Exception):
                review._normalize_review_document(
                    broken,
                    review_id="r1",
                    contract=contract,
                    prior_findings=[],
                )

    def test_structured_adapter_trust_and_invocation_boundaries(self) -> None:
        review = runner.review_module()
        trusted = self.runtime / "d_review.py"
        trusted_sha = hashlib.sha256(trusted.read_bytes()).hexdigest()

        def entry_for(adapter_path: Path, argv: list[str]) -> dict:
            return {
                "invocation_id": "V001",
                "label": "structured trust probe",
                "argv": argv,
                "cwd": ".",
                "context": "ordinary_ro",
                "purpose": "Probe the structured adapter trust boundary.",
                "mandatory": True,
                "expected_exit": 0,
                "timeout_seconds": 60,
                "capture_limit_bytes": 1_048_576,
                "environment_policy": "minimal_private",
                "ro_enforcement": "required",
                "evidence": {
                    "kind": "structured_unittest",
                    "adapter": {
                        "id": "coordinator-stdlib-unittest",
                        "version": 1,
                        "path": str(adapter_path),
                        "sha256": hashlib.sha256(
                            adapter_path.read_bytes()
                        ).hexdigest(),
                    },
                    "report_env": "D2_STRUCTURED_REPORT",
                    "min_collected": 1,
                    "min_run": 1,
                },
            }

        def valid_argv(adapter_path: Path) -> list[str]:
            return [
                sys.executable,
                "-I",
                "-B",
                str(adapter_path),
                "_unittest-adapter",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
            ]

        valid = entry_for(trusted, valid_argv(trusted))
        self.assertEqual(
            review._structured_adapter_problem(valid, trusted, self.repo), ""
        )
        # A foreign JSON emitter with a self-consistent ID/hash is not the
        # trusted coordinator adapter.
        foreign = self.root / "foreign-emitter.py"
        foreign.write_text("print('{}')\n", encoding="utf-8")
        fake = entry_for(foreign, valid_argv(foreign))
        self.assertIn(
            "trusted coordinator adapter",
            review._structured_adapter_problem(fake, foreign, self.repo),
        )
        # An exact trusted copy inside the candidate workspace is still
        # candidate-owned source.
        inside = self.repo / "allowed" / "copied-adapter.py"
        shutil.copyfile(trusted, inside)
        copied = entry_for(inside, valid_argv(inside))
        copied["evidence"]["adapter"]["sha256"] = trusted_sha
        self.assertIn(
            "candidate workspace",
            review._structured_adapter_problem(copied, inside, self.repo),
        )
        # The trusted path as an unused argument with a code-execution
        # interpreter invocation never counts.
        unused = entry_for(
            trusted,
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "print('foreign')",
                str(trusted),
                "_unittest-adapter",
                "discover",
            ],
        )
        unused["evidence"]["adapter"]["sha256"] = trusted_sha
        self.assertIn(
            "unsupported interpreter option",
            review._structured_adapter_problem(unused, trusted, self.repo),
        )
        # A different interpreter is refused even with the trusted bytes.
        wrong = entry_for(
            trusted,
            [
                "/bin/sh",
                "-c",
                "true",
                str(trusted),
                "_unittest-adapter",
                "discover",
            ],
        )
        wrong["evidence"]["adapter"]["sha256"] = trusted_sha
        self.assertIn(
            "trusted coordinator interpreter",
            review._structured_adapter_problem(wrong, trusted, self.repo),
        )
        # The adapter must be the literal executed script, not a foreign
        # script with the trusted path elsewhere in argv.
        shadow = entry_for(
            trusted,
            [
                sys.executable,
                "-I",
                "-B",
                str(foreign),
                str(trusted),
                "_unittest-adapter",
                "discover",
            ],
        )
        shadow["evidence"]["adapter"]["sha256"] = trusted_sha
        self.assertIn(
            "literal script",
            review._structured_adapter_problem(shadow, trusted, self.repo),
        )
        # A tampered sibling sanitizer next to an exact adapter copy fails.
        compromised = self.root / "compromised-runtime"
        compromised.mkdir()
        shutil.copyfile(trusted, compromised / "d_review.py")
        (compromised / "c_providers.py").write_text(
            "raise SystemExit('tampered')\n", encoding="utf-8"
        )
        sibling = entry_for(
            compromised / "d_review.py",
            valid_argv(compromised / "d_review.py"),
        )
        self.assertIn(
            "support file",
            review._structured_adapter_problem(
                sibling, compromised / "d_review.py", self.repo
            ),
        )

    def test_foreign_and_unused_structured_adapters_block_validation(self) -> None:
        trusted = self.runtime / "d_review.py"
        trusted_sha = hashlib.sha256(trusted.read_bytes()).hexdigest()
        emitter = self.root / "foreign-emitter.py"
        report_counts = {
            "collected": 1,
            "run": 1,
            "passed": 1,
            "failures": 0,
            "errors": 0,
            "skips": 0,
        }
        emitter.write_text(
            "import json, os, sys\n"
            "path = os.environ.get('D2_STRUCTURED_REPORT')\n"
            "if path:\n"
            "    with open(path, 'w') as handle:\n"
            f"        json.dump({{'counts': {json.dumps(report_counts)}}}, handle)\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )

        def structured(
            invocation_id: str,
            adapter_path: Path,
            declared_sha: str,
            argv: list[str],
        ) -> dict:
            return {
                "invocation_id": invocation_id,
                "label": f"structured {invocation_id}",
                "argv": argv,
                "cwd": ".",
                "context": "ordinary_ro",
                "purpose": "Exercise a structured adapter trust boundary.",
                "mandatory": True,
                "expected_exit": 0,
                "timeout_seconds": 60,
                "capture_limit_bytes": 1_048_576,
                "environment_policy": "minimal_private",
                "ro_enforcement": "required",
                "evidence": {
                    "kind": "structured_unittest",
                    "adapter": {
                        "id": "coordinator-stdlib-unittest",
                        "version": 1,
                        "path": str(adapter_path),
                        "sha256": declared_sha,
                    },
                    "report_env": "D2_STRUCTURED_REPORT",
                    "min_collected": 1,
                    "min_run": 1,
                },
            }

        foreign = structured(
            "V001",
            emitter,
            hashlib.sha256(emitter.read_bytes()).hexdigest(),
            [
                sys.executable,
                "-I",
                "-B",
                str(emitter),
                "_unittest-adapter",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
            ],
        )
        unused = structured(
            "V002",
            trusted,
            trusted_sha,
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "print('foreign')",
                str(trusted),
                "_unittest-adapter",
                "discover",
            ],
        )
        entries = [foreign, unused]
        constraints = {
            "version": 2,
            "allowed_paths": ["allowed/**"],
            "denied_paths": [".env"],
            "criteria": [
                {
                    "id": f"C{index:03d}",
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                }
                for index, text in enumerate(CRITERIA, start=1)
            ],
            "required_validation": [
                {"argv": list(entry["argv"]), "label": entry["label"]}
                for entry in entries
            ],
            "max_changed_files": 8,
            "validation_policy": {"version": 1, "entries": entries},
        }
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        validation = self.run_validation()
        self.assertEqual(validation["classification"], "blocked", validation)
        reasons = " ".join(validation["reasons"]).lower()
        self.assertIn("trusted coordinator adapter", reasons)
        self.assertIn("unsupported interpreter option", reasons)
        self.assertEqual(validation["counts"]["run"], 0)
        self.assertFalse(
            any(entry.get("passed") for entry in validation.get("entries") or [])
        )

    @REAL_BWRAP
    def test_systems_preflight_and_real_context_mount_layout(self) -> None:
        self.assertTrue(
            str(Path(self.repo).resolve()).startswith("/tmp/"),
            "the physical regression must exercise a workspace under /tmp",
        )
        adapter, secret = self.install_pinned_adapter()
        host_marker = self.root / "host-tmp-marker"
        host_marker.write_text("host only\n", encoding="utf-8")
        constraints = self.mixed_validation_constraints(adapter, host_marker, secret)
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        # A systems_trusted invocation is invalid until the active leader
        # records its exact current preflight; there is no fallback.
        denied = self.run_cli(
            "execution-validate",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--timeout-seconds",
            "120",
            "--config",
            str(self.config),
            "--json",
            env=self.validation_env(),
            expected=2,
        )
        self.assertIn("preflight", (denied.stderr + denied.stdout).lower())
        self.json_cli(
            "execution-preflight",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--invocation-id",
            "V002",
            "--leader",
            "codex-leader",
            "--json",
        )
        validation = self.run_validation()
        self.assertEqual(validation["classification"], "passed", validation)
        self.assertEqual(validation["counts"]["run"], 2, validation)
        journal = self.journal()
        validation_job = journal["validation_intents"][-1]["payload"]["job_id"]
        evidence = json.loads(
            (
                self.state
                / "jobs"
                / validation_job
                / "validation-evidence.json"
            ).read_text()
        )
        observed = {
            item["invocation_id"]: item["observation"]
            for item in evidence["enforcement"]["observed_contexts"]
        }
        self.assertEqual(observed["V001"]["cap_eff"], "0" * 16)
        self.assertIn("parent_cap_eff", observed["V002"])
        # Adapter exposure is context-specific: only the structured invocations
        # that declare the pinned adapter receive the exact literal RO rebind.
        entries_by_id = {
            item["invocation_id"]: item for item in evidence["entries"]
        }
        expected_adapter_ro = [
            str(adapter),
            str(adapter.with_name("c_providers.py")),
        ]
        for invocation_id in ("V001", "V002"):
            self.assertEqual(
                entries_by_id[invocation_id]["sandbox"]["literal_adapter_ro"],
                expected_adapter_ro,
                invocation_id,
            )
        self.assertEqual(
            entries_by_id["V003"]["sandbox"]["literal_adapter_ro"], []
        )
        # The plain command_check declares no adapter grant, so the actual
        # namespace really hides it while proving EROFS, masks and scratch.
        v003_stdout = Path(
            entries_by_id["V003"]["stdout"]["path"]
        ).read_text(encoding="utf-8")
        v003_checks = json.loads(v003_stdout.strip().splitlines()[-1])
        self.assertFalse(v003_checks["adapter_readable"], v003_checks)
        self.assertTrue(v003_checks["adapter_hidden"], v003_checks)
        self.assertTrue(v003_checks["secret_hidden"], v003_checks)
        self.assertEqual(v003_checks["source_errno"], "EROFS", v003_checks)
        # The pinned adapter and its exact support file ran from the masked
        # coordinator state; the sibling secret never appeared in the sandbox.
        scratch = self.state / "jobs" / validation_job / "validation-scratch"
        for name in ("home", "tmp", "cache"):
            marker = scratch / name / "command-check-marker"
            self.assertTrue(marker.is_file(), marker)
            self.assertEqual(marker.read_text(encoding="utf-8"), name)
        files = [
            path.name
            for path in (scratch / "report").iterdir()
            if path.is_file()
        ]
        self.assertEqual(len(files), 2, files)
        self.assertTrue(
            all(path.endswith(".json") for path in files), files
        )

    def test_validation_evidence_tamper_blocks_finalize(self) -> None:
        constraints = self.constraints()
        self.create_plan()
        digest, _candidate = self.complete_consensus(
            self.candidate(constraints=constraints)
        )
        self.freeze_contract(self.contract_document(digest, constraints))
        launched = self.implement(
            self.implementation_task(),
            self.write_writes(
                [("allowed/impl.txt", b"initial implementation\n")],
                [],
                ["allowed/impl.txt"],
            ),
        )
        job_id = launched["job_id"]
        self.assertEqual(self.wait(job_id).get("state"), "succeeded")
        self.assertTrue(self.finalize_job(job_id)["completed"])
        validation_job = self.json_cli(
            "execution-validate",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--timeout-seconds",
            "120",
            "--config",
            str(self.config),
            "--json",
        )["job_id"]
        self.assertEqual(self.wait(validation_job).get("state"), "succeeded")
        evidence = self.state / "jobs" / validation_job / "validation-evidence.json"
        evidence.write_text(evidence.read_text() + " ", encoding="utf-8")
        refused = self.run_cli(
            "execution-validation-finalize",
            "--plan-id",
            "d2-plan",
            "--step-id",
            "step-one",
            "--job-id",
            validation_job,
            "--json",
            expected=2,
        )
        self.assertIn(
            "does not match the digest bound by the B2 completion receipt",
            refused.stderr,
        )


if __name__ == "__main__":
    unittest.main()
