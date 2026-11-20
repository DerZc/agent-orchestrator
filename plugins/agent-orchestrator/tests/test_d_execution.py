from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
RUNNER = SCRIPTS / "cli_agent_job.py"

RUNNER_SPEC = importlib.util.spec_from_file_location(
    "agent_orchestrator_runner_d1", RUNNER
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
marker = os.environ.get("C_FAKE_START_MARKER")
if marker:
    with open(marker, "a", encoding="utf-8") as handle:
        handle.write("provider-start\n")
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
        "operation": "implementation",
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
if os.environ.get("C_FAKE_EXIT"):
    raise SystemExit(int(os.environ["C_FAKE_EXIT"]))
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

CRITERIA = ["Focused D1 tests pass", "Immutable evidence is retained"]


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
        "feasibility": "Feasible with the existing B1/B2/C modules.",
        "testing": ["Run the focused D1 test suite."],
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


class D1ExecutionTests(unittest.TestCase):
    """D1 pipeline coverage with a non-isolating bwrap transport shim.

    Every provenance, mapping, consensus and implementation case runs actual
    mock CLI provider processes through the real runner/C/B2 pipeline. The shim
    provides no confinement and these tests make no confinement claim; real
    namespace cases remain host-authoritative and run separately.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self._previous_home = os.environ.get("AGENT_ORCHESTRATOR_HOME")
        os.environ["AGENT_ORCHESTRATOR_HOME"] = str(self.state)
        self.addCleanup(self._restore_home)
        self.repo = self.make_repo(self.root / "repo")
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
            "# Goal\nShip the strict managed execution feature.\n\n"
            "# Decisions and assumptions\nFollow the frozen candidate.\n\n"
            "# Constraints and guardrails\nDo not publish or change credentials.\n\n"
            "# Checklist\n- [ ] Implement the strict managed execution feature.\n\n"
            "# Validation strategy\nRun the focused D1 tests.\n\n"
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

    def require_real_bwrap(self) -> None:
        """Skip cases that require genuine kernel confinement.

        Cycle2 strict writers with a non-empty original protected-user set must
        prove that C's declared mounts were actually applied inside the
        sandbox.  The transport shim used by the rest of this file cannot do
        that honestly, so these cases run only where the host bubblewrap probe
        really creates namespaces.  The fake shim is removed so the actual
        system bubblewrap is used.
        """
        available, reason = runner.c_module().isolation_status()
        if not available:
            self.skipTest(
                "real bubblewrap namespaces are unavailable on this host; "
                "the non-confining transport shim cannot substitute for "
                "kernel confinement: " + str(reason)
            )
        fake = self.bin / "bwrap"
        if fake.exists():
            fake.unlink()
        available, reason = runner.c_module().isolation_status()
        if not available:
            self.skipTest(
                "real bubblewrap isolation is unavailable after removing the "
                "transport shim: " + str(reason)
            )

    def clean_env(self) -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ANTHROPIC")
            and key not in {"CLAUDE_CODE_AUTO_COMPACT_WINDOW"}
            and not key.startswith("C_FAKE_")
        }
        return env

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
        self.git(path, "add", "tracked.txt", "allowed/old.txt")
        self.git(path, "commit", "-qm", "baseline")
        self.git(path, "checkout", "-qb", "feature/d1-tests")
        return path

    def write_provider_tools(self, bin_dir: Path) -> None:
        bin_dir.mkdir(parents=True)
        claude = bin_dir / "claude"
        claude.write_text(FAKE_PROVIDER.format(python=sys.executable))
        claude.chmod(0o755)
        bwrap = bin_dir / "bwrap"
        bwrap.write_text(FAKE_BWRAP.format(python=sys.executable))
        bwrap.chmod(0o755)

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
                    "objective": "Implement the strict managed execution feature.",
                    "scope": ["allowed"],
                    "deliverables": ["execution journal"],
                    "acceptance_criteria": selected,
                    "depends_on": [],
                    "brief": {
                        "original_objective": (
                            "Implement the strict managed execution feature safely."
                        ),
                        "repository_context": (
                            "The existing agent orchestrator workspace."
                        ),
                        "constraints": ["No provider quota use in tests"],
                        "proposed_approach": (
                            "Reuse the B1 plan lock and the B2 writer lease."
                        ),
                        "expected_changes": [
                            "execution journal",
                            "CLI commands",
                        ],
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

    def json_cli(self, *args: str, env: dict[str, str] | None = None) -> dict:
        result = self.run_cli(*args, env=env)
        return json.loads(result.stdout)

    def create_plan(
        self,
        plan_id: str = "d1-plan",
        *,
        strict: bool = True,
        workspace: Path | None = None,
        manifest_path: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> dict:
        args = [
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(workspace or self.repo),
            "--title",
            "D1 managed plan",
            "--plan-id",
            plan_id,
            "--research-team",
            "--manifest-file",
            str(manifest_path or self.manifest_path),
            "--executor",
            "fake",
            "--json",
        ]
        if strict:
            args.append("--strict-execution")
        return self.json_cli(*args, env=env)

    def checkpoint(
        self, plan_id: str = "d1-plan", env: dict[str, str] | None = None
    ) -> dict:
        return self.json_cli("plan-checkpoint", plan_id, "--json", env=env)

    # ------------------------------------------------------------------
    # Discussion jobs and submissions
    # ------------------------------------------------------------------

    def launch_discussion(
        self,
        role: str,
        round_number: int,
        operation: str,
        payload: dict,
        *,
        plan_id: str = "d1-plan",
        step_id: str = "step-one",
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
            step_id,
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

    def wait(
        self,
        job_id: str,
        *,
        env: dict[str, str] | None = None,
        timeout: float = 90,
    ) -> dict:
        result = self.run_cli(
            "wait",
            job_id,
            "--timeout-seconds",
            str(timeout),
            "--poll-seconds",
            "0.2",
            "--json",
            env=env,
            timeout=timeout + 30,
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
        *,
        plan_id: str = "d1-plan",
        step_id: str = "step-one",
        expect: int = 0,
        extra: tuple[str, ...] = (),
    ) -> dict | subprocess.CompletedProcess[str]:
        submission = self.normalize(operation, payload)
        path = self.root / f"submission-{role}-{round_number}-{time.time_ns()}.json"
        path.write_text(json.dumps(submission), encoding="utf-8")
        args = [
            "consensus-submit",
            "--plan-id",
            plan_id,
            "--step-id",
            step_id,
            "--role",
            role,
            "--round",
            str(round_number),
            "--submission-file",
            str(path),
            "--json",
            *extra,
        ]
        if role == "codex":
            args.extend(["--leader", "codex-leader"])
        elif job_id is not None:
            args.extend(["--source-job", job_id])
        result = self.run_cli(*args, expected=expect)
        return json.loads(result.stdout) if expect == 0 else result

    def vote(
        self,
        role: str,
        digest: str,
        *,
        job_id: str | None,
        vote: str = "AGREE",
        rationale: str = "The frozen candidate is acceptable.",
        plan_id: str = "d1-plan",
        step_id: str = "step-one",
        expect: int = 0,
        extra: tuple[str, ...] = (),
        source: bool = True,
    ) -> dict | subprocess.CompletedProcess[str]:
        args = [
            "consensus-vote",
            "--plan-id",
            plan_id,
            "--step-id",
            step_id,
            "--role",
            role,
            "--digest",
            digest,
            "--vote",
            vote,
            "--rationale",
            rationale,
            "--json",
            *extra,
        ]
        if role == "codex":
            args.extend(["--leader", "codex-leader"])
        elif job_id is not None:
            args.extend(
                ["--source-job", job_id] if source else ["--job-id", job_id]
            )
        result = self.run_cli(*args, expected=expect)
        return json.loads(result.stdout) if expect == 0 else result

    def constraints(self, *, allowed: list[str] | None = None) -> dict:
        return {
            "version": 1,
            "allowed_paths": allowed or ["allowed/**"],
            "denied_paths": [".env"],
            "criteria": [
                {
                    "id": f"C{index:03d}",
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                }
                for index, text in enumerate(CRITERIA, start=1)
            ],
            "required_validation": [
                {"argv": ["python3", "-m", "unittest", "discover"]}
            ],
            "max_changed_files": 8,
        }

    def candidate(
        self,
        objection_ids: tuple[str, ...] = ("O001", "O002", "O003"),
        *,
        constraints: dict | None = None,
        final_design: str | None = None,
    ) -> dict:
        return {
            "final_design": final_design
            or (
                "Use one immutable execution journal with protected evidence for "
                "every managed step."
            ),
            "important_decisions": [
                "B1 remains the only discussion authority.",
                "D1 stops at IMPLEMENTATION_COMPLETE.",
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
                for objection_id in objection_ids
            ],
            "remaining_risks": ["crash windows are tested explicitly"],
            "execution_constraints": constraints or self.constraints(),
        }

    def freeze_candidate(
        self, candidate: dict, *, plan_id: str = "d1-plan"
    ) -> str:
        path = self.root / f"candidate-{time.time_ns()}.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        result = self.json_cli(
            "consensus-freeze",
            "--plan-id",
            plan_id,
            "--step-id",
            "step-one",
            "--candidate-file",
            str(path),
            "--json",
        )
        return str(result["frozen_digest"])

    def complete_consensus(
        self,
        *,
        plan_id: str = "d1-plan",
        candidate: dict | None = None,
        before_ballots=None,
    ) -> tuple[str, dict]:
        selections = {
            "deepseek": (
                proposal_payload(),
                cross_payload(
                    "Recovery must never infer a no-start from wall time."
                ),
            ),
            "glm": (
                proposal_payload(),
                cross_payload(
                    "Immutable evidence must survive provider job cleanup."
                ),
            ),
            "codex": (
                proposal_payload(),
                cross_payload(
                    "Strict source evidence must bind the frozen candidate."
                ),
            ),
        }
        for role in ("deepseek", "glm", "codex"):
            payload = selections[role][0]
            job = (
                self.launch_discussion(role, 1, "proposal", payload)
                if role != "codex"
                else None
            )
            self.submit(role, 1, "proposal", payload, job, plan_id=plan_id)
        for role in ("deepseek", "glm", "codex"):
            payload = selections[role][1]
            job = (
                self.launch_discussion(role, 2, "cross_examination", payload)
                if role != "codex"
                else None
            )
            self.submit(
                role, 2, "cross_examination", payload, job, plan_id=plan_id
            )
        document = candidate or self.candidate()
        digest = self.freeze_candidate(document, plan_id=plan_id)
        if before_ballots is not None:
            before_ballots(digest)
        for role in ("deepseek", "glm", "codex"):
            payload = consensus_payload(digest)
            job = (
                self.launch_discussion(
                    role,
                    3,
                    "consensus",
                    payload,
                    plan_id=plan_id,
                    extra_env={"C_FAKE_CANDIDATE": digest},
                )
                if role != "codex"
                else None
            )
            self.vote(
                role,
                digest,
                job_id=job,
                rationale=payload["rationale"],
                plan_id=plan_id,
            )
        checkpoint = self.checkpoint(plan_id)
        self.assertEqual(checkpoint["consensus_state"], "CONSENSUS_REACHED")
        return digest, document

    def contract_document(
        self,
        digest: str,
        *,
        constraints: dict | None = None,
        overrides: dict | None = None,
    ) -> dict:
        selected = constraints or self.constraints()
        state = runner.b1_module().replay_plan_state_unlocked("d1-plan")
        document = {
            "version": 1,
            "plan_id": "d1-plan",
            "step_id": "step-one",
            "cycle": state["steps"]["step-one"]["cycle"],
            "candidate_sha256": digest,
            "plan_sha256": state["static"]["plan_sha256"],
            "manifest_digest": state["static"]["manifest_digest"],
            "objective": "Implement the approved strict execution feature end to end.",
            "why": "Consensus requires one managed writer with immutable proof.",
            "relevant_modules": ["plugins/agent-orchestrator/scripts"],
            "allowed_paths": list(selected["allowed_paths"]),
            "denied_paths": list(selected["denied_paths"]),
            "required_behavior": [
                "Journal every execution fact",
                "Reject unauthorized writers before startup",
            ],
            "required_interfaces": [
                "execution-implement",
                "execution-finalize",
            ],
            "tests": ["Run the focused D1 tests"],
            "acceptance_criteria": [
                {
                    "id": item["id"],
                    "text": CRITERIA[index],
                }
                for index, item in enumerate(selected["criteria"])
            ],
            "required_validation": [
                {"argv": list(item["argv"])}
                for item in selected["required_validation"]
            ],
            "max_changed_files": selected.get("max_changed_files"),
            "target_branch": "feature/d1-tests",
            "protected_branches": ["main"],
            "reporting": ["Return the complete changed path list"],
        }
        if overrides:
            document.update(overrides)
        return document

    def freeze_contract(
        self,
        document: dict,
        *,
        plan_id: str = "d1-plan",
        expect: int = 0,
    ) -> dict | subprocess.CompletedProcess[str]:
        path = self.root / f"contract-{time.time_ns()}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        result = self.run_cli(
            "execution-contract",
            "--plan-id",
            plan_id,
            "--step-id",
            "step-one",
            "--contract-file",
            str(path),
            "--json",
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def implementation_task(self, text: str = "Implement the frozen contract.\n") -> Path:
        path = self.root / f"impl-{time.time_ns()}.md"
        path.write_text(text, encoding="utf-8")
        return path

    def implement(
        self,
        task: Path,
        *,
        env_overrides: dict[str, str] | None = None,
        plan_id: str = "d1-plan",
        expect: int = 0,
        timeout_seconds: int = 60,
    ) -> dict | subprocess.CompletedProcess[str]:
        local = dict(self.env)
        if env_overrides:
            local.update(env_overrides)
        result = self.run_cli(
            "execution-implement",
            "--plan-id",
            plan_id,
            "--step-id",
            "step-one",
            "--task-file",
            str(task),
            "--timeout-seconds",
            str(timeout_seconds),
            "--config",
            str(self.config),
            "--json",
            expected=expect,
            env=local,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def finalize(
        self,
        job_id: str,
        *,
        plan_id: str = "d1-plan",
        expect: int = 0,
    ) -> dict | subprocess.CompletedProcess[str]:
        result = self.run_cli(
            "execution-finalize",
            "--plan-id",
            plan_id,
            "--step-id",
            "step-one",
            "--job-id",
            job_id,
            "--json",
            expected=expect,
        )
        return json.loads(result.stdout) if expect == 0 else result

    def implementation_writes(
        self,
        writes: list[tuple[str, bytes]],
        deletes: list[str],
        changed: list[str],
        extra_env: dict[str, str] | None = None,
    ) -> dict[str, str]:
        local = {
            "C_FAKE_IMPLEMENT": "1",
            "C_FAKE_WRITES": json.dumps(
                [
                    [path, base64.b64encode(content).decode("ascii")]
                    for path, content in writes
                ]
            ),
            "C_FAKE_DELETES": json.dumps(deletes),
            "C_FAKE_CHANGED": json.dumps(changed),
        }
        if extra_env:
            local.update(extra_env)
        return local

    def implementation_jobs(self) -> list[str]:
        root = self.state / "jobs"
        if not root.is_dir():
            return []
        found: list[str] = []
        for path in sorted(root.iterdir()):
            meta_path = path / "meta.json"
            if not meta_path.is_file():
                continue
            meta = json.loads(meta_path.read_text())
            if (
                isinstance(meta.get("managed_execution"), dict)
                and meta["managed_execution"].get("kind") == "implementation"
            ):
                found.append(path.name)
        return found

    def journal(self, plan_id: str = "d1-plan") -> dict:
        return runner.d_module()._replay_journal(plan_id)

    def evidence_blob(self, plan_id: str, result_payload: dict) -> dict:
        return runner.d_module()._load_evidence_blob(
            plan_id,
            result_payload["evidence_blob_sha256"],
            result_payload["evidence_digest"],
            "test attempt evidence",
        )

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_full_strict_flow_evidence_and_closed_gates(self) -> None:
        self.create_plan()

        def ballot_forgeries(digest: str) -> None:
            job = self.launch_discussion(
                "deepseek",
                3,
                "consensus",
                consensus_payload(digest),
                extra_env={"C_FAKE_CANDIDATE": digest},
            )
            stale = self.vote(
                "deepseek",
                "b" * 64,
                job_id=job,
                rationale=consensus_payload(digest)["rationale"],
                expect=2,
            )
            self.assertIn("stale", stale.stderr)
            substituted = self.vote(
                "deepseek",
                digest,
                job_id=job,
                rationale="A rationale the provider never emitted.",
                expect=2,
            )
            self.assertIn("deterministic mapping", substituted.stderr)
            wrong_role = self.vote(
                "glm",
                digest,
                job_id=job,
                rationale=consensus_payload(digest)["rationale"],
                expect=2,
            )
            self.assertIn("role", wrong_role.stderr)

        digest, candidate = self.complete_consensus(
            before_ballots=ballot_forgeries
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "AWAITING_CONTRACT")
        self.assertTrue(checkpoint["strict_execution"])
        self.assertFalse(checkpoint["complete"])

        contract = self.contract_document(digest)
        frozen = self.freeze_contract(contract)
        self.assertEqual(frozen["cycle"], 1)
        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["execution"]["stage"], "READY_TO_IMPLEMENT"
        )

        task = self.implementation_task()
        local = self.implementation_writes(
            [
                ("allowed/new.txt", b"new content\n"),
                ("allowed/binary.bin", b"\x00\x01binary\x00payload"),
            ],
            ["allowed/old.txt"],
            ["allowed/new.txt", "allowed/binary.bin", "allowed/old.txt"],
        )
        launched = self.implement(task, env_overrides=local)
        job_id = launched["job_id"]
        status = self.wait(job_id, env={**self.env, **local})
        self.assertEqual(status.get("state"), "succeeded", status)
        finalized = self.finalize(job_id)
        self.assertTrue(finalized["completed"], finalized)
        self.assertEqual(finalized["state"], "IMPLEMENTATION_COMPLETE")
        repeated_finalize = self.finalize(job_id)
        self.assertTrue(repeated_finalize["idempotent"])
        self.assertEqual(
            repeated_finalize["changed_paths"],
            finalized["changed_paths"],
        )
        self.assertEqual(
            sorted(finalized["changed_paths"]),
            ["allowed/binary.bin", "allowed/new.txt", "allowed/old.txt"],
        )
        self.assertEqual((self.repo / "allowed/new.txt").read_text(), "new content\n")
        self.assertFalse((self.repo / "allowed/old.txt").exists())

        journal = self.journal()
        self.assertEqual(len(journal["completions"]), 1)
        result_payload = journal["results"][0]["payload"]
        evidence = self.evidence_blob("d1-plan", result_payload)
        delta = evidence["delta"]
        self.assertEqual(sorted(delta["new_paths"]), ["allowed/binary.bin", "allowed/new.txt"])
        self.assertEqual(delta["deleted_paths"], ["allowed/old.txt"])
        self.assertEqual(delta["binary_paths"], ["allowed/binary.bin"])
        self.assertTrue(delta["diff_blob_sha256"])
        diff_bytes = runner.d_module()._read_blob(
            "d1-plan", delta["diff_blob_sha256"], "test diff"
        )
        self.assertIn(b"allowed/new.txt", diff_bytes)
        self.assertIn(b"new content", diff_bytes)
        self.assertIn(b"allowed/binary.bin", diff_bytes)
        self.assertIn(b"allowed/old.txt", diff_bytes)
        self.assertEqual(evidence["classification"], "drained_success")
        self.assertIn("contract", evidence)
        self.assertIn("intent", evidence)
        self.assertIn("claim", evidence)
        self.assertTrue(evidence["proofs"].get("lease-completion.json"))

        # Simulate a crash after the result event but before the completion
        # event: the remaining journal prefix is valid, and a finalize retry
        # must append the exact missing completion without a new invocation.
        completion_event = journal["completions"][0]
        completion_file = (
            self.state
            / "plans"
            / "d1-plan"
            / "execution"
            / "events"
            / f"{completion_event['sequence']:06d}.json"
        )
        completion_file.unlink()
        recovered = self.finalize(job_id)
        self.assertTrue(recovered["completed"], recovered)
        journal = self.journal()
        self.assertEqual(len(journal["completions"]), 1)
        self.assertEqual(journal["completions"][0]["payload"]["job_id"], job_id)
        self.assertEqual(len(journal["results"]), 1)

        plan = self.json_cli("plan-status", "d1-plan", "--json")
        self.assertFalse(plan["complete"])
        self.assertEqual(
            plan["execution"]["stage"], "IMPLEMENTATION_COMPLETE"
        )
        self.assertIn("D2", plan["execution"]["next_action"])
        item = plan["items"][0]
        self.assertEqual(item["execution_stage"], "IMPLEMENTATION_COMPLETE")
        self.assertNotEqual(item.get("state"), "done")
        checkpoint = self.checkpoint()
        attempt = checkpoint["execution"]["attempt"]
        self.assertEqual(attempt["classification"], "drained_success")
        self.assertEqual(attempt["invocations"], 1)
        self.assertEqual(
            attempt["evidence_digest"], result_payload["evidence_digest"]
        )
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["remaining"], 3
        )
        self.assertEqual(
            checkpoint["execution"]["formal_repair_budget"]["used"], 0
        )

        # Later source drift invalidates eligibility and is visible, without
        # rewriting the historical completion or marking the item done.
        drift_file = self.repo / "drift-after-complete.txt"
        drift_file.write_text("later user drift\n")
        drift = self.checkpoint()
        self.assertEqual(
            drift["execution"]["stage"], "IMPLEMENTATION_COMPLETE"
        )
        self.assertTrue(drift["execution"]["source_drift"])
        self.assertIn("drift", drift["execution"]["next_action"])
        self.assertTrue(drift["steps"][0]["execution_source_drift"])
        drift_file.unlink()
        restored = self.checkpoint()
        self.assertFalse(restored["execution"]["source_drift"])
        self.assertNotIn("drift", restored["execution"]["next_action"])

        rows = json.loads(
            self.run_cli("dashboard", "--json").stdout
        )
        row = next(item for item in rows if item["job_id"] == job_id)
        self.assertEqual(row["managed_execution"]["kind"], "implementation")
        self.assertEqual(
            row["plan_execution"]["stage"], "IMPLEMENTATION_COMPLETE"
        )

        refused = self.run_cli(
            "record-review",
            job_id,
            "--verdict",
            "accepted",
            "--reviewer",
            "codex",
            "--test",
            "mock validation",
            expected=2,
        )
        self.assertIn("closed in D1", refused.stderr)
        self.assertFalse((self.state / "jobs" / job_id / "review.json").exists())

        # Missing or corrupt immutable evidence fails the derived view closed.
        evidence_blob = (
            self.state
            / "plans"
            / "d1-plan"
            / "execution"
            / "blobs"
            / result_payload["evidence_blob_sha256"]
        )
        original_blob = evidence_blob.read_bytes()
        evidence_blob.write_bytes(b"tampered")
        corrupt_blob = self.run_cli(
            "plan-checkpoint", "d1-plan", "--json", expected=2
        )
        self.assertIn("corrupt execution evidence blob", corrupt_blob.stderr)
        evidence_blob.write_bytes(original_blob)
        proof_sha = evidence["proofs"]["meta.json"]["blob_sha256"]
        proof_blob = (
            self.state / "plans" / "d1-plan" / "execution" / "blobs" / proof_sha
        )
        original_proof = proof_blob.read_bytes()
        proof_blob.write_bytes(b"tampered proof")
        corrupt_proof = self.run_cli(
            "plan-checkpoint", "d1-plan", "--json", expected=2
        )
        self.assertIn(
            "corrupt execution evidence blob", corrupt_proof.stderr
        )
        proof_blob.write_bytes(original_proof)
        contract_sha = journal["contracts"][0]["payload"][
            "contract_blob_sha256"
        ]
        contract_blob = (
            self.state
            / "plans"
            / "d1-plan"
            / "execution"
            / "blobs"
            / contract_sha
        )
        original_contract = contract_blob.read_bytes()
        contract_blob.write_bytes(b"tampered contract")
        corrupt_contract = self.run_cli(
            "plan-checkpoint", "d1-plan", "--json", expected=2
        )
        self.assertIn(
            "corrupt execution evidence blob", corrupt_contract.stderr
        )
        contract_blob.write_bytes(original_contract)
        protection_sha = journal["intents"][0]["payload"][
            "protection_manifest_blob_sha256"
        ]
        protection_blob = (
            self.state
            / "plans"
            / "d1-plan"
            / "execution"
            / "blobs"
            / protection_sha
        )
        original_protection = protection_blob.read_bytes()
        tampered_manifest = json.loads(original_protection)
        tampered_manifest["roots"] = []
        protection_blob.write_text(json.dumps(tampered_manifest, sort_keys=True))
        corrupt_protection = self.run_cli(
            "plan-checkpoint", "d1-plan", "--json", expected=2
        )
        self.assertIn(
            "protection manifest", corrupt_protection.stderr
        )
        protection_blob.write_bytes(original_protection)

        # A coordinated reopen is allowed only while quiescent and makes the
        # old binding immediately ineligible; old history is retained.
        reopened = self.json_cli(
            "consensus-new-cycle",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "codex",
            "--authorization",
            "Coordinator requests a fresh consensus after success.",
            "--authorization-kind",
            "coordinator",
            "--json",
        )
        self.assertEqual(reopened["stage"], "PROPOSALS_OPEN")
        stale = self.finalize(job_id, expect=2)
        self.assertIn("CONSENSUS_REACHED", stale.stderr)
        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["execution"]["stage"], "DISCUSSION_PENDING"
        )
        self.assertEqual(len(self.journal()["completions"]), 1)

        # Corrupt journal evidence fails the derived views closed.
        events = sorted(
            (self.state / "plans" / "d1-plan" / "execution" / "events").glob(
                "*.json"
            )
        )
        original = events[0].read_bytes()
        tampered = json.loads(original)
        tampered["at"] = "tampered"
        events[0].write_text(json.dumps(tampered))
        corrupt = self.run_cli(
            "plan-checkpoint", "d1-plan", "--json", expected=2
        )
        self.assertIn("digest does not match", corrupt.stderr)
        events[0].write_bytes(original)

    def test_strict_source_gates_and_worker_revalidation(self) -> None:
        self.create_plan()
        job_id = self.launch_discussion(
            "deepseek", 1, "proposal", proposal_payload()
        )
        meta = json.loads(
            (self.state / "jobs" / job_id / "meta.json").read_text()
        )
        d = runner.d_module()
        self.assertIsNone(d.validate_managed_worker(meta))

        tampered = json.loads(json.dumps(meta))
        tampered["managed_execution"]["assignment_digest"] = "a" * 64
        self.assertIn("assignment", d.validate_managed_worker(tampered) or "")

        tampered = json.loads(json.dumps(meta))
        tampered["managed_execution"]["role"] = "codex"
        self.assertTrue(d.validate_managed_worker(tampered))

        (self.repo / "untracked.txt").write_text("changed\n")
        changed = d.validate_managed_worker(meta)
        self.assertIn("source changed", changed or "")
        (self.repo / "untracked.txt").unlink()

        # Missing, nonexistent or role-mismatched source evidence is rejected.
        missing = self.submit(
            "deepseek",
            1,
            "proposal",
            proposal_payload(),
            None,
            expect=2,
        )
        self.assertIn("--source-job", missing.stderr)
        forged = self.submit(
            "deepseek",
            1,
            "proposal",
            proposal_payload(),
            "no-such-provider-job",
            expect=2,
        )
        self.assertIn("does not exist", forged.stderr)
        wrong_role = self.submit(
            "glm",
            1,
            "proposal",
            proposal_payload(),
            job_id,
            expect=2,
        )
        self.assertIn("role", wrong_role.stderr)
        codex_job = self.submit(
            "codex",
            1,
            "proposal",
            proposal_payload(),
            None,
            expect=2,
            extra=("--job-id", "pretend-provider-job"),
        )
        self.assertIn("leader", codex_job.stderr)
        mismatch = self.normalize("proposal", proposal_payload())
        mismatch["approach"] = (
            "A different but well-formed proposal that the provider never emitted."
        )
        mismatch_path = self.root / "mismatched-submission.json"
        mismatch_path.write_text(json.dumps(mismatch), encoding="utf-8")
        wrong_payload = self.run_cli(
            "consensus-submit",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--role",
            "deepseek",
            "--round",
            "1",
            "--submission-file",
            str(mismatch_path),
            "--source-job",
            job_id,
            "--json",
            expected=2,
        )
        self.assertIn("deterministic mapping", wrong_payload.stderr)
        # The real, exact mapped submission succeeds exactly once.
        self.submit("deepseek", 1, "proposal", proposal_payload(), job_id)
        duplicate = self.submit(
            "deepseek", 1, "proposal", proposal_payload(), job_id, expect=2
        )
        self.assertIn("already", duplicate.stderr)

        # A second live job may not occupy the same discussion slot.
        task = self.root / "task-glm-live.md"
        task.write_text("Return the required proposal payload for glm.\n")
        live = dict(self.env)
        live["C_FAKE_RESULT"] = result_text("proposal", proposal_payload())
        live["C_FAKE_SLEEP"] = "3"
        launched = self.run_cli(
            "execution-discussion",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--role",
            "glm",
            "--round",
            "1",
            "--task-file",
            str(task),
            "--timeout-seconds",
            "30",
            "--config",
            str(self.config),
            "--json",
            env=live,
        )
        live_job = json.loads(launched.stdout)["job_id"]
        live_conflict = self.run_cli(
            "execution-discussion",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--role",
            "glm",
            "--round",
            "1",
            "--task-file",
            str(task),
            "--timeout-seconds",
            "5",
            "--config",
            str(self.config),
            "--json",
            expected=2,
        )
        self.assertIn("provider job", live_conflict.stderr)
        self.wait(live_job, env=live)

    def test_contract_narrowing_immutability_and_reopen_fencing(self) -> None:
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        missing_contract = self.implement(
            self.implementation_task(), expect=2
        )
        self.assertIn("No execution contract", missing_contract.stderr)
        self.assertEqual(self.implementation_jobs(), [])

        wider = self.contract_document(digest)
        wider["allowed_paths"] = ["allowed/**", "tracked.txt"]
        self.assertIn(
            "approved pattern",
            self.freeze_contract(wider, expect=2).stderr,
        )
        dropped = self.contract_document(digest)
        dropped["acceptance_criteria"] = dropped["acceptance_criteria"][:1]
        self.assertIn(
            "criterion", self.freeze_contract(dropped, expect=2).stderr
        )
        substituted = self.contract_document(digest)
        substituted["acceptance_criteria"][0]["text"] = "A different criterion"
        self.assertIn(
            "criterion", self.freeze_contract(substituted, expect=2).stderr
        )
        dropped_argv = self.contract_document(digest)
        dropped_argv["required_validation"] = []
        self.assertIn(
            "required_validation",
            self.freeze_contract(dropped_argv, expect=2).stderr,
        )
        raised = self.contract_document(digest)
        raised["max_changed_files"] = 9
        self.assertIn(
            "max_changed_files",
            self.freeze_contract(raised, expect=2).stderr,
        )
        weakened = self.contract_document(digest)
        weakened["denied_paths"] = []
        self.assertIn(
            "denial", self.freeze_contract(weakened, expect=2).stderr
        )
        protected = self.contract_document(digest)
        protected["target_branch"] = "main"
        self.assertIn(
            "protected", self.freeze_contract(protected, expect=2).stderr
        )

        valid = self.contract_document(digest)
        first = self.freeze_contract(valid)
        same = self.freeze_contract(valid)
        self.assertTrue(same["idempotent"])
        self.assertEqual(first["contract_digest"], same["contract_digest"])
        changed = self.contract_document(digest)
        changed["objective"] = (
            "Implement a different objective with the same approved patterns."
        )
        self.assertIn(
            "immutable", self.freeze_contract(changed, expect=2).stderr
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "READY_TO_IMPLEMENT")

        # A pending intent fences every B1 reopen until it is provably closed.
        d = runner.d_module()
        task = self.implementation_task()
        descriptor = d.prepare_implementation(
            plan_id="d1-plan", step_id="step-one", task_file=task
        )
        fenced = self.run_cli(
            "consensus-new-cycle",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "codex",
            "--authorization",
            "Coordinator requests a fresh cycle while a writer is pending.",
            "--authorization-kind",
            "coordinator",
            "--json",
            expected=2,
        )
        self.assertIn("pending", fenced.stderr)
        aborted = d.abort_unstarted(
            plan_id="d1-plan",
            step_id="step-one",
            job_id=descriptor["job_id"],
            reason="test closed an unstarted intent",
        )
        self.assertTrue(aborted["aborted"])
        reopened = self.json_cli(
            "consensus-new-cycle",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "codex",
            "--authorization",
            "Coordinator requests a fresh cycle after aborting the intent.",
            "--authorization-kind",
            "coordinator",
            "--json",
        )
        self.assertEqual(reopened["stage"], "PROPOSALS_OPEN")
        stale = self.run_cli(
            "execution-finalize",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--job-id",
            descriptor["job_id"],
            "--json",
            expected=2,
        )
        self.assertIn("CONSENSUS_REACHED", stale.stderr)

    def test_unauthorized_writer_dirty_overlap_and_preservation(self) -> None:
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()

        # GLM/custom writer routes stay structurally closed on a strict plan.
        legacy = self.run_cli(
            "launch",
            "--cli",
            "glm",
            "--operation",
            "implementation",
            "--approved-executor",
            "glm",
            "--workspace",
            str(self.repo),
            "--task-file",
            str(task),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("unauthorized_role", legacy.stderr)
        custom = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--approved-executor",
            "fake",
            "--workspace",
            str(self.repo),
            "--task-file",
            str(task),
            "--config",
            str(self.config),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("B1 blocks", custom.stderr)
        codex_role = self.run_cli(
            "execution-discussion",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "1",
            "--task-file",
            str(task),
            "--json",
            expected=2,
        )
        self.assertIn("invalid choice", codex_role.stderr)
        widened = self.run_cli(
            "execution-implement",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--task-file",
            str(task),
            "--role",
            "codex",
            "--json",
            expected=2,
        )
        self.assertIn("unrecognized arguments", widened.stderr)
        self.assertEqual(self.implementation_jobs(), [])

        # Dirty overlap inside the approved scope refuses startup before effect.
        dirty = self.repo / "allowed" / "dirty.txt"
        dirty.write_text("user data\n")
        refused = self.implement(task, expect=2)
        self.assertIn("overlap", refused.stderr)
        self.assertEqual(self.implementation_jobs(), [])
        dirty.unlink()

        # The success path below protects unrelated user bytes with genuine
        # read-only mounts, which the non-confining transport shim cannot do.
        self.require_real_bwrap()

        # Unrelated pre-existing dirt is preserved and excluded from the delta.
        notes = self.repo / "notes.txt"
        notes.write_text("user notes\n")
        index_before = runner.b2_module().snapshot_workspace(
            self.repo, strict=True
        )["index"]["sha256"]
        written = self.repo / "allowed" / "result.txt"
        local = self.implementation_writes(
            [("allowed/result.txt", b"result\n")],
            [],
            ["allowed/result.txt"],
            {"C_FAKE_SLEEP": "4"},
        )
        launched = self.implement(task, env_overrides=local)
        job_id = launched["job_id"]
        second = self.implement(task, env_overrides=local, expect=2)
        self.assertIn(
            "claimed",
            second.stderr + (second.stdout or ""),
        )
        self.wait(job_id, env={**self.env, **local})
        finalized = self.finalize(job_id)
        self.assertTrue(finalized["completed"], finalized)
        self.assertEqual(notes.read_text(), "user notes\n")
        self.assertEqual(written.read_text(), "result\n")
        index_after = runner.b2_module().snapshot_workspace(
            self.repo, strict=True
        )["index"]["sha256"]
        self.assertEqual(index_before, index_after)
        self.assertEqual(
            sorted(finalized["changed_paths"]), ["allowed/result.txt"]
        )
        journal = self.journal()
        evidence = self.evidence_blob("d1-plan", journal["results"][0]["payload"])
        self.assertNotIn("notes.txt", evidence["delta"]["paths"])

        # A foreign state home cannot observe or extend this execution.
        other = dict(self.env)
        other["AGENT_ORCHESTRATOR_HOME"] = str(self.root / "other-state")
        foreign = self.run_cli(
            "execution-finalize",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--job-id",
            job_id,
            "--json",
            expected=2,
            env=other,
        )
        self.assertTrue(
            "Unknown plan" in foreign.stderr
            or "empty consensus ledger" in foreign.stderr,
            foreign.stderr,
        )

    def test_continuation_recovery_and_user_edit_block(self) -> None:
        self.require_real_bwrap()
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()

        # Unrelated hidden-index bytes outside the approved scope are preserved
        # across both invocations of the same attempt.
        index_path = self.repo / ".git" / "index"
        self.git(self.repo, "update-index", "--assume-unchanged", "tracked.txt")
        unrelated = self.repo / "tracked.txt"
        unrelated_bytes = b"UNRELATED HIDDEN CONTENT ACROSS CONTINUATION\n"
        unrelated.write_bytes(unrelated_bytes)
        index_before = hashlib.sha256(index_path.read_bytes()).hexdigest()

        first_local = self.implementation_writes(
            [("allowed/result.txt", b"first attempt\n")],
            [],
            [],
        )
        launched = self.implement(task, env_overrides=first_local)
        first_job = launched["job_id"]
        self.wait(first_job, env={**self.env, **first_local})
        first = self.finalize(first_job)
        self.assertEqual(first["classification"], "drained_failure", first)
        self.assertIn("do not reconcile", " ".join(first["reasons"]))
        self.assertFalse(first["completed"])
        refused_abort = self.run_cli(
            "execution-abort",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--job-id",
            first_job,
            "--reason",
            "an invocation that produced evidence is never a no-start",
            "--json",
            expected=2,
        )
        self.assertIn(
            "claimed or produced evidence", refused_abort.stdout
        )

        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["execution"]["stage"], "CONTINUATION_REQUIRED"
        )

        # A user edit to the residue can never be authorized by capture.
        residue = self.repo / "allowed" / "result.txt"
        residue.write_text("user edit\n")
        blocked = self.run_cli(
            "execution-continue",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--operator",
            "codex",
            "--authorization",
            "Authorize the exact own-attempt continuation.",
            "--json",
            expected=2,
        )
        self.assertIn("changed after the drained invocation", blocked.stderr)
        residue.write_text("first attempt\n")

        continuation = self.json_cli(
            "execution-continue",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--operator",
            "codex",
            "--authorization",
            "Authorize the exact own-attempt continuation.",
            "--json",
        )
        self.assertEqual(continuation["invocation"], 2)
        idempotent = self.json_cli(
            "execution-continue",
            "--plan-id",
            "d1-plan",
            "--step-id",
            "step-one",
            "--operator",
            "codex",
            "--authorization",
            "Authorize the exact own-attempt continuation.",
            "--json",
        )
        self.assertTrue(idempotent["idempotent"])

        # A provable pre-invocation abort of the continuation intent can be
        # reissued under the same authorization, without a second writer start.
        d = runner.d_module()
        aborted_descriptor = d.prepare_implementation(
            plan_id="d1-plan", step_id="step-one", task_file=task
        )
        aborted = d.abort_unstarted(
            plan_id="d1-plan",
            step_id="step-one",
            job_id=aborted_descriptor["job_id"],
            reason="test proved the continuation invocation never started",
        )
        self.assertTrue(aborted["aborted"])

        second_local = self.implementation_writes(
            [("allowed/second.txt", b"second attempt\n")],
            [],
            ["allowed/result.txt", "allowed/second.txt"],
        )
        launched = self.implement(task, env_overrides=second_local)
        second_job = launched["job_id"]
        self.assertNotEqual(first_job, second_job)
        self.wait(second_job, env={**self.env, **second_local})
        finalized = self.finalize(second_job)
        self.assertTrue(finalized["completed"], finalized)
        self.assertEqual(finalized["invocation"], 2)
        self.assertEqual(
            sorted(finalized["changed_paths"]),
            ["allowed/result.txt", "allowed/second.txt"],
        )
        self.assertEqual(residue.read_text(), "first attempt\n")
        self.assertEqual(unrelated.read_bytes(), unrelated_bytes)
        self.assertEqual(
            hashlib.sha256(index_path.read_bytes()).hexdigest(), index_before
        )
        journal = self.journal()
        self.assertEqual(len(journal["results"]), 2)
        self.assertEqual(len(journal["completions"]), 1)
        self.assertEqual(len(journal["continuations"]), 1)

    def test_legacy_candidate_compatibility_and_strict_requirements(self) -> None:
        self.create_plan(plan_id="legacy-plan", strict=False)

        def legacy_submit(role: str, round_number: int, payload: dict) -> None:
            path = self.root / f"legacy-{role}-{round_number}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            args = [
                "consensus-submit",
                "--plan-id",
                "legacy-plan",
                "--step-id",
                "step-one",
                "--role",
                role,
                "--round",
                str(round_number),
                "--submission-file",
                str(path),
                "--job-id",
                f"manual-{role}",
                "--json",
            ]
            self.run_cli(*args)

        legacy_proposal = {
            "approach": "Use the existing manual consensus procedure.",
            "rationale": "Legacy plans keep their exact historical behavior.",
            "assumptions": ["old ledgers remain readable"],
            "risks": ["no managed writer"],
            "alternatives": ["strict execution"],
            "feasibility": "standard library only",
            "tests": ["legacy compatibility"],
        }
        legacy_cross = {
            "responses": ["The legacy receipts remain byte compatible."],
            "challenges": [
                {"objection": "Do not add fields to old candidates.", "severity": "major"}
            ],
            "revisions": ["Keep the optional field absent."],
        }
        for role in ("deepseek", "glm", "codex"):
            legacy_submit(role, 1, legacy_proposal)
        for role in ("deepseek", "glm", "codex"):
            legacy_submit(role, 2, legacy_cross)
        candidate = {
            "final_design": (
                "Preserve the historical manual consensus ledger without new "
                "execution fields."
            ),
            "important_decisions": ["manual records remain readable"],
            "rejected_alternatives": [
                {"alternative": "strict execution", "reason": "not requested"}
            ],
            "objection_dispositions": [
                {
                    "objection_id": objection_id,
                    "disposition": "accepted",
                    "reason": "the field stays absent",
                }
                for objection_id in ("O001", "O002", "O003")
            ],
            "remaining_risks": ["legacy behavior is unchanged"],
        }
        digest = self.freeze_candidate(candidate, plan_id="legacy-plan")
        for role in ("deepseek", "glm"):
            self.vote(
                role,
                digest,
                job_id=f"manual-{role}",
                plan_id="legacy-plan",
                source=False,
            )
        self.vote("codex", digest, job_id=None, plan_id="legacy-plan")
        checkpoint = self.checkpoint("legacy-plan")
        self.assertNotIn("strict_execution", checkpoint)
        self.assertNotIn("execution", checkpoint)
        state = runner.b1_module().replay_plan_state_unlocked("legacy-plan")
        frozen = state["steps"]["step-one"]["candidate"]["candidate"]
        self.assertNotIn("execution_constraints", frozen)
        self.assertEqual(state["steps"]["step-one"]["candidate"]["digest"], digest)

        # The source-job bypass exists only for strict plans.
        legacy_path = self.root / "legacy-source.json"
        legacy_path.write_text(json.dumps(legacy_proposal), encoding="utf-8")
        bypass = self.run_cli(
            "consensus-submit",
            "--plan-id",
            "legacy-plan",
            "--step-id",
            "step-one",
            "--role",
            "deepseek",
            "--round",
            "1",
            "--submission-file",
            str(legacy_path),
            "--source-job",
            "some-job",
            "--json",
            expected=2,
        )
        self.assertIn("only for strict-execution", bypass.stderr)

        # A strict-mode candidate must carry the versioned constraints.
        b1 = runner.b1_module()
        state = b1.replay_plan_state_unlocked("legacy-plan")
        manifest_step = state["static"]["manifest"]["steps"][0]
        with self.assertRaises(runner.RunnerError):
            b1._validate_candidate(
                candidate, ["O001"], manifest_step, strict=True
            )
        with self.assertRaises(runner.RunnerError):
            b1._validate_candidate(
                self.candidate(),
                ["O001", "O002", "O003"],
                manifest_step,
                strict=False,
            )

    def test_hidden_and_ignored_scope_content_refused_before_start(self) -> None:
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()
        marker = self.root / "protected-provider-marker"
        index_path = self.repo / ".git" / "index"

        def index_sha() -> str:
            return hashlib.sha256(index_path.read_bytes()).hexdigest()

        old_path = self.repo / "allowed" / "old.txt"
        for flag, restore_flag in (
            ("--assume-unchanged", "--no-assume-unchanged"),
            ("--skip-worktree", "--no-skip-worktree"),
        ):
            self.git(self.repo, "update-index", flag, "allowed/old.txt")
            user_bytes = f"PREEXISTING USER BYTES {flag}\n".encode("utf-8")
            old_path.write_bytes(user_bytes)
            index_before = index_sha()
            local = self.implementation_writes(
                [("allowed/old.txt", b"DESTRUCTIVE IMPLEMENTATION OVERWRITE\n")],
                [],
                ["allowed/old.txt"],
            )
            local["C_FAKE_START_MARKER"] = str(marker)
            refused = self.implement(task, env_overrides=local, expect=2)
            self.assertIn(
                "protected user content overlaps", refused.stderr, refused.stderr
            )
            self.assertIn("hidden index flag", refused.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(self.implementation_jobs(), [])
            self.assertEqual(old_path.read_bytes(), user_bytes)
            self.assertEqual(index_sha(), index_before)
            listed = subprocess.run(
                [
                    "git",
                    "--no-optional-locks",
                    "ls-files",
                    "-v",
                    "--",
                    "allowed/old.txt",
                ],
                cwd=self.repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            tag = listed.split(" ", 1)[0] if listed else ""
            self.assertTrue(tag == "S" or tag.islower(), listed)
            self.git(self.repo, "update-index", restore_flag, "allowed/old.txt")
            old_path.write_bytes(b"old\n")

        # Ignored pre-existing bytes in the approved scope are protected even
        # though git status is clean and the path is not dirty or untracked.
        exclude = self.repo / ".git" / "info" / "exclude"
        original_exclude = exclude.read_bytes()
        cache = self.repo / "allowed" / "cache.tmp"
        user_bytes = b"PREEXISTING IGNORED USER BYTES\n"
        exclude.write_text("allowed/cache.tmp\n", encoding="utf-8")
        cache.write_bytes(user_bytes)
        index_before = index_sha()
        local = self.implementation_writes(
            [("allowed/cache.tmp", b"DESTRUCTIVE IMPLEMENTATION OVERWRITE\n")],
            [],
            ["allowed/cache.tmp"],
        )
        local["C_FAKE_START_MARKER"] = str(marker)
        refused = self.implement(task, env_overrides=local, expect=2)
        self.assertIn("protected user content overlaps", refused.stderr)
        self.assertNotIn(
            "allowed/cache.tmp (hidden index flag)", refused.stderr
        )
        self.assertFalse(marker.exists())
        self.assertEqual(self.implementation_jobs(), [])
        self.assertEqual(cache.read_bytes(), user_bytes)
        self.assertEqual(index_sha(), index_before)
        cache.unlink()
        exclude.write_bytes(original_exclude)

    def test_unrelated_hidden_and_ignored_content_preserved(self) -> None:
        self.require_real_bwrap()
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()
        index_path = self.repo / ".git" / "index"

        exclude = self.repo / ".git" / "info" / "exclude"
        original_exclude = exclude.read_bytes()
        exclude.write_text("other/cache.tmp\n", encoding="utf-8")
        other = self.repo / "other"
        other.mkdir()
        ignored = other / "cache.tmp"
        ignored_bytes = b"UNRELATED IGNORED USER BYTES\n"
        ignored.write_bytes(ignored_bytes)

        # Hidden-index user bytes outside the approved scope must not block a
        # normal clean tracked edit, and both the bytes and flags survive.
        self.git(self.repo, "update-index", "--assume-unchanged", "tracked.txt")
        tracked = self.repo / "tracked.txt"
        hidden_bytes = b"UNRELATED HIDDEN USER BYTES\n"
        tracked.write_bytes(hidden_bytes)
        index_before = hashlib.sha256(index_path.read_bytes()).hexdigest()

        local = self.implementation_writes(
            [
                ("allowed/old.txt", b"ordinary clean tracked edit\n"),
                ("allowed/new.txt", b"new approved file\n"),
            ],
            [],
            ["allowed/old.txt", "allowed/new.txt"],
        )
        launched = self.implement(task, env_overrides=local)
        job_id = launched["job_id"]
        status = self.wait(job_id, env={**self.env, **local})
        self.assertEqual(status.get("state"), "succeeded", status)
        # A startup marker outside the writable workspace mounts is correctly
        # denied by the real confinement (EROFS), so startup is proven by the
        # provider's own validated result instead of a synthetic file write.
        self.assertTrue(
            (status.get("provider_result") or {}).get("validated"), status
        )
        finalized = self.finalize(job_id)
        self.assertTrue(finalized["completed"], finalized)
        self.assertEqual(
            sorted(finalized["changed_paths"]),
            ["allowed/new.txt", "allowed/old.txt"],
        )
        self.assertEqual(
            (self.repo / "allowed" / "old.txt").read_bytes(),
            b"ordinary clean tracked edit\n",
        )
        self.assertEqual((self.repo / "allowed" / "new.txt").read_bytes(), b"new approved file\n")
        self.assertEqual(tracked.read_bytes(), hidden_bytes)
        self.assertEqual(ignored.read_bytes(), ignored_bytes)
        self.assertEqual(
            hashlib.sha256(index_path.read_bytes()).hexdigest(), index_before
        )
        listed = subprocess.run(
            ["git", "--no-optional-locks", "ls-files", "-v", "--", "tracked.txt"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertTrue(listed.split(" ", 1)[0].islower(), listed)
        ignored.unlink()
        exclude.write_bytes(original_exclude)

    def test_out_of_scope_ignored_overwrite_blocks_completion(self) -> None:
        # Git status cannot see ignored files.  Cycle2 pins the original
        # ignored bytes read-only before the provider starts, so an
        # out-of-scope overwrite is denied by the kernel and the attempt can
        # never report a false complete or an empty successful delta.
        self.require_real_bwrap()
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()
        exclude = self.repo / ".git" / "info" / "exclude"
        original_exclude = exclude.read_bytes()
        exclude.write_text("local.sql\n", encoding="utf-8")
        ignored = self.repo / "local.sql"
        user_bytes = b"UNRELATED IGNORED USER BYTES\n"
        ignored.write_bytes(user_bytes)
        index_path = self.repo / ".git" / "index"
        index_before = hashlib.sha256(index_path.read_bytes()).hexdigest()
        try:
            local = self.implementation_writes(
                [("local.sql", b"PROVIDER OVERWRITE\n")], [], []
            )
            launched = self.implement(task, env_overrides=local)
            job_id = launched["job_id"]
            waited = self.run_cli(
                "wait",
                job_id,
                "--timeout-seconds",
                "90",
                "--poll-seconds",
                "0.2",
                "--json",
                env={**self.env, **local},
                expected=1,
            )
            waited_meta = json.loads(waited.stdout)
            self.assertEqual(waited_meta.get("state"), "failed")
            finalized = self.finalize(job_id)
            self.assertFalse(finalized["completed"], finalized)
            self.assertNotEqual(finalized["state"], "IMPLEMENTATION_COMPLETE")
            self.assertEqual(finalized["changed_paths"], [])
            reasons = " ".join(finalized["reasons"])
            self.assertIn("provider", reasons.lower())
            # The kernel denied the write through the read-only protected root.
            self.assertEqual(ignored.read_bytes(), user_bytes)
            self.assertEqual(
                hashlib.sha256(index_path.read_bytes()).hexdigest(), index_before
            )
            checkpoint = self.checkpoint()
            self.assertNotEqual(
                checkpoint["execution"]["stage"], "IMPLEMENTATION_COMPLETE"
            )
            attempt = checkpoint["execution"]["attempt"]
            self.assertIsNotNone(attempt["protection_manifest_digest"])
        finally:
            ignored.unlink(missing_ok=True)
            exclude.write_bytes(original_exclude)

    def test_journal_directory_durability_chain_and_sync_failure(self) -> None:
        d = runner.d_module()
        state_plans = self.state / "plans"

        blob_plan = state_plans / "durability-blob"
        blob_plan.mkdir(parents=True)
        calls: list[Path] = []
        with mock.patch.object(d, "_fsync_dir", side_effect=calls.append):
            blob_sha = d._publish_blob(
                "durability-blob", b"durable evidence", "test blob"
            )
        self.assertEqual(
            calls,
            [
                blob_plan,
                blob_plan / "execution",
                blob_plan / "execution" / "blobs",
            ],
        )
        calls.clear()
        with mock.patch.object(d, "_fsync_dir", side_effect=calls.append):
            repeated = d._publish_blob(
                "durability-blob", b"durable evidence", "test blob"
            )
        self.assertEqual(repeated, blob_sha)
        self.assertEqual(
            calls,
            [
                blob_plan,
                blob_plan / "execution",
                blob_plan / "execution" / "blobs",
            ],
        )

        event_plan = state_plans / "durability-event"
        event_plan.mkdir(parents=True)
        event_path = event_plan / "execution" / "events" / "000001.json"
        calls.clear()
        with mock.patch.object(d, "_fsync_dir", side_effect=calls.append):
            d._write_event_file(
                "durability-event", event_path, {"sequence": 1}
            )
        self.assertEqual(
            calls,
            [
                event_plan,
                event_plan / "execution",
                event_plan / "execution" / "events",
            ],
        )
        self.assertTrue(event_path.is_file())

        failing_plan = state_plans / "durability-failing"
        failing_plan.mkdir(parents=True)
        original = d._fsync_dir

        def fail_execution_sync(path: Path) -> None:
            if Path(path) == failing_plan / "execution":
                raise OSError("injected directory sync failure")
            original(path)

        with mock.patch.object(d, "_fsync_dir", side_effect=fail_execution_sync):
            with self.assertRaises(runner.RunnerError) as raised:
                d._publish_blob(
                    "durability-failing", b"never durable", "failing blob"
                )
        self.assertIn("durably publish", str(raised.exception))
        remaining = failing_plan / "execution" / "blobs"
        self.assertFalse(remaining.is_dir() and any(remaining.iterdir()))

        # The same failure during the first prepared publication must leave no
        # acknowledged intent or started writer behind.
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()
        plan_dir = state_plans / "d1-plan"

        def fail_first_publication(path: Path) -> None:
            if Path(path) == plan_dir / "execution":
                raise OSError("injected first-publication directory sync failure")
            original(path)

        with mock.patch.object(
            d, "_fsync_dir", side_effect=fail_first_publication
        ):
            with self.assertRaises(runner.RunnerError) as raised:
                d.prepare_implementation(
                    plan_id="d1-plan", step_id="step-one", task_file=task
                )
        self.assertIn("durably publish", str(raised.exception))
        journal = d._replay_journal("d1-plan")
        self.assertEqual(journal["intents"], [])
        self.assertEqual(journal["claims"], [])
        self.assertEqual(self.implementation_jobs(), [])
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["execution"]["stage"], "READY_TO_IMPLEMENT")

    def test_transport_shim_never_claims_protected_confinement(self) -> None:
        # The non-confining transport shim must never be accepted as kernel
        # protection.  C refuses to start the provider when its in-namespace
        # mount check cannot prove the declared protected root is read-only,
        # so no bytes are touched and no completion is recorded.
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        self.freeze_contract(self.contract_document(digest))
        task = self.implementation_task()
        exclude = self.repo / ".git" / "info" / "exclude"
        original_exclude = exclude.read_bytes()
        exclude.write_text("local.sql\n", encoding="utf-8")
        ignored = self.repo / "local.sql"
        user_bytes = b"UNRELATED IGNORED USER BYTES\n"
        ignored.write_bytes(user_bytes)
        try:
            local = self.implementation_writes(
                [("local.sql", b"PROVIDER OVERWRITE\n")], [], []
            )
            launched = self.implement(task, env_overrides=local)
            job_id = launched["job_id"]
            waited = self.run_cli(
                "wait",
                job_id,
                "--timeout-seconds",
                "90",
                "--poll-seconds",
                "0.2",
                "--json",
                env={**self.env, **local},
                expected=1,
            )
            metadata = json.loads(waited.stdout)
            self.assertEqual(metadata.get("state"), "failed")
            worker_error = metadata.get("provider_error") or metadata.get("error") or {}
            self.assertEqual(worker_error.get("code"), "isolation_unavailable")
            finalized = self.finalize(job_id)
            self.assertFalse(finalized["completed"], finalized)
            self.assertEqual(finalized["changed_paths"], [])
            self.assertEqual(ignored.read_bytes(), user_bytes)
            checkpoint = self.checkpoint()
            self.assertNotEqual(
                checkpoint["execution"]["stage"], "IMPLEMENTATION_COMPLETE"
            )
        finally:
            ignored.unlink(missing_ok=True)
            exclude.write_bytes(original_exclude)

    def test_large_ignored_roots_flow_without_content_census(self) -> None:
        self.require_real_bwrap()
        exclude = self.repo / ".git" / "info" / "exclude"
        original_exclude = exclude.read_bytes()
        exclude.write_text("vendor/\nhuge-sparse.bin\nlocal.sql\n", encoding="utf-8")
        vendor = self.repo / "vendor"
        vendor.mkdir()
        for index in range(50_001):
            descriptor = os.open(
                vendor / f"entry-{index}",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
        sparse = self.repo / "huge-sparse.bin"
        sparse.write_bytes(b"sparse ignored user byte")
        os.truncate(sparse, 129 * 1024 * 1024)
        local = self.repo / "local.sql"
        local.write_bytes(b"ignored user database\n")
        try:
            self.create_plan()
            digest, _candidate = self.complete_consensus()
            self.freeze_contract(self.contract_document(digest))
            task = self.implementation_task()
            started = time.monotonic()
            local_env = self.implementation_writes(
                [("allowed/large-root.txt", b"approved result\n")],
                [],
                ["allowed/large-root.txt"],
            )
            launched = self.implement(task, env_overrides=local_env)
            job_id = launched["job_id"]
            self.wait(job_id, env={**self.env, **local_env})
            finalized = self.finalize(job_id)
            elapsed = time.monotonic() - started
            self.assertTrue(finalized["completed"], finalized)
            self.assertLess(elapsed, 300.0)
            self.assertEqual(local.read_bytes(), b"ignored user database\n")
            self.assertEqual(
                (vendor / "entry-0").read_bytes(), b""
            )
            self.assertEqual(
                (self.repo / "allowed" / "large-root.txt").read_bytes(),
                b"approved result\n",
            )
            journal = self.journal()
            evidence = self.evidence_blob(
                "d1-plan", journal["results"][0]["payload"]
            )
            protection = evidence["protection"]
            manifest = protection["manifest"]
            self.assertIn(
                "vendor", {entry["path"] for entry in manifest["roots"]}
            )
            self.assertIn(
                "huge-sparse.bin", {entry["path"] for entry in manifest["roots"]}
            )
            self.assertFalse(
                manifest["coverage"]["recursive_ignored_content_hashes"]
            )
            self.assertLess(
                manifest["counts"]["extra_mount_argv_bytes"], 128 * 1024
            )
            self.assertTrue(
                protection["confinement"]["application"]["verified"]
            )
        finally:
            exclude.write_bytes(original_exclude)

    def test_protected_branch_refusal(self) -> None:
        main_repo = self.root / "main-repo"
        main_repo.mkdir()
        self.git(main_repo, "init", "-q", "-b", "main")
        self.git(main_repo, "config", "user.email", "tests@example.invalid")
        self.git(main_repo, "config", "user.name", "Tests")
        (main_repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        (main_repo / "allowed").mkdir()
        (main_repo / "allowed" / "old.txt").write_text("old\n", encoding="utf-8")
        self.git(main_repo, "add", "tracked.txt", "allowed/old.txt")
        self.git(main_repo, "commit", "-qm", "baseline")
        self.repo = main_repo
        self.create_plan()
        digest, _candidate = self.complete_consensus()
        refused = self.freeze_contract(
            self.contract_document(digest), expect=2
        )
        self.assertIn("target branch", refused.stderr)
        self.assertIn("feature/d1-tests", refused.stderr)
        blocked = self.implement(self.implementation_task(), expect=2)
        self.assertIn("contract", blocked.stderr)
        self.assertEqual(self.implementation_jobs(), [])


if __name__ == "__main__":
    unittest.main()
