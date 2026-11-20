from __future__ import annotations

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
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "scripts" / "cli_agent_job.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "agent_orchestrator_runner_b1", RUNNER
)
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)

V1_ROLES = ("codex", "antigravity", "deepseek", "glm")
ROLES = ("codex", "deepseek", "glm")


class B1ConsensusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.env = os.environ.copy()
        self.env["AGENT_ORCHESTRATOR_HOME"] = str(self.state)
        self.workspace = self.root / "repo"
        self.workspace.mkdir()
        self.git(self.workspace, "init", "-q")
        self.git(self.workspace, "config", "user.email", "worker@example.test")
        self.git(self.workspace, "config", "user.name", "Worker")
        (self.workspace / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        self.git(self.workspace, "add", "tracked.txt")
        self.git(self.workspace, "commit", "-qm", "baseline")
        (self.workspace / "subdir").mkdir()

        self.plan_file = self.root / "plan.md"
        self.write_plan(self.plan_file)
        self.brief = {
            "original_objective": (
                "Ship durable research-plan consensus for long-term objectives."
            ),
            "repository_context": (
                "Agent Orchestrator runner, plan directory and record lock."
            ),
            "constraints": ["standard library only", "no production launcher changes"],
            "proposed_approach": (
                "One immutable ordered event ledger with a 4/4 ballot gate."
            ),
            "expected_changes": ["consensus ledger module", "runner admission guards"],
            "acceptance_criteria": ["public runner tests demonstrate every branch"],
        }
        self.manifest = {
            "policy_version": 2,
            "steps": [
                {
                    "id": "step-one",
                    "objective": "Implement the durable B1 consensus ledger gate.",
                    "scope": ["plugins/agent-orchestrator/scripts"],
                    "deliverables": ["consensus ledger", "public runner CLI"],
                    "acceptance_criteria": ["public runner tests pass"],
                    "depends_on": [],
                    "brief": dict(self.brief),
                }
            ],
        }
        self.manifest_file = self.root / "manifest.json"
        self.write_manifest(self.manifest, self.manifest_file)
        self.proposal_files = {}
        for role in ROLES:
            path = self.root / f"proposal-{role}.json"
            path.write_text(json.dumps(self.proposal()), encoding="utf-8")
            self.proposal_files[role] = path
        self.cross_files = {}
        for role in ROLES:
            path = self.root / f"cross-{role}.json"
            path.write_text(json.dumps(self.cross(role)), encoding="utf-8")
            self.cross_files[role] = path
        self.task_file = self.root / "task.md"
        self.task_file.write_text("implement the bounded change\n", encoding="utf-8")
        self.agents_config = self.root / "agents.json"
        self.agents_config.write_text(
            json.dumps(
                {
                    "agents": {
                        "fake": {
                            "argv": [
                                sys.executable,
                                "-c",
                                "import sys; sys.stdin.read()",
                            ],
                            "prompt_transport": "stdin",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

    def git(self, cwd: Path, *args: str) -> None:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def write_plan(
        self,
        path: Path,
        checked: bool = False,
        goal: str = "Ship the bounded B1 consensus feature with durable evidence.",
    ) -> None:
        marker = "x" if checked else " "
        path.write_text(
            f"# Goal\n{goal}\n\n"
            "# Decisions and assumptions\nFollow the frozen candidate.\n\n"
            "# Constraints and guardrails\nDo not publish or change credentials.\n\n"
            f"# Checklist\n- [{marker}] Implement and verify the managed flow.\n\n"
            "# Validation strategy\nRun the public runner tests.\n\n"
            "# Completion criteria\nAll acceptance evidence is recorded.\n",
            encoding="utf-8",
        )

    def write_manifest(self, manifest: object, path: Path) -> None:
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def proposal(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "approach": "Persist immutable ordered event files under the plan lock.",
            "rationale": "Replay yields one authoritative durable ledger.",
            "assumptions": ["local POSIX filesystem semantics"],
            "risks": ["crash between publication and projection"],
            "alternatives": ["append-only JSONL", "SQLite ledger"],
            "feasibility": "Standard library only with bounded payloads.",
            "tests": ["unanimous flow", "dissent flow"],
        }
        value.update(overrides)
        return value

    def cross(self, role: str) -> dict[str, object]:
        if role == "codex":
            return {
                "responses": [
                    "All three proposals were read; the event ledger is strongest."
                ],
                "challenges": [
                    {
                        "objection": "Define recovery for a crash before projections regenerate.",
                        "severity": "major",
                    }
                ],
                "revisions": ["Regenerate computed views on every checkpoint."],
            }
        return {
            "responses": ["All three proposals were read and the approach is sound."],
            "challenges": [],
            "revisions": [],
        }

    def candidate(self, objection_ids: list[str]) -> dict[str, object]:
        return {
            "final_design": (
                "Use one immutable event ledger with canonical digests and "
                "projection regeneration."
            ),
            "important_decisions": ["events are authoritative"],
            "rejected_alternatives": [
                {
                    "alternative": "append-only JSONL",
                    "reason": "partial tail recovery risk",
                }
            ],
            "objection_dispositions": [
                {
                    "objection_id": objection_id,
                    "disposition": "accepted",
                    "reason": "projection regeneration recovers this case",
                }
                for objection_id in objection_ids
            ],
            "remaining_risks": ["POSIX local filesystem assumptions"],
        }

    def candidate_file(self, objection_ids: list[str], name: str = "candidate") -> Path:
        path = self.root / f"{name}-{len(objection_ids)}.json"
        path.write_text(json.dumps(self.candidate(objection_ids)), encoding="utf-8")
        return path

    def run_cli(
        self, *args: str, expected: int = 0, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(RUNNER), *args],
            capture_output=True,
            text=True,
            env=env or self.env,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            expected,
            (result.stderr or "") + (result.stdout or ""),
        )
        return result

    def run_cli_with_hook(
        self,
        args: tuple[str, ...],
        target: str,
        mode: str = "exit",
        code: int = 23,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run the public CLI in a subprocess that interrupts one internals call.

        ``exit`` simulates a genuine process interruption with ``os._exit`` (the
        ``finally`` blocks do not run). ``raise`` injects an ordinary in-process
        failure so the deterministic cleanup path is exercised.
        """
        script = self.root / f"interrupt-{target.strip('_')}-{mode}.py"
        if mode == "raise":
            action = f"    raise RuntimeError('injected failure in {target}')\n"
        elif mode == "assert_lock":
            action = (
                "    import fcntl\n"
                "    lock_path = Path(call_args[0]) / 'consensus' / 'ledger.lock'\n"
                "    lock_fd = os.open(str(lock_path), os.O_RDWR)\n"
                "    try:\n"
                "        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                "    except BlockingIOError:\n"
                "        os._exit(0)\n"
                "    os._exit(41)\n"
            )
        else:
            action = f"    os._exit({code})\n"
        script.write_text(
            "import importlib.util\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "RUNNER = Path(sys.argv[1])\n"
            "sys.argv = [str(RUNNER), *sys.argv[2:]]\n"
            "spec = importlib.util.spec_from_file_location("
            "'agent_orchestrator_interrupt', RUNNER)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "b1 = module.b1_module()\n"
            "def interrupt(*call_args, **call_kwargs):\n"
            f"{action}"
            f"setattr(b1, {target!r}, interrupt)\n"
            "raise SystemExit(module.main())\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [sys.executable, str(script), str(RUNNER), *args],
            capture_output=True,
            text=True,
            env=env or self.env,
            timeout=60,
            check=False,
        )

    def create_managed_args(
        self,
        plan_id: str = "b1-plan",
        workspace: Path | None = None,
        manifest: Path | None = None,
        title: str = "B1 managed plan",
        extra: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        return (
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(workspace or self.workspace),
            "--title",
            title,
            "--plan-id",
            plan_id,
            "--research-team",
            "--manifest-file",
            str(manifest or self.manifest_file),
            "--executor",
            "fake",
            "--json",
            *extra,
        )

    def wait_for_file(self, path: Path, timeout: float = 30.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.is_file():
                text = path.read_text(encoding="utf-8").strip()
                if text:
                    return text
            time.sleep(0.05)
        self.fail(f"Timed out waiting for {path}")

    def project_mode(self, env: dict[str, str] | None = None) -> None:
        self.run_cli(
            "preferences", "--workspace-mode", "project", "--json", env=env
        )

    def create_managed(
        self,
        plan_id: str = "b1-plan",
        workspace: Path | None = None,
        manifest: Path | None = None,
        expected: int = 0,
        extra: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
    ) -> dict[str, object]:
        self.project_mode(env)
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(workspace or self.workspace),
            "--title",
            "B1 managed plan",
            "--plan-id",
            plan_id,
            "--research-team",
            "--manifest-file",
            str(manifest or self.manifest_file),
            "--executor",
            "fake",
            "--json",
            *extra,
            expected=expected,
            env=env,
        )
        return json.loads(result.stdout) if expected == 0 else {}

    def checkpoint(
        self, plan_id: str = "b1-plan", env: dict[str, str] | None = None
    ) -> dict[str, object]:
        return json.loads(
            self.run_cli("plan-checkpoint", plan_id, "--json", env=env).stdout
        )

    def submit(
        self,
        plan_id: str,
        role: str,
        round_number: int,
        *,
        expected: int = 0,
        operation_id: str | None = None,
        retry_id: str | None = None,
        step_id: str = "step-one",
        env: dict[str, str] | None = None,
    ) -> dict[str, object]:
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
            str(
                self.proposal_files[role]
                if round_number == 1
                else self.cross_files[role]
            ),
            "--job-id",
            f"job-{role}",
            "--json",
        ]
        if operation_id:
            args.extend(["--operation-id", operation_id])
        if retry_id:
            args.extend(["--retry-id", retry_id])
        result = self.run_cli(*args, expected=expected, env=env)
        return json.loads(result.stdout) if expected == 0 else result

    def freeze(
        self,
        plan_id: str,
        objection_ids: list[str] | None = None,
        step_id: str = "step-one",
        env: dict[str, str] | None = None,
    ) -> str:
        path = self.candidate_file(
            [f"O{index:03d}" for index in range(1, len(objection_ids or []) + 1)]
            if objection_ids is not None
            else ["O001"]
        )
        result = self.run_cli(
            "consensus-freeze",
            "--plan-id",
            plan_id,
            "--step-id",
            step_id,
            "--candidate-file",
            str(path),
            "--json",
            env=env,
        )
        return str(json.loads(result.stdout)["frozen_digest"])

    def vote(
        self,
        plan_id: str,
        role: str,
        digest: str,
        vote: str = "AGREE",
        *,
        expected: int = 0,
        operation_id: str | None = None,
        step_id: str = "step-one",
        env: dict[str, str] | None = None,
        rationale: str | None = None,
    ) -> dict[str, object]:
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
            "--job-id",
            f"job-{role}",
            "--json",
        ]
        if rationale:
            args.extend(["--rationale", rationale])
        if operation_id:
            args.extend(["--operation-id", operation_id])
        result = self.run_cli(*args, expected=expected, env=env)
        return json.loads(result.stdout) if expected == 0 else result

    def complete_consensus(
        self,
        plan_id: str,
        votes: tuple[str, ...] = ("AGREE",) * 3,
        step_id: str = "step-one",
    ) -> str:
        for role in ROLES:
            self.submit(plan_id, role, 1, step_id=step_id)
        for role in ROLES:
            self.submit(plan_id, role, 2, step_id=step_id)
        digest = self.freeze(plan_id, step_id=step_id)
        for role, vote in zip(ROLES, votes):
            self.vote(plan_id, role, digest, vote, step_id=step_id)
        return digest

    def v1_manifest(self) -> dict[str, object]:
        return {
            "policy_version": 1,
            "steps": [
                {
                    "id": "step-one",
                    "objective": "Preserve the historical four-agent policy record.",
                    "scope": ["plugins/agent-orchestrator/scripts"],
                    "deliverables": ["historical replay"],
                    "acceptance_criteria": ["v1 history remains byte-stable"],
                    "depends_on": [],
                    "brief": dict(self.brief),
                }
            ],
        }

    def build_v1_ledger(
        self, plan_id: str = "v1-plan", workspace: Path | None = None
    ) -> str:
        """Build an authentic policy-version-1 ledger for historical tests.

        The events use the original v1 schema exactly: four roles, a binding
        without a roster, and the original four-role tally and vote order. The
        new module must replay this history unchanged while refusing mutation.
        """
        b1 = runner.b1_module()
        path = self.state / "plans" / plan_id
        path.mkdir(parents=True, exist_ok=True)
        plan_copy = path / "plan.md"
        plan_copy.write_text(self.plan_file.read_text(encoding="utf-8"), encoding="utf-8")
        (path / "plan.json").write_text(
            json.dumps({"managed": True, "historical": "original projection"}) + "\n",
            encoding="utf-8",
        )
        (path / "checkpoint.json").write_text(
            json.dumps({"historical": "original checkpoint"}) + "\n",
            encoding="utf-8",
        )
        manifest = self.v1_manifest()
        manifest_digest = b1._digest(manifest)
        plan_sha256 = hashlib.sha256(plan_copy.read_bytes()).hexdigest()
        canonical = str((workspace or self.workspace).resolve())
        payload = {
            "workspace": canonical,
            "canonical_workspace": canonical,
            "workspace_project_id": "p-historical-v1",
            "title": "Historical four-agent plan",
            "workspace_mode": "project",
            "plan_file": str(plan_copy),
            "plan_sha256": plan_sha256,
            "policy": {"name": b1.POLICY_NAME, "version": 1},
            "roles": list(V1_ROLES),
            "round_budget": 3,
            "manifest": manifest,
            "manifest_digest": manifest_digest,
            "goal": {
                "objective": "Keep the archived four-agent design intact.",
                "status": "active",
            },
            "team_policy": {
                "topology": "lead-worker",
                "max_parallel": 1,
                "native_subagents": "deny",
                "ownership": "agent-orchestrator",
            },
            "executor_policy": {"mode": "allowlist_only", "allowed": []},
        }

        def append(operation_id: str, spec: dict[str, object]) -> None:
            events_dir = path / "consensus" / "events"
            if b1._published_event_files(events_dir):
                state = b1.replay_events(path)
            else:
                state = {"events": []}
            b1._append_specs(
                path,
                state,
                [spec],
                operation_id,
                b1._digest({"operation_id": operation_id, "spec": spec}),
            )

        append(
            "v1-enroll",
            {
                "type": "plan_enrolled",
                "step_id": None,
                "cycle": 1,
                "round": None,
                "payload": payload,
            },
        )
        for role in V1_ROLES:
            append(
                f"v1-proposal-{role}",
                {
                    "type": "proposal_recorded",
                    "step_id": "step-one",
                    "cycle": 1,
                    "round": 1,
                    "payload": {
                        "role": role,
                        "provenance": {"job_id": f"v1-job-{role}", "leader": None},
                        "submission": self.proposal(),
                        "retry_id": None,
                    },
                },
            )
        for role in V1_ROLES:
            cross = {
                "responses": ["All four historical proposals were reviewed."],
                "challenges": (
                    [
                        {
                            "objection_id": "O001",
                            "objection": "Define recovery for a crash before projections.",
                            "severity": "major",
                        }
                    ]
                    if role == "codex"
                    else []
                ),
                "revisions": (
                    ["Regenerate computed views from the immutable ledger."]
                    if role == "codex"
                    else []
                ),
            }
            append(
                f"v1-cross-{role}",
                {
                    "type": "cross_examination_recorded",
                    "step_id": "step-one",
                    "cycle": 1,
                    "round": 2,
                    "payload": {
                        "role": role,
                        "provenance": {"job_id": f"v1-job-{role}", "leader": None},
                        "submission": cross,
                        "retry_id": None,
                    },
                },
            )
        candidate = self.candidate(["O001"])
        binding = {
            "policy": {"name": b1.POLICY_NAME, "version": 1},
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "manifest_digest": manifest_digest,
            "step_id": "step-one",
            "cycle": 1,
            "vote_round": 3,
            "dependency_references": [],
        }
        digest = b1._candidate_digest(binding, candidate)
        append(
            "v1-freeze",
            {
                "type": "candidate_frozen",
                "step_id": "step-one",
                "cycle": 1,
                "round": 3,
                "payload": {
                    "digest": digest,
                    "binding": binding,
                    "candidate": candidate,
                    "objection_ids": ["O001"],
                },
            },
        )
        for role in V1_ROLES:
            append(
                f"v1-vote-{role}",
                {
                    "type": "ballot_recorded",
                    "step_id": "step-one",
                    "cycle": 1,
                    "round": 3,
                    "payload": {
                        "role": role,
                        "vote": "AGREE",
                        "rationale": "historical four-agent agreement",
                        "digest": digest,
                        "provenance": {"job_id": f"v1-job-{role}", "leader": None},
                        "retry_id": None,
                    },
                },
            )
        append(
            "v1-consensus",
            {
                "type": "consensus_reached",
                "step_id": "step-one",
                "cycle": 1,
                "round": 3,
                "payload": {
                    "digest": digest,
                    "tally": {"AGREE": 4, "DISAGREE": 0, "NEEDS_DISCUSSION": 0},
                    "votes": [{"role": role, "vote": "AGREE"} for role in V1_ROLES],
                },
            },
        )
        names = (
            "DISCUSSION_BRIEF.md",
            "PROPOSAL_CODEX.md",
            "PROPOSAL_ANTIGRAVITY.md",
            "PROPOSAL_DEEPSEEK.md",
            "PROPOSAL_GLM.md",
            "DISCUSSION_LOG.md",
            "CONSENSUS.md",
        )
        for directory in (
            path / "steps" / "step-one",
            path / "steps" / "step-one" / "cycle-1",
        ):
            directory.mkdir(parents=True, exist_ok=True)
            for name in names:
                (directory / name).write_bytes(
                    f"ORIGINAL V1 {name}\n".encode("utf-8")
                )
        for name in (
            "proposals.md",
            "discussion-brief.md",
            "discussion-log.md",
            "consensus.md",
        ):
            (path / name).write_bytes(f"ORIGINAL V1 ROOT {name}\n".encode("utf-8"))
        return digest

    def extra_repo(self, name: str) -> Path:
        repo = self.root / name
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "worker@example.test")
        self.git(repo, "config", "user.name", "Worker")
        (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        self.git(repo, "add", "tracked.txt")
        self.git(repo, "commit", "-qm", "baseline")
        return repo

    def file_bytes(self, directory: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(directory)): path.read_bytes()
            for path in sorted(directory.rglob("*"))
            if path.is_file()
        }

    def test_managed_plan_creation_and_legacy_defaults(self) -> None:
        self.project_mode()
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace / "subdir"),
            "--title",
            "B1 managed plan",
            "--plan-id",
            "b1-plan",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
        )
        created = json.loads(result.stdout)
        self.assertTrue(created["managed"])
        self.assertEqual(created["canonical_workspace"], str(self.workspace.resolve()))
        self.assertEqual(created["workspace_project_id"][:2], "p-")
        self.assertEqual(created["policy"]["name"], "b1-durable-consensus")
        self.assertFalse(created["complete"])
        self.assertEqual(created["items"][0]["consensus_state"], "PROPOSALS_OPEN")
        status = self.run_cli("plan-status", "b1-plan").stdout
        self.assertIn("managed: true", status)
        self.assertIn("PROPOSALS_OPEN", status)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "IN_PROGRESS")
        self.assertTrue(checkpoint["missing_actions"])
        self.assertIn("record round 1 proposal from codex", checkpoint["next_action"])

        # Ordinary plans keep their existing behavior and are not managed.
        legacy_workspace = self.root / "legacy"
        legacy_workspace.mkdir()
        legacy = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(legacy_workspace),
            "--title",
            "Legacy plan",
            "--plan-id",
            "legacy-plan",
            "--executor",
            "fake",
            "--json",
        )
        legacy_plan = json.loads(legacy.stdout)
        self.assertNotIn("managed", legacy_plan)
        self.assertEqual(legacy_plan["items"][0]["state"], "pending")

    def test_research_team_requires_project_mode_and_git_identity(self) -> None:
        # Default workspace mode is worktree.
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Wrong mode",
            "--plan-id",
            "wrong-mode",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("project workspace mode", result.stderr)
        self.project_mode()
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.root),
            "--title",
            "No git",
            "--plan-id",
            "no-git",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("canonical Git workspace identity", result.stderr)
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "No manifest",
            "--plan-id",
            "no-manifest",
            "--research-team",
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("requires a structured --manifest-file", result.stderr)

    def test_manifest_and_plan_validation_rejects_unchecked_assumptions(self) -> None:
        self.project_mode()
        bad_manifests = {
            "unknown-version": {
                "policy_version": 3,
                "steps": self.manifest["steps"],
            },
            "evidence-key": {
                "policy_version": 2,
                "steps": [{**self.manifest["steps"][0], "status": "done"}],
            },
            "duplicate-step": {
                "policy_version": 2,
                "steps": [self.manifest["steps"][0], self.manifest["steps"][0]],
            },
            "later-dependency": {
                "policy_version": 2,
                "steps": [
                    {
                        **self.manifest["steps"][0],
                        "id": "step-one",
                        "depends_on": ["step-two"],
                    },
                    {**self.manifest["steps"][0], "id": "step-two"},
                ],
            },
            "short-objective": {
                "policy_version": 2,
                "steps": [{**self.manifest["steps"][0], "objective": "short"}],
            },
        }
        for name, manifest in bad_manifests.items():
            path = self.root / f"manifest-{name}.json"
            self.write_manifest(manifest, path)
            result = self.run_cli(
                "create-plan",
                "--plan-file",
                str(self.plan_file),
                "--workspace",
                str(self.workspace),
                "--title",
                name,
                "--plan-id",
                f"bad-{name}",
                "--research-team",
                "--manifest-file",
                str(path),
                "--executor",
                "fake",
                "--json",
                expected=2,
            )
            self.assertTrue(result.stderr.strip(), name)
        malformed = self.root / "manifest-malformed.json"
        malformed.write_text("{not json", encoding="utf-8")
        self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Malformed",
            "--plan-id",
            "bad-malformed",
            "--research-team",
            "--manifest-file",
            str(malformed),
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        checked_plan = self.root / "plan-checked.md"
        self.write_plan(checked_plan, checked=True)
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(checked_plan),
            "--workspace",
            str(self.workspace),
            "--title",
            "Prechecked",
            "--plan-id",
            "bad-prechecked",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("prechecked boxes", result.stderr)
        # None of the rejected attempts enrolled the workspace.
        self.assertFalse((self.state / "plans" / "bad-prechecked").exists())

    def test_unanimous_consensus_artifacts_and_post_consensus_gate(self) -> None:
        self.create_managed()
        for role in ROLES:
            self.submit("b1-plan", role, 1)
        for role in ROLES:
            self.submit("b1-plan", role, 2)
        digest = self.freeze("b1-plan")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "BALLOTS_OPEN")
        for role in ROLES:
            self.vote("b1-plan", role, digest, "AGREE")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "CONSENSUS_REACHED")
        self.assertEqual(checkpoint["implementation_gate"], "B1_FAIL_CLOSED_AWAITING_B2")
        self.assertEqual(
            checkpoint["steps"][0]["tally"],
            {"AGREE": 3, "DISAGREE": 0, "NEEDS_DISCUSSION": 0},
        )
        self.assertIn("B2", checkpoint["next_action"])
        plan = json.loads((self.state / "plans" / "b1-plan" / "plan.json").read_text())
        self.assertFalse(plan["complete"])
        self.assertEqual(plan["items"][0]["state"], "consensus_reached")
        self.assertEqual(plan["items"][0]["consensus_state"], "CONSENSUS_REACHED")

        plan_dir = self.state / "plans" / "b1-plan"
        proposals = (plan_dir / "proposals.md").read_text()
        for label in ("Codex", "DeepSeek", "GLM"):
            self.assertIn(f"## {label}", proposals)
        self.assertNotIn("Antigravity", proposals)
        brief = (plan_dir / "discussion-brief.md").read_text()
        self.assertIn("Round 1 proposals", brief)
        self.assertIn("O001", brief)
        log = (plan_dir / "discussion-log.md").read_text()
        self.assertIn("3 AGREE ballots frozen as consensus", log)
        consensus = (plan_dir / "consensus.md").read_text()
        self.assertIn("Final consensus", consensus)
        self.assertIn("Frozen digest", consensus)
        self.assertIn("All 3 roles explicitly AGREE", consensus)
        self.assertEqual(
            len(list((plan_dir / "consensus" / "events").glob("[0-9]*.json"))), 12
        )

        # A failed, missing, or stale vote can no longer change the settled plan.
        self.vote("b1-plan", "codex", digest, "AGREE", expected=2)
        self.run_cli(
            "consensus-freeze",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--candidate-file",
            str(self.candidate_file(["O001"])),
            "--json",
            expected=2,
        )
        # Post-consensus launches and legacy plan creation remain fail-closed.
        launch = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(self.workspace / "subdir"),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--allow-dirty",
            "--allow-concurrent-workspace",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("enrolled in managed research plan", launch.stderr)
        legacy = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Legacy bypass",
            "--plan-id",
            "legacy-bypass",
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("already enrolled", legacy.stderr)

    def test_dissent_requires_human_cycle_and_preserves_settled_evidence(self) -> None:
        self.create_managed()
        digest = self.complete_consensus(
            "b1-plan", votes=("AGREE", "AGREE", "DISAGREE")
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "HUMAN_DECISION_REQUIRED")
        self.assertEqual(checkpoint["steps"][0]["tally"]["DISAGREE"], 1)
        self.assertIn("human authorization", checkpoint["next_action"])
        consensus = (self.state / "plans" / "b1-plan" / "consensus.md").read_text()
        self.assertIn("No consensus", consensus)
        self.assertIn(digest, consensus)

        # The settled cycle cannot be re-voted or extended into a fourth round.
        self.vote("b1-plan", "codex", digest, "AGREE", expected=2)
        self.submit("b1-plan", "codex", 1, expected=2)
        # Only a recorded human authorization opens fresh discussion.
        self.run_cli(
            "consensus-new-cycle",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "Human owner",
            "--authorization",
            "I reviewed the dissent and authorize a fresh discussion cycle.",
            "--json",
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["cycle"], 2)
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "PROPOSALS_OPEN")
        closed = checkpoint["steps"][0]["closed_cycles"]
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]["cycle"], 1)
        self.assertEqual(closed[0]["outcome"], "HUMAN_DECISION_REQUIRED")
        self.assertEqual(closed[0]["digest"], digest)
        self.assertEqual(closed[0]["tally"]["DISAGREE"], 1)
        consensus = (self.state / "plans" / "b1-plan" / "consensus.md").read_text()
        self.assertIn("Preserved earlier cycles", consensus)
        # Fresh cycle accepts new round 1 receipts.
        self.submit("b1-plan", "codex", 1)
        self.assertEqual(self.checkpoint()["steps"][0]["proposal_roles"], ["codex"])
        for role in ("deepseek", "glm"):
            self.submit("b1-plan", role, 1)
        for role in ROLES:
            self.submit("b1-plan", role, 2)
        fresh_digest = self.freeze("b1-plan")
        # The same candidate content is bound to the new epoch, so old ballots
        # cannot be replayed against an equal-looking design.
        self.assertNotEqual(fresh_digest, digest)
        stale_cycle = self.vote(
            "b1-plan", "codex", digest, "AGREE", expected=2
        )
        self.assertIn("stale", stale_cycle.stderr)

    def test_needs_discussion_ballot_never_reaches_consensus(self) -> None:
        self.create_managed()
        digest = self.complete_consensus(
            "b1-plan", votes=("AGREE", "NEEDS_DISCUSSION", "AGREE")
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "HUMAN_DECISION_REQUIRED")
        self.assertEqual(
            checkpoint["steps"][0]["tally"]["NEEDS_DISCUSSION"], 1
        )
        self.assertNotEqual(checkpoint["steps"][0]["consensus_state"], "CONSENSUS_REACHED")
        self.assertEqual(checkpoint["steps"][0]["frozen_digest"], digest)

    def test_stale_duplicate_and_missing_votes_never_produce_consensus(self) -> None:
        self.create_managed()
        digest = self.complete_consensus_prologue("b1-plan")
        malformed = self.run_cli(
            "consensus-vote",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--digest",
            digest,
            "--vote",
            "MAYBE",
            "--json",
            expected=2,
        )
        self.assertIn("invalid choice", malformed.stderr)
        stale = "f" * 64
        result = self.vote("b1-plan", "codex", stale, "AGREE", expected=2)
        self.assertIn("stale", result.stderr)
        self.vote(
            "b1-plan",
            "codex",
            digest,
            "AGREE",
            operation_id="op-vote-codex-1",
        )
        duplicate = self.vote("b1-plan", "codex", digest, "DISAGREE", expected=2)
        self.assertIn("already voted", duplicate.stderr)
        conflict = self.vote(
            "b1-plan",
            "codex",
            digest,
            "DISAGREE",
            expected=2,
            operation_id="op-vote-codex-1",
        )
        self.assertIn("different content", conflict.stderr)
        retry = self.vote(
            "b1-plan",
            "codex",
            digest,
            "AGREE",
            operation_id="op-vote-codex-1",
        )
        self.assertTrue(retry["idempotent"])
        self.vote("b1-plan", "deepseek", digest, "AGREE")
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "BALLOTS_OPEN")
        self.assertEqual(
            checkpoint["steps"][0]["tally"],
            {"AGREE": 2, "DISAGREE": 0, "NEEDS_DISCUSSION": 0},
        )
        self.assertNotEqual(checkpoint["consensus_state"], "CONSENSUS_REACHED")
        self.assertTrue(
            any(
                "record round 3 ballot from glm" in action
                for action in checkpoint["missing_actions"]
            )
        )

    def complete_consensus_prologue(self, plan_id: str) -> str:
        for role in ROLES:
            self.submit(plan_id, role, 1)
        for role in ROLES:
            self.submit(plan_id, role, 2)
        return self.freeze(plan_id)

    def test_missing_provider_pause_resume_and_retry(self) -> None:
        self.create_managed()
        paused = json.loads(
            self.run_cli(
                "consensus-pause",
                "--plan-id",
                "b1-plan",
                "--step-id",
                "step-one",
                "--role",
                "deepseek",
                "--reason",
                "provider transport unavailable",
                "--guidance",
                "retry the same request after reconnecting",
                "--job-id",
                "job-deepseek",
                "--json",
            ).stdout
        )
        retry_id = paused["pause"]["retry_id"]
        checkpoint = self.checkpoint()
        self.assertTrue(
            any(
                "resume provider deepseek" in action
                for action in checkpoint["missing_actions"]
            )
        )
        blocked = self.submit("b1-plan", "deepseek", 1, expected=2)
        self.assertIn("paused", blocked.stderr)
        wrong = self.run_cli(
            "consensus-resume",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "deepseek",
            "--retry-id",
            "retry-wrong",
            "--json",
            expected=2,
        )
        self.assertIn("No open pause", wrong.stderr)
        self.run_cli(
            "consensus-resume",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "deepseek",
            "--retry-id",
            retry_id,
            "--json",
        )
        self.submit("b1-plan", "deepseek", 1)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["open_pauses"], [])
        self.assertEqual(checkpoint["steps"][0]["proposal_roles"], ["deepseek"])
        self.assertEqual(checkpoint["consensus_state"], "IN_PROGRESS")
        # A recorded retry ID can also clear the pause in the same submission.
        second = json.loads(
            self.run_cli(
                "consensus-pause",
                "--plan-id",
                "b1-plan",
                "--step-id",
                "step-one",
                "--role",
                "glm",
                "--reason",
                "second provider timed out",
                "--guidance",
                "retry once the provider reconnects",
                "--job-id",
                "job-glm",
                "--json",
            ).stdout
        )
        self.submit(
            "b1-plan", "glm", 1, retry_id=second["pause"]["retry_id"]
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["open_pauses"], [])
        self.assertEqual(
            checkpoint["steps"][0]["proposal_roles"], ["deepseek", "glm"]
        )

    def test_malformed_and_duplicate_submissions_are_rejected(self) -> None:
        self.create_managed()
        malformed = self.root / "malformed.json"
        malformed.write_text("{broken", encoding="utf-8")
        self.run_cli(
            "consensus-submit",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "1",
            "--submission-file",
            str(malformed),
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        missing = self.root / "missing-field.json"
        incomplete = self.proposal()
        del incomplete["risks"]
        missing.write_text(json.dumps(incomplete), encoding="utf-8")
        self.run_cli(
            "consensus-submit",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "1",
            "--submission-file",
            str(missing),
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        hollow = self.root / "hollow.json"
        hollow.write_text(json.dumps(self.proposal(approach="too short")), encoding="utf-8")
        self.run_cli(
            "consensus-submit",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "1",
            "--submission-file",
            str(hollow),
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        self.submit("b1-plan", "codex", 1)
        duplicate = self.submit("b1-plan", "codex", 1, expected=2)
        self.assertIn("already submitted", duplicate.stderr)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["proposal_roles"], ["codex"])
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "PROPOSALS_OPEN")

    def test_oversized_submission_is_rejected_before_publication(self) -> None:
        self.create_managed()
        oversized = self.root / "oversized.json"
        oversized.write_text(
            json.dumps(
                self.proposal(
                    assumptions=[f"assumption {index} " + "x" * 8000 for index in range(20)]
                )
            ),
            encoding="utf-8",
        )
        result = self.run_cli(
            "consensus-submit",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "1",
            "--submission-file",
            str(oversized),
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        self.assertIn("exceeds 32768 bytes", result.stderr)
        events = self.state / "plans" / "b1-plan" / "consensus" / "events"
        self.assertEqual(len(list(events.glob("[0-9]*.json"))), 1)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["proposal_roles"], [])
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "PROPOSALS_OPEN")

    def test_early_actions_are_blocked_until_the_protocol_stage_opens(self) -> None:
        self.create_managed()
        premature = self.run_cli(
            "consensus-vote",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--digest",
            "a" * 64,
            "--vote",
            "AGREE",
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        self.assertIn("expected BALLOTS_OPEN", premature.stderr)
        self.freeze_expected_failure("b1-plan")
        for role in ROLES:
            self.submit("b1-plan", role, 1)
        self.freeze_expected_failure("b1-plan")
        for role in ROLES:
            self.submit("b1-plan", role, 2)
        self.freeze("b1-plan")

    def freeze_expected_failure(self, plan_id: str) -> None:
        result = self.run_cli(
            "consensus-freeze",
            "--plan-id",
            plan_id,
            "--step-id",
            "step-one",
            "--candidate-file",
            str(self.candidate_file(["O001"])),
            "--json",
            expected=2,
        )
        self.assertIn("This action is unavailable at stage", result.stderr)

    def test_concurrent_and_restarted_submissions_are_durable(self) -> None:
        self.create_managed()
        processes = []
        for role in ("codex", "deepseek"):
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(RUNNER),
                        "consensus-submit",
                        "--plan-id",
                        "b1-plan",
                        "--step-id",
                        "step-one",
                        "--role",
                        role,
                        "--round",
                        "1",
                        "--submission-file",
                        str(self.proposal_files[role]),
                        "--job-id",
                        f"job-{role}",
                        "--operation-id",
                        f"op-{role}-1",
                        "--json",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=self.env,
                )
            )
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr or stdout)
        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["steps"][0]["proposal_roles"], ["codex", "deepseek"]
        )
        # An exact retry in a fresh process is idempotent.
        retried = self.submit(
            "b1-plan", "codex", 1, operation_id="op-codex-1"
        )
        self.assertTrue(retried["idempotent"])
        event_count = len(
            list(
                (self.state / "plans" / "b1-plan" / "consensus" / "events").glob(
                    "[0-9]*.json"
                )
            )
        )
        self.assertEqual(event_count, 3)  # enrollment + two proposals

    def test_corrupt_published_event_blocks_work_and_temp_files_are_ignored(
        self,
    ) -> None:
        self.create_managed()
        self.submit("b1-plan", "codex", 1)
        events = self.state / "plans" / "b1-plan" / "consensus" / "events"
        (events / ".000002.json.unpublished.tmp").write_text(
            "{partial", encoding="utf-8"
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["proposal_roles"], ["codex"])
        event = events / "000002.json"
        corrupted = json.loads(event.read_text())
        corrupted["payload"]["submission"]["approach"] = "tampered after publication"
        event.write_text(json.dumps(corrupted), encoding="utf-8")
        blocked = self.run_cli(
            "plan-checkpoint", "b1-plan", "--json", expected=2
        )
        self.assertIn("digest", blocked.stderr)
        (events / "unexpected-entry").write_text("x", encoding="utf-8")
        event.write_text(json.dumps(json.loads(event.read_text())), encoding="utf-8")

    def test_dependency_steps_require_unavailable_verified_merge_evidence(self) -> None:
        manifest = {
            "policy_version": 2,
            "steps": [
                self.manifest["steps"][0],
                {
                    "id": "step-two",
                    "objective": "Consume the independently verified merge receipt.",
                    "scope": ["plugins/agent-orchestrator/skills"],
                    "deliverables": ["dependent change"],
                    "acceptance_criteria": ["dependency evidence is verified"],
                    "depends_on": ["step-one"],
                    "brief": dict(self.brief),
                },
            ],
        }
        path = self.root / "manifest-dependent.json"
        self.write_manifest(manifest, path)
        self.create_managed(manifest=path)
        checkpoint = self.checkpoint()
        blocked = checkpoint["steps"][1]
        self.assertEqual(blocked["consensus_state"], "DEPENDENCY_BLOCKED")
        self.assertTrue(blocked["dependency_blockers"])
        self.assertTrue(
            any(
                "independently verified MERGED evidence" in reason
                for reason in blocked["blocked_reasons"]
            ),
            blocked["blocked_reasons"],
        )
        self.assertTrue(
            any(
                "cannot mint" in action or "no command that mints" in action
                for action in blocked["missing_actions"]
            ),
            blocked["missing_actions"],
        )
        events = self.state / "plans" / "b1-plan" / "consensus" / "events"
        baseline = len(list(events.glob("[0-9]*.json")))
        # Every public transition for the dependent step fails before any event
        # is published, before and after the predecessor reaches consensus.
        blocked_submit = self.submit(
            "b1-plan", "codex", 1, step_id="step-two", expected=2
        )
        self.assertIn("DEPENDENCY_BLOCKED", blocked_submit.stderr)
        self.assertIn("MERGE", blocked_submit.stderr.upper())
        freeze = self.run_cli(
            "consensus-freeze",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-two",
            "--candidate-file",
            str(self.candidate_file(["O001"])),
            "--json",
            expected=2,
        )
        self.assertIn("DEPENDENCY_BLOCKED", freeze.stderr)
        vote = self.vote(
            "b1-plan", "codex", "a" * 64, step_id="step-two", expected=2
        )
        self.assertIn("DEPENDENCY_BLOCKED", vote.stderr)
        pause = self.run_cli(
            "consensus-pause",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-two",
            "--role",
            "codex",
            "--reason",
            "provider unavailable for dependent step",
            "--guidance",
            "wait for the merge evidence gate",
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        self.assertIn("DEPENDENCY_BLOCKED", pause.stderr)
        resume = self.run_cli(
            "consensus-resume",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-two",
            "--role",
            "codex",
            "--retry-id",
            "retry-1",
            "--json",
            expected=2,
        )
        self.assertIn("DEPENDENCY_BLOCKED", resume.stderr)
        cycle = self.run_cli(
            "consensus-new-cycle",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-two",
            "--authorized-by",
            "Human owner",
            "--authorization",
            "This must not bypass the dependency gate.",
            "--json",
            expected=2,
        )
        self.assertIn("DEPENDENCY_BLOCKED", cycle.stderr)
        self.assertEqual(len(list(events.glob("[0-9]*.json"))), baseline)
        # Predecessor consensus is not merge evidence.
        self.complete_consensus("b1-plan")
        checkpoint = self.checkpoint()
        blocked = checkpoint["steps"][1]
        self.assertEqual(blocked["consensus_state"], "DEPENDENCY_BLOCKED")
        self.assertEqual(checkpoint["next_item"]["id"], "step-two")
        self.assertIn("MERGED", checkpoint["next_action"])
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "CONSENSUS_REACHED")
        after = len(list(events.glob("[0-9]*.json")))
        blocked_submit = self.submit(
            "b1-plan", "codex", 1, step_id="step-two", expected=2
        )
        self.assertIn("DEPENDENCY_BLOCKED", blocked_submit.stderr)
        self.assertEqual(len(list(events.glob("[0-9]*.json"))), after)

    def test_enrollment_event_alone_blocks_bypass_and_regenerates_views(self) -> None:
        self.create_managed()
        plan_dir = self.state / "plans" / "b1-plan"
        (plan_dir / "plan.json").unlink()
        # The published ledger, not the mutable projection or registry, still
        # owns this checkout. Remove every other admission breadcrumb too.
        (self.workspace / ".git" / "agent-orchestrator" / "enrollment.json").unlink()
        runner.write_json(
            self.state / "plans" / "enrollment.json",
            {"version": 1, "workspaces": {}},
        )
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Crash bypass",
            "--plan-id",
            "crash-bypass",
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("belongs to managed plan", result.stderr)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "IN_PROGRESS")
        self.assertTrue((plan_dir / "plan.json").is_file())
        self.assertTrue((plan_dir / "consensus.md").is_file())

        # A corrupt projection next to the valid first event must not fail open
        # for launch or worker admission (B1-004).
        (plan_dir / "plan.json").write_text("{broken", encoding="utf-8")
        launch = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(self.workspace),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("managed", launch.stderr)
        worker_job = self.state / "jobs" / "event-ledger-worker"
        runner.write_json(
            worker_job / "meta.json",
            {
                "job_id": "event-ledger-worker",
                "agent": "fake",
                "workspace": str(self.workspace),
                "plan_id": "b1-plan",
                "state": "starting",
            },
        )
        worker = subprocess.run(
            [sys.executable, str(RUNNER), "_worker", "--job-dir", str(worker_job)],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            check=False,
        )
        self.assertEqual(worker.returncode, 2, worker.stderr)
        self.assertIn("managed", worker.stderr)
        # The ledger remains authoritative and repairs the projection.
        checkpoint = self.checkpoint()
        self.assertTrue((plan_dir / "plan.json").is_file())
        self.assertNotIn("broken", (plan_dir / "plan.json").read_text())

    def test_blocked_premature_launch_with_alternate_flags_and_path_forms(self) -> None:
        self.create_managed()
        # Normal, override, and subdirectory launches are all refused.
        for workspace, overrides in (
            (self.workspace, ()),
            (
                self.workspace,
                (
                    "--allow-dirty",
                    "--allow-concurrent-workspace",
                    "--allow-unstructured-task",
                ),
            ),
            (self.workspace / "subdir", ("--allow-dirty", "--allow-unstructured-task")),
        ):
            result = self.run_cli(
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(workspace),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--no-notify",
                "--json",
                *overrides,
                expected=2,
            )
            self.assertIn("enrolled in managed research plan", result.stderr)
        planned = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--workspace",
            str(self.workspace),
            "--task-file",
            str(self.task_file),
            "--plan-id",
            "b1-plan",
            "--checklist-item",
            "step-one",
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("enrolled in managed research plan", planned.stderr)
        # A managed item cannot be accepted from an unrelated non-Git workspace.
        plain = self.root / "plain-launch"
        plain.mkdir()
        detached = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--workspace",
            str(plain),
            "--task-file",
            str(self.task_file),
            "--plan-id",
            "b1-plan",
            "--checklist-item",
            "step-one",
            "--allow-unstructured-task",
            "--allow-dirty",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("managed B1 research plan", detached.stderr)
        self.assertFalse(any((self.state / "jobs").glob("*")))

    def test_legacy_review_and_worker_cannot_bypass_managed_gate(self) -> None:
        self.create_managed()
        jobs = self.state / "jobs"
        review_job = jobs / "review-job"
        runner.write_json(
            review_job / "meta.json",
            {
                "job_id": "review-job",
                "agent": "fake",
                "cli": "fake",
                "workspace": str(self.workspace),
                "plan_id": "b1-plan",
                "checklist_item": "step-one",
                "state": "succeeded",
            },
        )
        runner.write_json(
            review_job / "result.json",
            {"state": "succeeded", "exit_code": 0},
        )
        review = self.run_cli(
            "record-review",
            "review-job",
            "--verdict",
            "accepted",
            "--reviewer",
            "Independent reviewer",
            "--test",
            "python3 -m unittest focused",
            "--json",
            expected=2,
        )
        self.assertIn("Managed research plans", review.stderr)
        plan = json.loads((self.state / "plans" / "b1-plan" / "plan.json").read_text())
        self.assertFalse(plan["complete"])
        self.assertEqual(plan["items"][0]["state"], "pending")

        worker_job = jobs / "worker-job"
        runner.write_json(
            worker_job / "meta.json",
            {
                "job_id": "worker-job",
                "agent": "fake",
                "workspace": str(self.workspace),
                "plan_id": "b1-plan",
                "state": "starting",
            },
        )
        worker = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "_worker",
                "--job-dir",
                str(worker_job),
            ],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            check=False,
        )
        self.assertEqual(worker.returncode, 2, worker.stderr)
        self.assertIn("managed", worker.stderr)
        result = json.loads((worker_job / "result.json").read_text())
        self.assertEqual(result["state"], "failed")
        self.assertIn("managed", result["blocked_reason"])

    def test_enrollment_cannot_replace_or_run_over_an_active_job(self) -> None:
        jobs = self.state / "jobs"
        runner.write_json(
            jobs / "active-job" / "meta.json",
            {
                "job_id": "active-job",
                "workspace": str(self.workspace / "subdir"),
                "canonical_workspace": str(self.workspace.resolve()),
                "state": "starting",
                # An admitted live job always records a process; a stale
                # starting record with no live process is terminal-for-admission
                # and must not wedge enrollment.
                "worker_pid": os.getpid(),
            },
        )
        self.project_mode()
        result = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Over active job",
            "--plan-id",
            "over-active",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("active job", result.stderr)
        runner.write_json(
            jobs / "active-job" / "result.json",
            {"state": "succeeded", "exit_code": 0},
        )
        active_meta = runner.read_json(jobs / "active-job" / "meta.json")
        active_meta["state"] = "succeeded"
        # A finished job's worker is gone; a leftover live PID would fail
        # closed as a possible orphan writer.
        active_meta.pop("worker_pid", None)
        runner.write_json(jobs / "active-job" / "meta.json", active_meta)
        self.create_managed()
        repeated = self.create_managed()
        self.assertTrue(repeated["idempotent"])
        conflicting = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Different title",
            "--plan-id",
            "b1-plan",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("different enrollment content", conflicting.stderr)
        # A second managed plan for the same canonical checkout is refused.
        self.create_managed(plan_id="b1-plan-two", expected=2)

    def test_enrollment_rejects_repository_reservation_and_prunes_dead_ones(
        self,
    ) -> None:
        b1 = runner.b1_module()
        identity = runner.canonical_workspace(self.workspace)
        reservation_dir = (
            self.workspace / ".git" / "agent-orchestrator" / "active-jobs"
        )
        b1.reserve_active_job(
            identity, "startup-job", self.state / "jobs" / "startup-job", os.getpid()
        )
        reservations = sorted(reservation_dir.glob("startup-job.*.json"))
        self.assertEqual(len(reservations), 1)
        startup_token = json.loads(reservations[0].read_text())["reservation_id"]
        self.project_mode()
        denied = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("startup-job", denied.stderr)
        self.assertFalse(self.plan_path().exists())
        b1.release_active_job(identity, "startup-job", startup_token)
        self.assertFalse(reservations[0].exists())

        # A reservation whose recorded processes are gone is stale and pruned;
        # it must not block enrollment forever.
        b1.reserve_active_job(
            identity, "dead-job", self.state / "jobs" / "dead-job", 999_999_999
        )
        dead = sorted(reservation_dir.glob("dead-job.*.json"))
        self.assertEqual(len(dead), 1)
        self.assertTrue(dead[0].is_file())
        created = self.create_managed()
        self.assertFalse(created["idempotent"])
        self.assertFalse(dead[0].exists())

    def test_enrollment_detects_live_job_from_another_state_home(self) -> None:
        barrier = self.root / "provider-ready"
        sleepy = self.root / "sleepy-agents.json"
        script = (
            "import os, sys, time\n"
            "from pathlib import Path\n"
            "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8')\n"
            "time.sleep(120)\n"
        )
        sleepy.write_text(
            json.dumps(
                {
                    "agents": {
                        "sleepy": {
                            "argv": [sys.executable, "-c", script, str(barrier)],
                            "prompt_transport": "stdin",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        env_b = self.alternate_env()
        launched = self.run_cli(
            "launch",
            "--cli",
            "sleepy",
            "--config",
            str(sleepy),
            "--approved-executor",
            "sleepy",
            "--workspace",
            str(self.workspace),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            "--job-id",
            "sleepy-job",
            env=env_b,
        )
        self.assertEqual(json.loads(launched.stdout)["job_id"], "sleepy-job")
        provider_pid = int(self.wait_for_file(barrier))
        reservation_dir = (
            self.workspace / ".git" / "agent-orchestrator" / "active-jobs"
        )

        def record_has_provider() -> bool:
            records = list(reservation_dir.glob("sleepy-job.*.json"))
            if len(records) != 1:
                return False
            try:
                return (
                    json.loads(records[0].read_text()).get("provider_pid")
                    == provider_pid
                )
            except (OSError, json.JSONDecodeError):
                return False

        self.wait_until(record_has_provider)
        records = list(reservation_dir.glob("sleepy-job.*.json"))
        reservation = records[0]
        record = json.loads(reservation.read_text())
        self.assertEqual(record["job_id"], "sleepy-job")
        self.assertEqual(record["provider_pid"], provider_pid)
        self.assertIsNotNone(record["worker_pid"])
        self.assertEqual(
            reservation.name, f"sleepy-job.{record['reservation_id']}.json"
        )

        # Enrollment from a different state home is refused while the provider
        # admitted through state home B is alive.
        self.project_mode()
        denied = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("active job", denied.stderr)
        self.assertIn("sleepy-job", denied.stderr)
        self.assertFalse(self.plan_path().exists())

        # True process termination: stop the provider, the worker releases the
        # reservation, and the same checkout can then be enrolled.
        os.kill(provider_pid, signal.SIGTERM)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and reservation.exists():
            time.sleep(0.1)
        self.assertFalse(reservation.exists(), "reservation was not released")
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def reservation_dir(self) -> Path:
        return self.workspace / ".git" / "agent-orchestrator" / "active-jobs"

    def sleepy_config(self, name: str, seconds: float, ready: Path) -> Path:
        script = (
            "import os, sys, time\n"
            "from pathlib import Path\n"
            "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8')\n"
            f"time.sleep({seconds})\n"
        )
        path = self.root / f"agents-{name}.json"
        path.write_text(
            json.dumps(
                {
                    "agents": {
                        name: {
                            "argv": [sys.executable, "-c", script, str(ready)],
                            "prompt_transport": "stdin",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        return path

    def launch_sleepy(
        self,
        env: dict[str, str],
        name: str,
        seconds: float,
        job_id: str,
        ready: Path,
        expected: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "launch",
            "--cli",
            name,
            "--config",
            str(self.sleepy_config(name, seconds, ready)),
            "--approved-executor",
            name,
            "--workspace",
            str(self.workspace),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            "--job-id",
            job_id,
            expected=expected,
            env=env,
        )

    def kill_pid(self, pid: int) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return

    def wait_until(self, condition, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.05)
        self.fail("Timed out waiting for condition")

    def test_identical_job_ids_in_independent_state_homes_keep_separate_reservations(
        self,
    ) -> None:
        """B2: one repository lease serializes writers across state homes.

        The B1 ownership token remains unique per admitted launch, but two
        writers may no longer hold the same checkout at once: the second state
        home is refused by the stable repository writer lease even when it uses
        the same job ID.  After the first supervisor proves completion, the
        second state home acquires a fresh epoch/token and releases only its
        own record.
        """
        env_b = self.alternate_env("state-two")
        env_c = self.alternate_env("state-three")
        ready_long = self.root / "ready-long"
        ready_short = self.root / "ready-short"
        self.launch_sleepy(self.env, "long-job", 10, "same-job", ready_long)
        long_pid = int(self.wait_for_file(ready_long))
        self.addCleanup(self.kill_pid, long_pid)

        records = sorted(self.reservation_dir().glob("same-job.*.json"))
        self.assertEqual(len(records), 1, records)
        first_token = json.loads(records[0].read_text())["reservation_id"]

        # A second writer through another state home is refused before it can
        # publish a competing reservation; the override flag cannot bypass it.
        denied = self.launch_sleepy(
            env_b, "short-job", 2, "same-job", ready_short, expected=2
        )
        self.assertIn("writer lease", denied.stderr)
        self.assertEqual(
            len(list(self.reservation_dir().glob("same-job.*.json"))), 1
        )

        self.project_mode(env_c)
        blocked = self.run_cli(*self.create_managed_args(), expected=2, env=env_c)
        self.assertTrue(
            "lease" in blocked.stderr.lower()
            or "active job" in blocked.stderr.lower(),
            blocked.stderr,
        )
        self.assertFalse((self.root / "state-three" / "plans" / "b1-plan").exists())

        # True process termination drains the supervisor, writes completion and
        # releases the record. A sequential launch from the other state home
        # then gets a distinct ownership token.
        os.kill(long_pid, signal.SIGTERM)
        self.wait_for_file(self.state / "jobs" / "same-job" / "result.json", timeout=45)
        self.wait_until(lambda: not any(self.reservation_dir().glob("same-job.*.json")))

        self.launch_sleepy(env_b, "short-job", 2, "same-job", ready_short)
        short_pid = int(self.wait_for_file(ready_short))
        self.addCleanup(self.kill_pid, short_pid)
        records = sorted(self.reservation_dir().glob("same-job.*.json"))
        self.assertEqual(len(records), 1, records)
        second_token = json.loads(records[0].read_text())["reservation_id"]
        self.assertNotEqual(first_token, second_token)
        os.kill(short_pid, signal.SIGTERM)
        self.wait_for_file(
            self.root / "state-two" / "jobs" / "same-job" / "result.json", timeout=45
        )
        self.wait_until(lambda: not any(self.reservation_dir().glob("same-job.*.json")))

        # With every writer drained, the third state home can enroll.
        created = self.create_managed(env=env_c)
        self.assertFalse(created["idempotent"])

    def test_reservation_release_and_update_are_bound_to_ownership_token(self) -> None:
        b1 = runner.b1_module()
        identity = runner.canonical_workspace(self.workspace)
        first = b1.reserve_active_job(
            identity, "shared-job", self.state / "jobs" / "first", os.getpid()
        )
        second = b1.reserve_active_job(
            identity, "shared-job", self.state / "jobs" / "second", os.getpid()
        )
        assert first and second
        first_path = self.reservation_dir() / f"shared-job.{first}.json"
        second_path = self.reservation_dir() / f"shared-job.{second}.json"
        self.assertNotEqual(first, second)
        self.assertTrue(first_path.is_file() and second_path.is_file())

        # Releasing the first record leaves the second (live) record intact.
        b1.release_active_job(identity, "shared-job", first)
        self.assertFalse(first_path.exists())
        self.assertTrue(second_path.is_file())
        # A release with a foreign or missing token never removes another
        # launch's record, and a mismatched job ID never resolves one.
        b1.release_active_job(identity, "shared-job", first)
        b1.release_active_job(identity, "other-job", second)
        self.assertTrue(second_path.is_file())
        b1.register_job_process(
            identity,
            "other-job",
            "worker",
            os.getpid(),
            reservation_id=second,
        )
        self.assertTrue(second_path.is_file())
        self.assertEqual(list(self.reservation_dir().glob("other-job.*.json")), [])
        # Post-Popen registration is update-only: it cannot resurrect the
        # record a worker already released.
        b1.register_job_process(
            identity,
            "shared-job",
            "worker",
            os.getpid(),
            reservation_id=first,
        )
        self.assertFalse(first_path.exists())

        # Conflicting releases in either order: the surviving record keeps
        # blocking enrollment until it is released itself.
        self.project_mode()
        denied = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("shared-job", denied.stderr)
        b1.release_active_job(identity, "shared-job", second)
        self.assertFalse(second_path.exists())

        third = b1.reserve_active_job(
            identity, "later-job", self.state / "jobs" / "third", os.getpid()
        )
        fourth = b1.reserve_active_job(
            identity, "later-job", self.state / "jobs" / "fourth", os.getpid()
        )
        assert third and fourth
        third_path = self.reservation_dir() / f"later-job.{third}.json"
        fourth_path = self.reservation_dir() / f"later-job.{fourth}.json"
        # Release in the opposite order.
        b1.release_active_job(identity, "later-job", fourth)
        self.assertFalse(fourth_path.exists())
        self.assertTrue(third_path.is_file())
        b1.release_active_job(identity, "later-job", third)
        self.assertFalse(third_path.exists())

        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_legacy_reservation_files_are_read_and_pruned_safely(self) -> None:
        identity = runner.canonical_workspace(self.workspace)
        directory = self.reservation_dir()
        directory.mkdir(parents=True, exist_ok=True)
        legacy_path = directory / "old-job.json"

        def legacy(coordinator_pid: int) -> dict[str, object]:
            now = "2026-01-01T00:00:00+00:00"
            return {
                "version": 1,
                "job_id": "old-job",
                "canonical_workspace": identity["root"],
                "git_common_dir": identity["git_common_dir"],
                "state_home": str(self.state),
                "plans_dir": str(self.state / "plans"),
                "job_dir": str(self.state / "jobs" / "old-job"),
                "coordinator_pid": coordinator_pid,
                "worker_pid": None,
                "provider_pid": None,
                "created_at": now,
                "updated_at": now,
            }

        runner.write_json(legacy_path, legacy(os.getpid()))
        self.project_mode()
        denied = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("old-job", denied.stderr)
        self.assertFalse(self.plan_path().exists())

        # New code never owns legacy records; a dead one is pruned by replay.
        # Older fallback records may carry an empty job directory; they must
        # still be prunable instead of bricking the checkout.
        dead = legacy(999_999_999)
        dead["job_dir"] = ""
        runner.write_json(legacy_path, dead)
        created = self.create_managed()
        self.assertFalse(created["idempotent"])
        self.assertFalse(legacy_path.exists())

    def test_worker_restart_preserves_provider_and_creates_valid_record(self) -> None:
        job_id = "unreserved-job"
        job = self.state / "jobs" / job_id
        job.mkdir(parents=True)
        (job / "task.md").write_text("do bounded work\n", encoding="utf-8")
        ready = self.root / "unreserved-ready"
        profiles = runner.load_profiles(self.sleepy_config("sleepy", 120, ready))
        runner.write_json(
            job / "meta.json",
            {
                "job_id": job_id,
                "agent": "sleepy",
                "profile": profiles["sleepy"],
                "workspace": str(self.workspace),
                "state": "starting",
                "timeout_seconds": 60,
                "notify": False,
                "scope": {},
                "git_baseline": {},
            },
        )
        worker = subprocess.Popen(
            [sys.executable, str(RUNNER), "_worker", "--job-dir", str(job)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.env,
            start_new_session=True,
        )
        self.addCleanup(self.kill_pid, worker.pid)
        provider_pid = int(self.wait_for_file(ready))
        self.addCleanup(self.kill_pid, provider_pid)

        def record_is_complete() -> bool:
            records = list(self.reservation_dir().glob(f"{job_id}.*.json"))
            if len(records) != 1:
                return False
            try:
                candidate = json.loads(records[0].read_text())
            except (OSError, json.JSONDecodeError):
                return False
            return (
                candidate.get("provider_pid") == provider_pid
                and isinstance(candidate.get("worker_pid"), int)
                and candidate.get("version") == 2
            )

        self.wait_until(record_is_complete)
        record_path = list(self.reservation_dir().glob(f"{job_id}.*.json"))[0]
        record = json.loads(record_path.read_text())
        self.assertEqual(record["version"], 2)
        self.assertEqual(
            record_path.name, f"{job_id}.{record['reservation_id']}.json"
        )
        self.assertEqual(record["job_dir"], str(job.resolve()))
        self.assertTrue(Path(record["plans_dir"]).is_absolute())
        self.assertEqual(record["provider_pid"], provider_pid)
        self.assertGreater(record["worker_pid"], 0)
        self.assertEqual(record["coordinator_pid"], None)
        meta = runner.read_json(job / "meta.json")
        self.assertEqual(meta["reservation_id"], record["reservation_id"])

        # A legitimate restart (same job record, live old provider) updates the
        # worker slot of the same reservation and preserves provider occupancy.
        restart_pid = os.getpid()
        b1 = runner.b1_module()
        identity = runner.canonical_workspace(self.workspace)
        b1.register_job_process(
            identity,
            job_id,
            "worker",
            restart_pid,
            reservation_id=record["reservation_id"],
            job_dir=job,
        )
        restarted = json.loads(record_path.read_text())
        self.assertEqual(restarted["worker_pid"], restart_pid)
        self.assertEqual(restarted["provider_pid"], provider_pid)

        # Hard-kill the worker without release: the valid record stays and is
        # pruned once every recorded process has exited. The simulated restart
        # PID above belongs to this test process, so replace it with a dead PID.
        b1.register_job_process(
            identity,
            job_id,
            "worker",
            999_999_999,
            reservation_id=record["reservation_id"],
        )
        os.kill(worker.pid, signal.SIGKILL)
        worker.wait(timeout=10)
        self.kill_pid(provider_pid)
        created = self.create_managed()
        self.assertFalse(created["idempotent"])
        self.assertFalse(record_path.exists())

    def test_launch_does_not_overwrite_fast_worker_terminal_state(self) -> None:
        """AG-R2-001/002: a worker that releases first cannot be resurrected."""
        args = runner.build_parser().parse_args(
            [
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(self.workspace),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--no-notify",
                "--json",
                "--job-id",
                "fast-job",
            ]
        )
        runner.validate_cli_args(args)
        job = self.state / "jobs" / "fast-job"

        def fast_supervisor(argv, **kwargs):
            job_dir = Path(argv[argv.index("--job-dir") + 1])
            descriptor = int(argv[argv.index("--lock-fd") + 1])
            epoch = argv[argv.index("--epoch") + 1]
            meta = runner.read_json(job_dir / "meta.json")
            identity = runner.canonical_workspace(Path(meta["workspace"]))
            b2 = runner.b2_module()
            # Adopt the inherited locked descriptor exactly like the real
            # supervisor, then prove completion before releasing.
            b2.supervisor_attach(descriptor, epoch, job_dir)
            result = {
                "state": "succeeded",
                "started_at": runner.utc_now(),
                "finished_at": runner.utc_now(),
                "duration_seconds": 0.0,
                "exit_code": 0,
                "timed_out": False,
                "scope_violations": [],
                "usage_summary": None,
            }
            with runner.record_lock(job_dir / "meta.json"):
                runner.write_json(job_dir / "result.json", result)
                meta.update(result)
                runner.write_json(job_dir / "meta.json", meta)
            runner.b1_module().release_active_job(
                identity, meta["job_id"], meta["reservation_id"]
            )
            b2.mark_lease_completed(
                identity,
                epoch,
                job_id=meta["job_id"],
                final_check={
                    "state": "clean",
                    "violations": [],
                    "evidence": str(job_dir / "final-check.json"),
                    "finished_at": runner.utc_now(),
                },
            )
            return type("FakeProcess", (), {"pid": os.getpid()})()

        real_popen = subprocess.Popen

        def intercept(argv, *args, **kwargs):
            # ``subprocess.run`` also goes through Popen; only replace the
            # detached worker spawn under test.
            if isinstance(argv, (list, tuple)) and "--job-dir" in argv:
                return fast_supervisor(argv, **kwargs)
            return real_popen(argv, *args, **kwargs)

        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ), mock.patch.object(runner.subprocess, "Popen", side_effect=intercept):
            self.assertEqual(runner.command_launch(args), 0)

        result = runner.read_json(job / "result.json")
        meta = runner.read_json(job / "meta.json")
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(meta["state"], "succeeded")
        self.assertEqual(list(self.reservation_dir().glob("fast-job.*.json")), [])
        # The terminal result is authoritative for admission in this state home.
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_failed_worker_spawn_records_failure_and_releases_reservation(
        self,
    ) -> None:
        args = runner.build_parser().parse_args(
            [
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(self.workspace),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--no-notify",
                "--json",
                "--job-id",
                "failed-spawn",
            ]
        )
        runner.validate_cli_args(args)
        job = self.state / "jobs" / "failed-spawn"
        real_popen = subprocess.Popen

        def intercept(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and "--job-dir" in argv:
                raise OSError("spawn denied")
            return real_popen(argv, *args, **kwargs)

        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ), mock.patch.object(runner.subprocess, "Popen", side_effect=intercept):
            with self.assertRaises(OSError):
                runner.command_launch(args)

        result = runner.read_json(job / "result.json")
        meta = runner.read_json(job / "meta.json")
        self.assertEqual(result["state"], "failed")
        self.assertIn("spawn denied", result["startup_error"])
        self.assertEqual(meta["state"], "failed")
        self.assertEqual(list(self.reservation_dir().glob("failed-spawn.*.json")), [])
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_dead_starting_job_does_not_wedge_enrollment(self) -> None:
        dead_job = self.state / "jobs" / "dead-starting"
        runner.write_json(
            dead_job / "meta.json",
            {
                "job_id": "dead-starting",
                "workspace": str(self.workspace),
                "canonical_workspace": str(self.workspace.resolve()),
                "state": "starting",
                "worker_pid": 999_999_999,
            },
        )
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_terminal_result_with_live_orphan_provider_still_blocks(self) -> None:
        orphan = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.addCleanup(self.kill_pid, orphan.pid)
        job = self.state / "jobs" / "orphan-provider"
        runner.write_json(
            job / "meta.json",
            {
                "job_id": "orphan-provider",
                "workspace": str(self.workspace),
                "canonical_workspace": str(self.workspace.resolve()),
                "state": "succeeded",
                "worker_pid": 999_999_999,
                "provider_pid": orphan.pid,
            },
        )
        runner.write_json(job / "result.json", {"state": "succeeded"})
        self.project_mode()
        denied = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("orphan-provider", denied.stderr)
        self.kill_pid(orphan.pid)
        orphan.wait(timeout=10)
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def plan_path(self, plan_id: str = "b1-plan") -> Path:
        return self.state / "plans" / plan_id

    def event_paths(self, plan_id: str = "b1-plan") -> list[Path]:
        return sorted(
            (self.plan_path(plan_id) / "consensus" / "events").glob("[0-9]*.json")
        )

    def alternate_env(self, name: str = "state-two") -> dict[str, str]:
        env = dict(self.env)
        env["AGENT_ORCHESTRATOR_HOME"] = str(self.root / name)
        return env

    def test_second_state_home_cannot_admit_enrolled_checkout(self) -> None:
        env_a = self.env
        self.create_managed(env=env_a)
        marker = self.workspace / ".git" / "agent-orchestrator" / "enrollment.json"
        self.assertTrue(marker.is_file())
        env_b = self.alternate_env()
        # A different supported state home sees the repository-level marker.
        for workspace in (self.workspace, self.workspace / "subdir"):
            for overrides in (
                (),
                (
                    "--allow-dirty",
                    "--allow-concurrent-workspace",
                    "--allow-unstructured-task",
                ),
            ):
                launch = self.run_cli(
                    "launch",
                    "--cli",
                    "fake",
                    "--config",
                    str(self.agents_config),
                    "--approved-executor",
                    "fake",
                    "--workspace",
                    str(workspace),
                    "--task-file",
                    str(self.task_file),
                    "--allow-unstructured-task",
                    "--no-notify",
                    "--json",
                    *overrides,
                    expected=2,
                    env=env_b,
                )
                self.assertIn("enrolled in managed research plan", launch.stderr)
        link = self.root / "repo-link"
        link.symlink_to(self.workspace, target_is_directory=True)
        linked = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(link),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
            env=env_b,
        )
        self.assertIn("enrolled in managed research plan", linked.stderr)
        legacy = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Alternate home legacy",
            "--plan-id",
            "alternate-legacy",
            "--executor",
            "fake",
            "--json",
            expected=2,
            env=env_b,
        )
        self.assertIn("already enrolled", legacy.stderr)
        self.project_mode(env_b)
        second = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Alternate home managed",
            "--plan-id",
            "alternate-managed",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
            expected=2,
            env=env_b,
        )
        self.assertIn("already enrolled", second.stderr)
        # Worker entry in the second home also fails closed.
        worker_job = self.root / "state-two" / "jobs" / "alternate-worker"
        runner.write_json(
            worker_job / "meta.json",
            {
                "job_id": "alternate-worker",
                "agent": "fake",
                "workspace": str(self.workspace),
                "state": "starting",
            },
        )
        worker = subprocess.run(
            [sys.executable, str(RUNNER), "_worker", "--job-dir", str(worker_job)],
            capture_output=True,
            text=True,
            env=env_b,
            timeout=30,
            check=False,
        )
        self.assertEqual(worker.returncode, 2, worker.stderr)
        result = json.loads((worker_job / "result.json").read_text())
        self.assertEqual(result["state"], "failed")
        self.assertIn("enrolled in managed plan", result["blocked_reason"])
        self.assertFalse(any((self.root / "state-two" / "jobs").glob("job-*")))

        # A linked worktree of the same repository resolves to one identity.
        worktree = self.root / "linked-worktree"
        self.git(
            self.workspace,
            "worktree",
            "add",
            "-q",
            str(worktree),
            "-b",
            "linked-worktree",
        )
        worktree_launch = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(worktree),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
            env=env_b,
        )
        self.assertIn("enrolled in managed research plan", worktree_launch.stderr)

    def test_canonical_workspace_distinct_repositories_and_git_errors(self) -> None:
        identity = runner.canonical_workspace(self.workspace)
        self.assertTrue(identity["is_git"])
        self.assertEqual(identity["root"], str(self.workspace.resolve()))
        self.assertEqual(identity["git_common_dir"], str(self.workspace / ".git"))
        for form in (self.workspace / "subdir",):
            self.assertEqual(
                runner.canonical_workspace(form)["root"], identity["root"]
            )
        link = self.root / "identity-link"
        link.symlink_to(self.workspace, target_is_directory=True)
        self.assertEqual(runner.canonical_workspace(link)["root"], identity["root"])
        worktree = self.root / "identity-worktree"
        self.git(
            self.workspace,
            "worktree",
            "add",
            "-q",
            str(worktree),
            "-b",
            "identity-worktree",
        )
        self.assertEqual(
            runner.canonical_workspace(worktree)["root"], identity["root"]
        )

        first = self.bare_worktree("first")
        second = self.bare_worktree("second")
        first_identity = runner.canonical_workspace(first)
        second_identity = runner.canonical_workspace(second)
        self.assertTrue(first_identity["is_git"])
        self.assertTrue(first_identity["is_work_tree"])
        self.assertTrue(second_identity["is_git"])
        self.assertNotEqual(first_identity["root"], second_identity["root"])
        self.assertNotEqual(first_identity["project_id"], second_identity["project_id"])
        # A bare repository and the linked worktree share one repository root.
        bare = self.root / "first.git"
        bare_identity = runner.canonical_workspace(bare)
        self.assertTrue(bare_identity["is_git"])
        self.assertFalse(bare_identity["is_work_tree"])
        self.assertEqual(bare_identity["root"], first_identity["root"])
        # The Git administrative directory and its children belong to the same
        # canonical repository identity, but are not usable work trees.
        for form in (self.workspace / ".git", self.workspace / ".git" / "hooks"):
            admin = runner.canonical_workspace(form)
            self.assertTrue(admin["is_git"], form)
            self.assertFalse(admin["is_work_tree"], form)
            self.assertEqual(admin["root"], identity["root"], form)
            self.assertEqual(admin["git_common_dir"], identity["git_common_dir"], form)
        self.assertFalse(runner.canonical_workspace(bare)["is_work_tree"])

        plain = self.root / "plain-directory"
        plain.mkdir()
        self.assertFalse(runner.canonical_workspace(plain)["is_git"])
        with mock.patch.object(
            runner.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("git", 10),
        ):
            with self.assertRaises(runner.RunnerError):
                runner.canonical_workspace(self.workspace)

    def separate_git_dir_checkout(self, name: str) -> tuple[Path, Path]:
        base = self.root / name
        checkout = base / "checkout"
        gitdir = base / "gitdir"
        base.mkdir()
        self.git(
            self.root,
            "init",
            "-q",
            f"--separate-git-dir={gitdir}",
            str(checkout),
        )
        self.git(checkout, "config", "user.email", "worker@example.test")
        self.git(checkout, "config", "user.name", "Worker")
        (checkout / "file.txt").write_text(name + "\n", encoding="utf-8")
        self.git(checkout, "add", "file.txt")
        self.git(checkout, "commit", "-qm", "baseline")
        return checkout, gitdir

    def add_submodule(self, superproject: Path, source: Path, relative: str) -> Path:
        self.git(
            superproject,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(source),
            relative,
        )
        return superproject / relative

    def source_repository(self, name: str) -> Path:
        source = self.root / name
        source.mkdir()
        self.git(source, "init", "-q")
        self.git(source, "config", "user.email", "worker@example.test")
        self.git(source, "config", "user.name", "Worker")
        (source / "file.txt").write_text(name + "\n", encoding="utf-8")
        self.git(source, "add", "file.txt")
        self.git(source, "commit", "-qm", "baseline")
        return source

    def test_canonical_identity_unifies_separate_git_dir_administrative_paths(
        self,
    ) -> None:
        checkout, gitdir = self.separate_git_dir_checkout("sep-one")
        identity = runner.canonical_workspace(checkout)
        self.assertTrue(identity["is_work_tree"])
        self.assertEqual(identity["root"], str(gitdir.resolve()))
        self.assertEqual(identity["git_common_dir"], str(gitdir.resolve()))
        for form in (gitdir, gitdir / "hooks", gitdir / "refs"):
            admin = runner.canonical_workspace(form)
            self.assertTrue(admin["is_git"], form)
            self.assertFalse(admin["is_work_tree"], form)
            self.assertEqual(admin["root"], identity["root"], form)
            self.assertEqual(admin["project_id"], identity["project_id"], form)
            self.assertEqual(admin["git_common_dir"], identity["git_common_dir"], form)

        # Sibling separate-git-dir checkouts share a parent but never an
        # identity.
        second_checkout, second_gitdir = self.separate_git_dir_checkout("sep-two")
        second = runner.canonical_workspace(second_checkout)
        self.assertNotEqual(second["root"], identity["root"])
        self.assertNotEqual(second["project_id"], identity["project_id"])
        self.assertNotEqual(
            runner.canonical_workspace(second_gitdir)["root"], identity["root"]
        )

    def test_canonical_identity_unifies_submodule_administrative_paths(self) -> None:
        source = self.source_repository("sub-source-one")
        other_source = self.source_repository("sub-source-two")
        superproject = self.root / "super-one"
        superproject.mkdir()
        self.git(superproject, "init", "-q")
        self.git(superproject, "config", "user.email", "worker@example.test")
        self.git(superproject, "config", "user.name", "Worker")
        (superproject / "root.txt").write_text("root\n", encoding="utf-8")
        self.git(superproject, "add", "root.txt")
        self.git(superproject, "commit", "-qm", "baseline")
        nested = self.add_submodule(superproject, source, "nested/one")
        other = self.add_submodule(superproject, other_source, "nested/two")
        gitdir = superproject / ".git" / "modules" / "nested" / "one"
        other_gitdir = superproject / ".git" / "modules" / "nested" / "two"
        identity = runner.canonical_workspace(nested)
        self.assertTrue(identity["is_work_tree"])
        self.assertEqual(identity["root"], str(gitdir.resolve()))
        for form in (gitdir, gitdir / "hooks"):
            admin = runner.canonical_workspace(form)
            self.assertTrue(admin["is_git"], form)
            self.assertFalse(admin["is_work_tree"], form)
            self.assertEqual(admin["root"], identity["root"], form)
            self.assertEqual(admin["project_id"], identity["project_id"], form)
        other_identity = runner.canonical_workspace(other)
        self.assertNotEqual(other_identity["root"], identity["root"])
        self.assertEqual(other_identity["root"], str(other_gitdir.resolve()))
        # The superproject keeps its own distinct identity.
        super_identity = runner.canonical_workspace(superproject)
        self.assertNotEqual(super_identity["root"], identity["root"])
        self.assertEqual(super_identity["root"], str(superproject.resolve()))

    def test_separate_git_dir_managed_admission_covers_administrative_paths(
        self,
    ) -> None:
        checkout, gitdir = self.separate_git_dir_checkout("sep-enrolled")
        self.create_managed(plan_id="separate-plan", workspace=checkout)
        forms = (gitdir, gitdir / "hooks")
        for form in forms:
            launch = self.run_cli(
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(form),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--allow-dirty",
                "--allow-concurrent-workspace",
                "--no-notify",
                "--json",
                expected=2,
            )
            self.assertIn("enrolled in managed research plan", launch.stderr, form)
            legacy = self.run_cli(
                "create-plan",
                "--plan-file",
                str(self.plan_file),
                "--workspace",
                str(form),
                "--title",
                "Separate admin legacy",
                "--plan-id",
                "separate-legacy",
                "--executor",
                "fake",
                "--json",
                expected=2,
            )
            self.assertIn("already enrolled", legacy.stderr, form)
            managed = self.run_cli(
                *self.create_managed_args(
                    plan_id="separate-managed", workspace=form
                ),
                expected=2,
            )
            self.assertIn(
                "Git administrative directory or bare repository", managed.stderr
            )
            worker_job = self.state / "jobs" / f"sep-worker-{form.name}"
            runner.write_json(
                worker_job / "meta.json",
                {
                    "job_id": worker_job.name,
                    "agent": "fake",
                    "workspace": str(form),
                    "state": "starting",
                },
            )
            worker = subprocess.run(
                [sys.executable, str(RUNNER), "_worker", "--job-dir", str(worker_job)],
                capture_output=True,
                text=True,
                env=self.env,
                timeout=30,
                check=False,
            )
            self.assertEqual(worker.returncode, 2, worker.stderr)
            self.assertNotIn("Traceback", worker.stderr)
            result = json.loads((worker_job / "result.json").read_text())
            self.assertIn("enrolled in managed plan", result["blocked_reason"])

        # The published ledger in this state home is authoritative even when
        # the repository marker and the state-home registry entry are removed:
        # administrative forms stay closed.
        (gitdir / "agent-orchestrator" / "enrollment.json").unlink()
        (self.state / "plans" / "enrollment.json").unlink()
        for form in forms:
            launch = self.run_cli(
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(form),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--allow-dirty",
                "--allow-concurrent-workspace",
                "--no-notify",
                "--json",
                expected=2,
            )
            self.assertIn("belongs to managed research plan", launch.stderr, form)

    def test_submodule_managed_admission_covers_administrative_paths(self) -> None:
        source = self.source_repository("sub-admission-source")
        superproject = self.root / "super-admission"
        superproject.mkdir()
        self.git(superproject, "init", "-q")
        self.git(superproject, "config", "user.email", "worker@example.test")
        self.git(superproject, "config", "user.name", "Worker")
        (superproject / "root.txt").write_text("root\n", encoding="utf-8")
        self.git(superproject, "add", "root.txt")
        self.git(superproject, "commit", "-qm", "baseline")
        submodule = self.add_submodule(superproject, source, "nested/one")
        gitdir = superproject / ".git" / "modules" / "nested" / "one"
        self.create_managed(plan_id="sub-plan", workspace=submodule)
        for form in (gitdir, gitdir / "hooks"):
            launch = self.run_cli(
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(form),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--allow-dirty",
                "--allow-concurrent-workspace",
                "--no-notify",
                "--json",
                expected=2,
            )
            self.assertIn("enrolled in managed research plan", launch.stderr, form)
            legacy = self.run_cli(
                "create-plan",
                "--plan-file",
                str(self.plan_file),
                "--workspace",
                str(form),
                "--title",
                "Submodule admin legacy",
                "--plan-id",
                "sub-legacy",
                "--executor",
                "fake",
                "--json",
                expected=2,
            )
            self.assertIn("already enrolled", legacy.stderr, form)
            managed = self.run_cli(
                *self.create_managed_args(plan_id="sub-managed", workspace=form),
                expected=2,
            )
            self.assertIn(
                "Git administrative directory or bare repository", managed.stderr
            )
            worker_job = self.state / "jobs" / f"sub-worker-{form.name}"
            runner.write_json(
                worker_job / "meta.json",
                {
                    "job_id": worker_job.name,
                    "agent": "fake",
                    "workspace": str(form),
                    "state": "starting",
                },
            )
            worker = subprocess.run(
                [sys.executable, str(RUNNER), "_worker", "--job-dir", str(worker_job)],
                capture_output=True,
                text=True,
                env=self.env,
                timeout=30,
                check=False,
            )
            self.assertEqual(worker.returncode, 2, worker.stderr)
            result = json.loads((worker_job / "result.json").read_text())
            self.assertIn("enrolled in managed plan", result["blocked_reason"])

        # Ledger-only fallback: the marker and state registry entry may be
        # absent, but the administrative forms still stay closed.
        (gitdir / "agent-orchestrator" / "enrollment.json").unlink()
        (self.state / "plans" / "enrollment.json").unlink()
        fallback = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(gitdir / "hooks"),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--allow-dirty",
            "--allow-concurrent-workspace",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("belongs to managed research plan", fallback.stderr)

    def test_bare_repository_probe_failures_fail_closed(self) -> None:
        admin = self.workspace / ".git"
        real_run = subprocess.run

        def timeout_run(command: list[str], **kwargs: object) -> object:
            if "--is-bare-repository" in command:
                raise subprocess.TimeoutExpired(command, 10)
            return real_run(command, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(runner.subprocess, "run", side_effect=timeout_run):
            with self.assertRaises(runner.RunnerError):
                runner.canonical_workspace(admin)
            blocked = runner.b1_module().worker_block_reason(
                {"workspace": str(admin)}
            )
        self.assertIsNotNone(blocked)
        self.assertIn("Admission state unavailable", str(blocked))
        self.assertIn("Timed out", str(blocked))

        def failing_run(command: list[str], **kwargs: object) -> object:
            if "--is-bare-repository" in command:
                return subprocess.CompletedProcess(
                    command, 128, "", "fatal: bare probe failed"
                )
            return real_run(command, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(runner.subprocess, "run", side_effect=failing_run):
            with self.assertRaises(runner.RunnerError) as caught:
                runner.canonical_workspace(admin)
        self.assertIn("bare probe failed", str(caught.exception))

    def test_canonical_workspace_git_environment_is_locale_stable(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []
        real_run = subprocess.run

        def spy(command: list[str], **kwargs: object) -> object:
            calls.append((list(command), dict(kwargs)))
            return real_run(command, **kwargs)  # type: ignore[arg-type]

        plain = self.root / "plain-locale"
        plain.mkdir()
        with mock.patch.object(runner.subprocess, "run", side_effect=spy):
            runner.canonical_workspace(self.workspace)
            runner.canonical_workspace(plain)
        rev_parse_calls = [
            (command, kwargs)
            for command, kwargs in calls
            if "rev-parse" in command
        ]
        self.assertTrue(rev_parse_calls)
        for command, kwargs in rev_parse_calls:
            environment = kwargs.get("env") or {}
            self.assertEqual(environment.get("LC_ALL"), "C", command)
            self.assertEqual(environment.get("LANGUAGE"), "C", command)

    def test_git_administrative_paths_and_bare_repositories_fail_closed(self) -> None:
        self.create_managed()
        forms = (self.workspace / ".git", self.workspace / ".git" / "hooks")
        for form in forms:
            launch = self.run_cli(
                "launch",
                "--cli",
                "fake",
                "--config",
                str(self.agents_config),
                "--approved-executor",
                "fake",
                "--workspace",
                str(form),
                "--task-file",
                str(self.task_file),
                "--allow-unstructured-task",
                "--allow-dirty",
                "--allow-concurrent-workspace",
                "--no-notify",
                "--json",
                expected=2,
            )
            self.assertIn("enrolled in managed research plan", launch.stderr)
            legacy = self.run_cli(
                "create-plan",
                "--plan-file",
                str(self.plan_file),
                "--workspace",
                str(form),
                "--title",
                "Admin directory legacy",
                "--plan-id",
                "admin-legacy",
                "--executor",
                "fake",
                "--json",
                expected=2,
            )
            self.assertIn("already enrolled", legacy.stderr)
            managed = self.run_cli(
                *self.create_managed_args(
                    plan_id="admin-managed", workspace=form
                ),
                expected=2,
            )
            self.assertIn(
                "Git administrative directory or bare repository", managed.stderr
            )
            worker_job = self.state / "jobs" / f"admin-worker-{form.name}"
            runner.write_json(
                worker_job / "meta.json",
                {
                    "job_id": worker_job.name,
                    "agent": "fake",
                    "workspace": str(form),
                    "state": "starting",
                },
            )
            worker = subprocess.run(
                [sys.executable, str(RUNNER), "_worker", "--job-dir", str(worker_job)],
                capture_output=True,
                text=True,
                env=self.env,
                timeout=30,
                check=False,
            )
            self.assertEqual(worker.returncode, 2, worker.stderr)
            result = json.loads((worker_job / "result.json").read_text())
            self.assertIn("enrolled in managed plan", result["blocked_reason"])

        # A bare repository whose linked worktree is enrolled keeps the same
        # canonical identity and admission surface.
        seed = self.root / "bare-seed"
        seed.mkdir()
        self.git(seed, "init", "-q")
        self.git(seed, "config", "user.email", "worker@example.test")
        self.git(seed, "config", "user.name", "Worker")
        (seed / "file.txt").write_text("bare\n", encoding="utf-8")
        self.git(seed, "add", "file.txt")
        self.git(seed, "commit", "-qm", "baseline")
        bare = self.root / "enrolled.git"
        self.git(self.root, "init", "--bare", "-q", str(bare))
        self.git(seed, "remote", "add", "origin", str(bare))
        self.git(seed, "push", "-q", "origin", "HEAD:main")
        worktree = self.root / "enrolled-worktree"
        self.git(bare, "worktree", "add", "-q", str(worktree), "main")
        self.create_managed(plan_id="bare-plan", workspace=worktree)

        launch = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(bare),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--allow-dirty",
            "--allow-concurrent-workspace",
            "--no-notify",
            "--json",
            expected=2,
        )
        self.assertIn("enrolled in managed research plan", launch.stderr)
        legacy = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(bare),
            "--title",
            "Bare legacy",
            "--plan-id",
            "bare-legacy",
            "--executor",
            "fake",
            "--json",
            expected=2,
        )
        self.assertIn("already enrolled", legacy.stderr)
        managed = self.run_cli(
            *self.create_managed_args(plan_id="bare-managed", workspace=bare),
            expected=2,
        )
        self.assertIn("Git administrative directory or bare repository", managed.stderr)
        bare_worker = self.state / "jobs" / "bare-worker"
        runner.write_json(
            bare_worker / "meta.json",
            {
                "job_id": "bare-worker",
                "agent": "fake",
                "workspace": str(bare),
                "state": "starting",
            },
        )
        worker = subprocess.run(
            [sys.executable, str(RUNNER), "_worker", "--job-dir", str(bare_worker)],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            check=False,
        )
        self.assertEqual(worker.returncode, 2, worker.stderr)
        result = json.loads((bare_worker / "result.json").read_text())
        self.assertIn("enrolled in managed plan", result["blocked_reason"])

    def bare_worktree(self, name: str) -> Path:
        seed = self.root / f"seed-{name}"
        seed.mkdir()
        self.git(seed, "init", "-q")
        self.git(seed, "config", "user.email", "worker@example.test")
        self.git(seed, "config", "user.name", "Worker")
        (seed / "file.txt").write_text(name + "\n", encoding="utf-8")
        self.git(seed, "add", "file.txt")
        self.git(seed, "commit", "-qm", "baseline")
        bare = self.root / f"{name}.git"
        self.git(self.root, "init", "--bare", "-q", str(bare))
        self.git(seed, "remote", "add", "origin", str(bare))
        self.git(seed, "push", "-q", "origin", "HEAD:main")
        worktree = self.root / f"wt-{name}"
        self.git(bare, "worktree", "add", "-q", str(worktree), "main")
        return worktree

    def test_per_step_cycle_artifact_bundle_and_brief_immutability(self) -> None:
        manifest = {
            "policy_version": 2,
            "steps": [
                {
                    **self.manifest["steps"][0],
                    "id": "step-one",
                    "depends_on": [],
                },
                {
                    "id": "step-two",
                    "objective": "Second independent step with its own evidence.",
                    "scope": ["plugins/agent-orchestrator/skills"],
                    "deliverables": ["second artifact bundle"],
                    "acceptance_criteria": ["second bundle is complete"],
                    "depends_on": [],
                    "brief": dict(self.brief),
                },
            ],
        }
        path = self.root / "manifest-two-steps.json"
        self.write_manifest(manifest, path)
        self.create_managed(manifest=path)
        plan_dir = self.plan_path()
        names = (
            "DISCUSSION_BRIEF.md",
            "PROPOSAL_CODEX.md",
            "PROPOSAL_DEEPSEEK.md",
            "PROPOSAL_GLM.md",
            "DISCUSSION_LOG.md",
            "CONSENSUS.md",
        )
        for step_id in ("step-one", "step-two"):
            directory = plan_dir / "steps" / step_id
            for name in names:
                self.assertTrue((directory / name).is_file(), (step_id, name))
        brief_before = (plan_dir / "steps" / "step-one" / "DISCUSSION_BRIEF.md").read_text()
        self.assertIn("DISCUSSION BRIEF", brief_before)
        self.assertIn("Round 1", brief_before)
        # The coordinator-authored brief is captured before round one and
        # reproduced verbatim, not synthesized from the step metadata.
        for field, value in self.brief.items():
            values = value if isinstance(value, list) else [value]
            for item in values:
                self.assertIn(item, brief_before, field)
        # The archived enrollment event carries the same immutable brief.
        enrolled = json.loads(self.event_paths()[0].read_text())
        self.assertEqual(
            enrolled["payload"]["manifest"]["steps"][0]["brief"], self.brief
        )
        for role in ROLES:
            self.submit("b1-plan", role, 1, step_id="step-one")
        for role in ROLES:
            self.submit("b1-plan", role, 2, step_id="step-one")
        digest = self.freeze("b1-plan", step_id="step-one")
        for role in ROLES:
            self.vote(
                "b1-plan",
                role,
                digest,
                step_id="step-one",
                rationale=f"{role} accepts the frozen design for step one",
            )
        self.complete_consensus("b1-plan", step_id="step-two")
        brief_after = (plan_dir / "steps" / "step-one" / "DISCUSSION_BRIEF.md").read_text()
        self.assertEqual(brief_after, brief_before)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "CONSENSUS_REACHED")
        artifacts = checkpoint["step_artifacts"]
        self.assertEqual(
            sorted(artifacts["step-one"]["files"]), sorted(names)
        )
        for step_id in ("step-one", "step-two"):
            for size in artifacts[step_id]["files"].values():
                self.assertTrue(Path(size).is_file(), size)
            for cycle in artifacts[step_id]["cycles"].values():
                self.assertTrue(Path(cycle["directory"]).is_dir())
                for size in cycle["files"].values():
                    self.assertTrue(Path(size).is_file(), size)
        proposal = (plan_dir / "steps" / "step-one" / "PROPOSAL_DEEPSEEK.md").read_text()
        self.assertIn("Provenance: `job-deepseek`", proposal)
        self.assertIn("Persist immutable ordered event files", proposal)
        log = (plan_dir / "steps" / "step-one" / "DISCUSSION_LOG.md").read_text()
        self.assertIn("Regenerate computed views on every checkpoint.", log)
        self.assertIn('"provenance"', log)
        consensus = (plan_dir / "steps" / "step-one" / "CONSENSUS.md").read_text()
        digest = checkpoint["steps"][0]["frozen_digest"]
        self.assertIn("Final consensus", consensus)
        self.assertIn(digest, consensus)
        self.assertIn("job-codex", consensus)
        self.assertIn("codex accepts the frozen design for step one", consensus)
        log = (plan_dir / "steps" / "step-one" / "DISCUSSION_LOG.md").read_text()
        self.assertIn("codex accepts the frozen design for step one", log)
        self.assertIn("CONSENSUS.md", checkpoint["step_artifacts"]["step-one"]["cycles"]["1"]["files"])

        # Deleting every computed artifact bundle is recoverable from the ledger.
        shutil.rmtree(plan_dir / "steps")
        for name in ("plan.json", "checkpoint.json", "proposals.md", "discussion-brief.md", "discussion-log.md", "consensus.md"):
            (plan_dir / name).unlink()
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["consensus_state"], "CONSENSUS_REACHED")
        for step_id in ("step-one", "step-two"):
            directory = plan_dir / "steps" / step_id
            for name in names:
                self.assertTrue((directory / name).is_file(), (step_id, name))
        self.assertEqual(
            (plan_dir / "steps" / "step-one" / "DISCUSSION_BRIEF.md").read_text(),
            brief_before,
        )

    def test_cycle_two_preserves_cycle_one_bundle(self) -> None:
        self.create_managed()
        digest = self.complete_consensus(
            "b1-plan", votes=("AGREE", "AGREE", "DISAGREE", "AGREE")
        )
        plan_dir = self.plan_path()
        cycle_one = plan_dir / "steps" / "step-one" / "cycle-1"
        names = (
            "DISCUSSION_BRIEF.md",
            "PROPOSAL_CODEX.md",
            "PROPOSAL_DEEPSEEK.md",
            "PROPOSAL_GLM.md",
            "DISCUSSION_LOG.md",
            "CONSENSUS.md",
        )
        before = {name: (cycle_one / name).read_bytes() for name in names}
        self.assertIn(digest, (cycle_one / "CONSENSUS.md").read_text())
        self.assertIn("No consensus", (cycle_one / "CONSENSUS.md").read_text())
        self.assertIn(
            "Regenerate computed views on every checkpoint.",
            (cycle_one / "DISCUSSION_LOG.md").read_text(),
        )
        self.run_cli(
            "consensus-new-cycle",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "Human owner",
            "--authorization",
            "I reviewed the dissent and authorize cycle two.",
            "--json",
        )
        # Closed per-cycle bundles are deterministic and stay byte-identical.
        for name in names:
            self.assertEqual((cycle_one / name).read_bytes(), before[name], name)
        cycle_two = plan_dir / "steps" / "step-one" / "cycle-2"
        for name in names:
            self.assertTrue((cycle_two / name).is_file(), name)
        brief = (cycle_two / "DISCUSSION_BRIEF.md").read_text()
        self.assertIn("Human owner", brief)
        self.assertIn("human authorization", brief)
        # The original coordinator brief is preserved across cycles.
        for value in self.brief.values():
            for item in value if isinstance(value, list) else [value]:
                self.assertIn(item, brief)
        self.assertEqual(
            (cycle_one / "DISCUSSION_BRIEF.md").read_bytes(), before["DISCUSSION_BRIEF.md"]
        )
        log = (cycle_two / "DISCUSSION_LOG.md").read_text()
        self.assertIn("new_cycle_authorized", log)
        self.assertIn("I reviewed the dissent and authorize cycle two.", log)
        self.submit("b1-plan", "codex", 1)
        for name in names:
            self.assertEqual((cycle_one / name).read_bytes(), before[name], name)
        consent = (cycle_one / "PROPOSAL_CODEX.md").read_text()
        self.assertIn("Persist immutable ordered event files", consent)

    def test_authorized_new_cycle_reopens_unanimous_consensus(self) -> None:
        self.create_managed()
        first = self.complete_consensus("b1-plan")
        self.assertEqual(self.checkpoint()["consensus_state"], "CONSENSUS_REACHED")
        self.vote("b1-plan", "codex", first, "AGREE", expected=2)
        self.freeze_expected_failure("b1-plan")
        self.run_cli(
            "consensus-new-cycle",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "Human owner",
            "--authorization",
            "Amend the settled design and run a fresh three-role cycle.",
            "--json",
        )
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["cycle"], 2)
        self.assertEqual(checkpoint["steps"][0]["consensus_state"], "PROPOSALS_OPEN")
        closed = checkpoint["steps"][0]["closed_cycles"]
        self.assertEqual(closed[0]["outcome"], "CONSENSUS_REACHED")
        self.assertEqual(closed[0]["digest"], first)
        for role in ROLES:
            self.submit("b1-plan", role, 1)
        for role in ROLES:
            self.submit("b1-plan", role, 2)
        second = self.freeze("b1-plan")
        self.assertNotEqual(first, second)
        stale = self.vote("b1-plan", "codex", first, "AGREE", expected=2)
        self.assertIn("stale", stale.stderr)
        for role in ROLES:
            self.vote("b1-plan", role, second, "AGREE")
        self.assertEqual(self.checkpoint()["consensus_state"], "CONSENSUS_REACHED")
        cycle_one = (
            self.plan_path() / "steps" / "step-one" / "cycle-1" / "CONSENSUS.md"
        ).read_text()
        self.assertIn("Final consensus", cycle_one)
        self.assertIn(first, cycle_one)

    def test_crash_before_first_event_is_recoverable_by_owner_request(self) -> None:
        identity = runner.canonical_workspace(self.workspace)
        meta_dir = Path(identity["git_common_dir"]) / "agent-orchestrator"
        self.project_mode()
        # Genuine interruption after the intent and staging exist but before the
        # first durable event: os._exit skips every cleanup block.
        interrupted = self.run_cli_with_hook(
            self.create_managed_args(), "_append_specs", code=23
        )
        self.assertEqual(interrupted.returncode, 23, interrupted.stderr)
        plan_dir = self.plan_path()
        self.assertFalse(plan_dir.exists())
        intent = runner.read_json(meta_dir / "intent.json")
        self.assertEqual(
            Path(intent["plans_dir"]).resolve(), (self.state / "plans").resolve()
        )
        self.assertRegex(intent["request_digest"], r"^[0-9a-f]{64}$")
        staging = self.state / "plans" / intent["staging"]
        self.assertTrue((staging / ".b1-staging.json").is_file())

        env_b = self.alternate_env()
        blocked = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(self.workspace),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            expected=2,
            env=env_b,
        )
        self.assertIn("incomplete managed enrollment", blocked.stderr)

        # Simulate a crash in the middle of writing the staging marker: only an
        # unpublished dot temporary file remains in the staging directory.
        shutil.rmtree(staging / "consensus")
        (staging / ".b1-staging.json").unlink()
        (staging / "plan.md").unlink()
        (staging / "manifest.json").unlink()
        (staging / ".b1-staging.json.deadbeef.tmp").write_text(
            "partial marker\n", encoding="utf-8"
        )
        # An unrecognized file is never deleted: recovery fails closed until the
        # operator removes the unrelated state.
        (staging / "unrelated.txt").write_text("keep me\n", encoding="utf-8")
        refused = self.run_cli(
            *self.create_managed_args(), expected=2
        )
        self.assertIn("unrecognized staging directory", refused.stderr)
        self.assertTrue((staging / "unrelated.txt").is_file())
        (staging / "unrelated.txt").unlink()

        created = self.create_managed()
        self.assertFalse(created["idempotent"])
        self.assertFalse(staging.exists())
        self.assertFalse((staging.parent).exists())
        self.assertFalse((meta_dir / "intent.json").exists())
        self.assertTrue((meta_dir / "enrollment.json").is_file())
        self.assertEqual(len(self.event_paths()), 1)

    def test_crash_after_first_event_before_marker_is_recoverable(self) -> None:
        identity = runner.canonical_workspace(self.workspace)
        meta_dir = Path(identity["git_common_dir"]) / "agent-orchestrator"
        self.project_mode()
        # Genuine interruption after the plan directory is atomically published
        # with its first event but before the repository marker, registry and
        # projections are reconciled.
        interrupted = self.run_cli_with_hook(
            self.create_managed_args(), "_write_repo_marker", code=24
        )
        self.assertEqual(interrupted.returncode, 24, interrupted.stderr)
        plan_dir = self.plan_path()
        self.assertEqual(len(self.event_paths()), 1)
        self.assertTrue((meta_dir / "intent.json").is_file())
        self.assertFalse((meta_dir / "enrollment.json").exists())
        # A published plan must never carry unpublished staging scaffolding.
        self.assertFalse((plan_dir / ".b1-staging.json").exists())
        self.assertEqual(list((self.state / "plans").glob(".enroll-*")), [])

        retried = self.create_managed()
        self.assertTrue(retried["idempotent"])
        self.assertFalse((meta_dir / "intent.json").exists())
        self.assertTrue((meta_dir / "enrollment.json").is_file())
        self.assertTrue((self.state / "plans" / "enrollment.json").is_file())
        self.assertEqual(len(self.event_paths()), 1)
        self.checkpoint()

    def test_interrupted_enrollment_is_owned_by_one_state_home_and_request(self) -> None:
        identity = runner.canonical_workspace(self.workspace)
        meta_dir = Path(identity["git_common_dir"]) / "agent-orchestrator"
        self.project_mode()
        interrupted = self.run_cli_with_hook(
            self.create_managed_args(), "_write_repo_marker", code=25
        )
        self.assertEqual(interrupted.returncode, 25, interrupted.stderr)
        self.assertTrue((meta_dir / "intent.json").is_file())
        self.assertEqual(len(self.event_paths()), 1)

        # Another supported state home must not reconcile or clear the intent,
        # even for the same plan ID and a different manifest.
        env_b = self.alternate_env()
        self.project_mode(env_b)
        altered_manifest = self.root / "manifest-altered.json"
        altered = {
            "policy_version": 2,
            "steps": [
                {
                    **self.manifest["steps"][0],
                    "objective": "A different step objective for the same plan ID.",
                }
            ],
        }
        self.write_manifest(altered, altered_manifest)
        second_home = self.run_cli(
            *self.create_managed_args(manifest=altered_manifest),
            expected=2,
            env=env_b,
        )
        self.assertIn("owned by state home", second_home.stderr)
        self.assertIn(str(self.state.resolve()), second_home.stderr)
        self.assertFalse((self.root / "state-two" / "plans" / "b1-plan").exists())
        self.assertEqual(len(self.event_paths()), 1)
        self.assertTrue((meta_dir / "intent.json").is_file())

        # The owner also rejects different content and keeps the intent.
        conflicting = self.run_cli(
            *self.create_managed_args(manifest=altered_manifest),
            expected=2,
        )
        self.assertIn("different create-plan content", conflicting.stderr)
        self.assertTrue((meta_dir / "intent.json").is_file())
        self.assertEqual(len(self.event_paths()), 1)

        # The exact original request from the owner reconciles idempotently.
        retried = self.create_managed()
        self.assertTrue(retried["idempotent"])
        self.assertFalse((meta_dir / "intent.json").exists())
        self.assertEqual(len(self.event_paths()), 1)
        self.assertTrue((meta_dir / "enrollment.json").is_file())
        self.checkpoint()

    def test_ledger_filename_round_and_encoding_validation(self) -> None:
        self.create_managed()
        self.submit("b1-plan", "codex", 1)
        events = self.plan_path() / "consensus" / "events"
        second = events / "000002.json"
        original = second.read_text()
        second.rename(events / "000099.json")
        mismatch = self.run_cli("plan-checkpoint", "b1-plan", "--json", expected=2)
        self.assertIn("does not match its ordered sequence", mismatch.stderr)
        (events / "000099.json").rename(second)
        second.write_bytes(b"\xff\xfe")
        corrupted = self.run_cli("plan-checkpoint", "b1-plan", "--json", expected=2)
        self.assertIn("Cannot read valid JSON", corrupted.stderr)
        self.assertNotIn("Traceback", corrupted.stderr)
        second.write_text(original, encoding="utf-8")
        self.checkpoint()

        for role in ("deepseek", "glm"):
            self.submit("b1-plan", role, 1)
        for role in ROLES:
            self.submit("b1-plan", role, 2)
        digest = self.freeze("b1-plan")
        for role in ROLES:
            self.vote("b1-plan", role, digest, "AGREE")
        last = self.event_paths()[-1]
        tampered = json.loads(last.read_text())
        self.assertEqual(tampered["type"], "consensus_reached")
        tampered["round"] = 1
        tampered.pop("digest")
        tampered["digest"] = hashlib.sha256(
            json.dumps(
                tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        last.write_text(json.dumps(tampered), encoding="utf-8")
        invalid_round = self.run_cli(
            "plan-checkpoint", "b1-plan", "--json", expected=2
        )
        self.assertIn("round 3", invalid_round.stderr)

    def test_manifest_scope_string_bounds_replay_identically(self) -> None:
        self.project_mode()
        meta_dir = self.workspace / ".git" / "agent-orchestrator"
        oversized = {
            "policy_version": 2,
            "steps": [{**self.manifest["steps"][0], "scope": "x" * 2500}],
        }
        oversized_path = self.root / "manifest-scope-too-long.json"
        self.write_manifest(oversized, oversized_path)
        rejected = self.run_cli(
            *self.create_managed_args(manifest=oversized_path), expected=2
        )
        self.assertIn("2048", rejected.stderr)
        self.assertFalse(self.plan_path().exists())
        self.assertFalse((meta_dir / "intent.json").exists())
        self.assertEqual(list((self.state / "plans").glob(".enroll-*")), [])

        boundary = {
            "policy_version": 2,
            "steps": [{**self.manifest["steps"][0], "scope": "a" * 2048}],
        }
        boundary_path = self.root / "manifest-scope-boundary.json"
        self.write_manifest(boundary, boundary_path)
        created = self.create_managed(
            plan_id="scope-plan", manifest=boundary_path
        )
        self.assertEqual(created["items"][0]["scope"], ["a" * 2048])
        # Replay in a fresh process must accept the normalized one-item list
        # with exactly the same bound as the original string.
        checkpoint = self.checkpoint("scope-plan")
        self.assertEqual(checkpoint["steps"][0]["scope"], ["a" * 2048])
        self.assertEqual(self.checkpoint("scope-plan")["plan_id"], "scope-plan")

    def test_oversized_enrollment_failure_cleans_intent_and_staging(self) -> None:
        self.project_mode()
        meta_dir = self.workspace / ".git" / "agent-orchestrator"
        big_plan = self.root / "big-plan.md"
        self.write_plan(big_plan, goal="G" * 70_000)
        args = (
            "create-plan",
            "--plan-file",
            str(big_plan),
            "--workspace",
            str(self.workspace),
            "--title",
            "Oversized B1 plan",
            "--plan-id",
            "oversized-plan",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
        )
        result = self.run_cli(*args, expected=2)
        self.assertIn("65536", result.stderr)
        self.assertFalse(self.plan_path("oversized-plan").exists())
        self.assertFalse((meta_dir / "intent.json").exists())
        self.assertEqual(list((self.state / "plans").glob(".enroll-*")), [])

        # The checkout is not bricked: a legacy launch still works.
        launched = self.run_cli(
            "launch",
            "--cli",
            "fake",
            "--config",
            str(self.agents_config),
            "--approved-executor",
            "fake",
            "--workspace",
            str(self.workspace),
            "--task-file",
            str(self.task_file),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            "--job-id",
            "legacy-after-failure",
        )
        self.assertEqual(json.loads(launched.stdout)["job_id"], "legacy-after-failure")
        self.wait_for_file(self.state / "jobs" / "legacy-after-failure" / "result.json")
        reservation_dir = (
            self.workspace / ".git" / "agent-orchestrator" / "active-jobs"
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and list(
            reservation_dir.glob("legacy-after-failure.*.json")
        ):
            time.sleep(0.1)
        self.assertEqual(
            list(reservation_dir.glob("legacy-after-failure.*.json")), []
        )
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_injected_prepublication_failure_cleans_intent_and_allows_auto_plan(
        self,
    ) -> None:
        self.project_mode()
        meta_dir = self.workspace / ".git" / "agent-orchestrator"
        injected = self.run_cli_with_hook(
            self.create_managed_args(plan_id="injected-plan"),
            "_append_specs",
            mode="raise",
        )
        self.assertNotEqual(injected.returncode, 0)
        self.assertIn("injected failure", injected.stderr)
        self.assertFalse(self.plan_path("injected-plan").exists())
        self.assertFalse((meta_dir / "intent.json").exists())
        self.assertEqual(list((self.state / "plans").glob(".enroll-*")), [])

        auto = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Auto plan",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
        )
        generated = json.loads(auto.stdout)
        self.assertTrue(generated["plan_id"].startswith("plan-"))
        self.checkpoint(generated["plan_id"])

    def test_enrollment_delete_staging_scaffolding_and_protects_published_plan(
        self,
    ) -> None:
        self.create_managed()
        plan_dir = self.plan_path()
        self.assertFalse((plan_dir / ".b1-staging.json").exists())
        self.assertEqual(list((self.state / "plans").glob(".enroll-*")), [])

        # A published plan directory is authoritative. Even when every piece of
        # computed evidence is missing, cleanup must fail closed and never
        # delete the directory.
        shutil.rmtree(plan_dir / "consensus" / "events")
        (plan_dir / "plan.json").unlink()
        (plan_dir / "checkpoint.json").unlink()
        rejected = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("Plan already exists", rejected.stderr)
        self.assertTrue(plan_dir.is_dir())

    def test_postpublication_regeneration_holds_the_plan_lock(self) -> None:
        self.project_mode()
        # The injected replacement checks that the enrollment's postpublication
        # regeneration holds the plan lock (a second non-blocking flock would
        # otherwise succeed) and exits 41 when it does not.
        result = self.run_cli_with_hook(
            self.create_managed_args(plan_id="locked-plan"),
            "_regenerate_locked",
            mode="assert_lock",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.plan_path("locked-plan").is_dir())

    def test_enrollment_policy_idempotency_and_pause_provenance(self) -> None:
        self.create_managed()
        retried = self.create_managed()
        self.assertTrue(retried["idempotent"])
        # Alternate path forms resolve to the same enrollment identity.
        subdir_retry = self.create_managed(workspace=self.workspace / "subdir")
        self.assertTrue(subdir_retry["idempotent"])
        for extra, label in (
            (("--strategy", "quality-first"), "strategy"),
            (("--max-parallel", "2"), "team policy"),
        ):
            conflict = self.run_cli(
                "create-plan",
                "--plan-file",
                str(self.plan_file),
                "--workspace",
                str(self.workspace),
                "--title",
                "B1 managed plan",
                "--plan-id",
                "b1-plan",
                "--research-team",
                "--manifest-file",
                str(self.manifest_file),
                "--executor",
                "fake",
                "--json",
                *extra,
                expected=2,
            )
            self.assertIn("different enrollment content", conflict.stderr, label)
        self.assertEqual(len(self.event_paths()), 1)

        paused = json.loads(
            self.run_cli(
                "consensus-pause",
                "--plan-id",
                "b1-plan",
                "--step-id",
                "step-one",
                "--role",
                "deepseek",
                "--reason",
                "provider transport unavailable",
                "--guidance",
                "retry the same request after reconnecting",
                "--job-id",
                "job-deepseek",
                "--json",
            ).stdout
        )
        self.assertEqual(
            paused["pause"]["provenance"]["job_id"], "job-deepseek"
        )
        pause_event = self.event_paths()[-1]
        payload = json.loads(pause_event.read_text())
        self.assertEqual(payload["payload"]["provenance"], {
            "job_id": "job-deepseek",
            "leader": None,
        })
        checkpoint = self.checkpoint()
        self.assertEqual(
            checkpoint["steps"][0]["open_pauses"][0]["provenance"]["job_id"],
            "job-deepseek",
        )
        log = (
            self.plan_path() / "steps" / "step-one" / "DISCUSSION_LOG.md"
        ).read_text()
        self.assertIn('"job_id": "job-deepseek"', log)

        def rewrite(event: dict[str, object]) -> None:
            event.pop("digest", None)
            event["digest"] = hashlib.sha256(
                json.dumps(
                    event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            ).hexdigest()
            pause_event.write_text(json.dumps(event), encoding="utf-8")

        event = json.loads(pause_event.read_text())
        event["payload"].pop("provenance")
        rewrite(event)
        missing = self.run_cli("plan-checkpoint", "b1-plan", "--json", expected=2)
        self.assertIn("missing fields: provenance", missing.stderr)
        event["payload"]["provenance"] = {"job_id": None, "leader": None}
        rewrite(event)
        invalid = self.run_cli("plan-checkpoint", "b1-plan", "--json", expected=2)
        self.assertIn("requires a job_id or leader", invalid.stderr)

    def test_manifest_and_objection_hardening(self) -> None:
        self.project_mode()
        bad_manifests = {
            "null-dependency": {
                "policy_version": 2,
                "steps": [
                    self.manifest["steps"][0],
                    {
                        **self.manifest["steps"][0],
                        "id": "step-two",
                        "depends_on": None,
                    },
                ],
            },
            "duplicate-dependency": {
                "policy_version": 2,
                "steps": [
                    self.manifest["steps"][0],
                    {
                        **self.manifest["steps"][0],
                        "id": "step-two",
                        "depends_on": ["step-one", "step-one"],
                    },
                ],
            },
            "oversized-item": {
                "policy_version": 2,
                "steps": [
                    {
                        **self.manifest["steps"][0],
                        "deliverables": ["x" * 2500],
                    }
                ],
            },
        }
        for name, manifest in bad_manifests.items():
            path = self.root / f"manifest-{name}.json"
            self.write_manifest(manifest, path)
            result = self.run_cli(
                "create-plan",
                "--plan-file",
                str(self.plan_file),
                "--workspace",
                str(self.workspace),
                "--title",
                name,
                "--plan-id",
                f"bad-{name}",
                "--research-team",
                "--manifest-file",
                str(path),
                "--executor",
                "fake",
                "--json",
                expected=2,
            )
            self.assertTrue(result.stderr.strip(), name)

        self.create_managed()
        for role in ROLES:
            self.submit("b1-plan", role, 1)
        supplied = self.root / "cross-with-id.json"
        cross = self.cross("codex")
        cross["challenges"] = [
            {
                "objection": "Caller-supplied numbering must be rejected.",
                "severity": "major",
                "objection_id": "O001",
            }
        ]
        supplied.write_text(json.dumps(cross), encoding="utf-8")
        rejected = self.run_cli(
            "consensus-submit",
            "--plan-id",
            "b1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "2",
            "--submission-file",
            str(supplied),
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        self.assertIn("must not supply objection_id", rejected.stderr)
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["steps"][0]["cross_examination_roles"], [])

    def test_corrupt_marker_fails_worker_closed_without_traceback(self) -> None:
        self.create_managed()
        marker = self.workspace / ".git" / "agent-orchestrator" / "enrollment.json"
        marker.write_bytes(b"\xff\xfe")
        worker_job = self.state / "jobs" / "marker-worker"
        runner.write_json(
            worker_job / "meta.json",
            {
                "job_id": "marker-worker",
                "agent": "fake",
                "workspace": str(self.workspace),
                "state": "starting",
            },
        )
        worker = subprocess.run(
            [sys.executable, str(RUNNER), "_worker", "--job-dir", str(worker_job)],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            check=False,
        )
        self.assertEqual(worker.returncode, 2, worker.stderr)
        self.assertNotIn("Traceback", worker.stderr)
        result = json.loads((worker_job / "result.json").read_text())
        self.assertEqual(result["state"], "failed")
        self.assertIn("Admission state unavailable", result["blocked_reason"])
        self.assertTrue(
            any(
                json.loads(path.read_text()).get("type") == "worker_blocked"
                for path in (worker_job / "events").glob("*.json")
            )
        )

    def test_concurrent_enrollment_serializes_one_winner(self) -> None:
        env_two = self.alternate_env("state-two")
        self.project_mode(self.env)
        self.project_mode(env_two)
        base = [
            sys.executable,
            str(RUNNER),
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(self.workspace),
            "--title",
            "Race managed plan",
            "--research-team",
            "--manifest-file",
            str(self.manifest_file),
            "--executor",
            "fake",
            "--json",
        ]
        attempts = (
            ("race-one", self.env, "state"),
            ("race-two", env_two, "state-two"),
        )
        processes = [
            subprocess.Popen(
                [*base, "--plan-id", plan_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            for plan_id, env, _ in attempts
        ]
        results = [process.communicate(timeout=60) for process in processes]
        codes = sorted(process.returncode for process in processes)
        self.assertEqual(codes, [0, 2], results)
        marker = json.loads(
            (self.workspace / ".git" / "agent-orchestrator" / "enrollment.json").read_text()
        )
        winner = marker["plan_id"]
        losing_stderr = ""
        for (plan_id, _, home), process, (_, stderr) in zip(
            attempts, processes, results
        ):
            plan_dir = self.root / home / "plans" / plan_id
            if plan_id == winner:
                self.assertTrue((plan_dir / "plan.json").is_file())
            else:
                self.assertFalse(plan_dir.exists())
                losing_stderr = stderr
        self.assertTrue(
            "already enrolled" in losing_stderr
            or "belongs to managed plan" in losing_stderr,
            losing_stderr,
        )

    def test_legacy_non_git_workspace_remains_usable(self) -> None:
        plain = self.root / "plain-project"
        plain.mkdir()
        # A non-English locale must not turn Git's localizable "not a repository"
        # diagnostic into an admission failure for plain legacy directories.
        localized = dict(self.env)
        localized["LANG"] = "fr_FR.UTF-8"
        localized["LC_ALL"] = "fr_FR.UTF-8"
        created = self.run_cli(
            "create-plan",
            "--plan-file",
            str(self.plan_file),
            "--workspace",
            str(plain),
            "--title",
            "Plain legacy plan",
            "--plan-id",
            "plain-legacy",
            "--executor",
            "fake",
            "--json",
            env=localized,
        )
        plan = json.loads(created.stdout)
        self.assertNotIn("managed", plan)
        self.assertEqual(plan["items"][0]["state"], "pending")
        status = self.run_cli("plan-status", "plain-legacy", "--json")
        self.assertEqual(json.loads(status.stdout)["plan_id"], "plain-legacy")

    def test_policy_two_default_roster_artifacts_and_wrong_role_rejection(self) -> None:
        created = self.create_managed()
        self.assertEqual(created["policy"], {"name": "b1-durable-consensus", "version": 2})
        self.assertEqual(created["policy_status"], "ACTIVE")
        self.assertFalse(created["historical_read_only"])
        self.assertEqual(created["roles"], ["codex", "deepseek", "glm"])
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint["policy_version"], 2)
        self.assertEqual(checkpoint["roles"], ["codex", "deepseek", "glm"])
        self.assertFalse(checkpoint["historical_read_only"])
        step_dir = self.plan_path() / "steps" / "step-one"
        names = sorted(
            path.name for path in step_dir.iterdir() if path.is_file()
        )
        self.assertEqual(
            names,
            [
                "CONSENSUS.md",
                "DISCUSSION_BRIEF.md",
                "DISCUSSION_LOG.md",
                "PROPOSAL_CODEX.md",
                "PROPOSAL_DEEPSEEK.md",
                "PROPOSAL_GLM.md",
            ],
        )
        brief = (step_dir / "DISCUSSION_BRIEF.md").read_text()
        self.assertIn("Policy: `b1-durable-consensus` version 2", brief)
        self.assertIn("Roles: Codex, DeepSeek, GLM", brief)
        self.assertIn("each of the 3 roles", brief)
        self.assertNotIn("Antigravity", brief)
        self.assertTrue(checkpoint["missing_actions"])
        self.assertIn("codex", checkpoint["next_action"])

        # A removed or unknown role is rejected before any event is published.
        results = [
            self.run_cli(
                "consensus-submit",
                "--plan-id",
                "b1-plan",
                "--step-id",
                "step-one",
                "--role",
                "antigravity",
                "--round",
                "1",
                "--submission-file",
                str(self.proposal_files["codex"]),
                "--job-id",
                "job-codex",
                "--json",
                expected=2,
            ),
            self.run_cli(
                "consensus-vote",
                "--plan-id",
                "b1-plan",
                "--step-id",
                "step-one",
                "--role",
                "antigravity",
                "--digest",
                "a" * 64,
                "--vote",
                "AGREE",
                "--json",
                expected=2,
            ),
            self.run_cli(
                "consensus-pause",
                "--plan-id",
                "b1-plan",
                "--step-id",
                "step-one",
                "--role",
                "antigravity",
                "--reason",
                "removed provider must never run",
                "--guidance",
                "use the active three-role team",
                "--json",
                expected=2,
            ),
        ]
        for result in results:
            self.assertIn("not in the active policy version 2 roster", result.stderr)
            self.assertIn("Antigravity", result.stderr)
        self.assertEqual(len(self.event_paths()), 1)

        # Policy version 1 cannot be used to create new work; it is history.
        v1_manifest_file = self.root / "manifest-v1-create.json"
        self.write_manifest(self.v1_manifest(), v1_manifest_file)
        v1_create = self.run_cli(
            *self.create_managed_args(
                plan_id="v1-create",
                manifest=v1_manifest_file,
                extra=("--policy-version", "1"),
            ),
            expected=2,
        )
        self.assertIn("historical", v1_create.stderr)
        self.assertIn("version 2", v1_create.stderr)
        self.assertFalse(self.plan_path("v1-create").exists())
        mismatch = self.run_cli(
            *self.create_managed_args(plan_id="v1-mismatch", manifest=v1_manifest_file),
            expected=2,
        )
        self.assertIn("does not match --policy-version 2", mismatch.stderr)
        unknown = self.run_cli(
            *self.create_managed_args(
                plan_id="unknown-version", extra=("--policy-version", "3")
            ),
            expected=2,
        )
        self.assertIn("Unknown research policy version 3", unknown.stderr)

    def test_historical_v1_views_are_read_only_and_every_mutation_fails(self) -> None:
        digest = self.build_v1_ledger()
        plan_dir = self.plan_path("v1-plan")
        original = self.file_bytes(plan_dir)
        self.assertEqual(
            [path.name for path in self.event_paths("v1-plan")][:1], ["000001.json"]
        )
        self.assertEqual(len(self.event_paths("v1-plan")), 15)

        checkpoint = self.checkpoint("v1-plan")
        self.assertEqual(checkpoint["policy"], {"name": "b1-durable-consensus", "version": 1})
        self.assertEqual(checkpoint["policy_version"], 1)
        self.assertEqual(checkpoint["roles"], list(V1_ROLES))
        self.assertEqual(checkpoint["policy_status"], "HISTORICAL_READ_ONLY")
        self.assertTrue(checkpoint["historical_read_only"])
        self.assertIn("version 2", checkpoint["replacement_guidance"])
        self.assertEqual(checkpoint["consensus_state"], "CONSENSUS_REACHED")
        self.assertEqual(checkpoint["missing_actions"], [])
        self.assertIsNone(checkpoint["next_item"])
        self.assertIn("historical", checkpoint["next_action"])
        step = checkpoint["steps"][0]
        self.assertEqual(step["consensus_state"], "CONSENSUS_REACHED")
        self.assertEqual(step["frozen_digest"], digest)
        self.assertEqual(
            step["tally"], {"AGREE": 4, "DISAGREE": 0, "NEEDS_DISCUSSION": 0}
        )
        self.assertEqual(
            [vote["role"] for vote in step["votes"]], list(V1_ROLES)
        )
        self.assertTrue(
            all(vote["vote"] == "AGREE" for vote in step["votes"])
        )
        self.assertEqual(step["missing_actions"], [])
        files = step["artifacts"]["files"]
        self.assertEqual(len(files), 7)
        self.assertIn("PROPOSAL_ANTIGRAVITY.md", files)
        self.assertFalse(step["artifacts"]["regenerated"])
        self.assertTrue(step["artifacts"]["historical_read_only"])
        self.assertEqual(
            [path.name for path in self.event_paths("v1-plan")],
            [f"{i:06d}.json" for i in range(1, 16)],
        )

        status = json.loads(
            self.run_cli("plan-status", "v1-plan", "--json").stdout
        )
        self.assertEqual(status["policy"]["version"], 1)
        self.assertTrue(status["historical_read_only"])
        self.assertIn("version 2", status["replacement_guidance"])
        text_status = self.run_cli("plan-status", "v1-plan").stdout
        self.assertIn("historical_read_only: true", text_status)
        self.assertIn("replacement_guidance:", text_status)
        # Repeating reads must not rewrite any original byte.
        self.checkpoint("v1-plan")
        self.assertEqual(self.file_bytes(plan_dir), original)

        # An implicit in-place upgrade to policy version 2 is refused; the
        # historical plan ID and content stay untouched.
        self.project_mode()
        upgrade = self.run_cli(*self.create_managed_args(plan_id="v1-plan"), expected=2)
        self.assertIn("different enrollment content", upgrade.stderr)
        for name, data in original.items():
            self.assertEqual((plan_dir / name).read_bytes(), data, name)

        submit = self.run_cli(
            "consensus-submit",
            "--plan-id",
            "v1-plan",
            "--step-id",
            "step-one",
            "--role",
            "codex",
            "--round",
            "1",
            "--submission-file",
            str(self.proposal_files["codex"]),
            "--job-id",
            "job-codex",
            "--json",
            expected=2,
        )
        self.assertIn("historical", submit.stderr.lower())
        freeze = self.run_cli(
            "consensus-freeze",
            "--plan-id",
            "v1-plan",
            "--step-id",
            "step-one",
            "--candidate-file",
            str(self.candidate_file(["O001"])),
            "--json",
            expected=2,
        )
        self.assertIn("historical", freeze.stderr.lower())
        vote = self.vote("v1-plan", "codex", digest, "AGREE", expected=2)
        self.assertIn("historical", vote.stderr.lower())
        pause = self.run_cli(
            "consensus-pause",
            "--plan-id",
            "v1-plan",
            "--step-id",
            "step-one",
            "--role",
            "deepseek",
            "--reason",
            "do not launch a removed provider",
            "--guidance",
            "preserve this ledger and create a version 2 plan",
            "--job-id",
            "job-deepseek",
            "--json",
            expected=2,
        )
        self.assertIn("historical", pause.stderr.lower())
        resume = self.run_cli(
            "consensus-resume",
            "--plan-id",
            "v1-plan",
            "--step-id",
            "step-one",
            "--role",
            "deepseek",
            "--retry-id",
            "retry-historical",
            "--json",
            expected=2,
        )
        self.assertIn("historical", resume.stderr.lower())
        new_cycle = self.run_cli(
            "consensus-new-cycle",
            "--plan-id",
            "v1-plan",
            "--step-id",
            "step-one",
            "--authorized-by",
            "Human owner",
            "--authorization",
            "This must not reopen historical policy version 1.",
            "--json",
            expected=2,
        )
        self.assertIn("historical", new_cycle.stderr.lower())
        # A removed-provider role is rejected even when addressed directly.
        removed = self.run_cli(
            "consensus-submit",
            "--plan-id",
            "v1-plan",
            "--step-id",
            "step-one",
            "--role",
            "antigravity",
            "--round",
            "1",
            "--submission-file",
            str(self.proposal_files["codex"]),
            "--job-id",
            "job-antigravity",
            "--json",
            expected=2,
        )
        self.assertIn("Antigravity", removed.stderr)
        self.assertIn("historical", removed.stderr.lower())
        # No event, provider job, or reservation was created by any attempt.
        self.assertEqual(len(self.event_paths("v1-plan")), 15)
        for name, data in original.items():
            self.assertEqual((plan_dir / name).read_bytes(), data, name)
        self.assertFalse((self.state / "jobs").exists())
        self.assertEqual(list(self.reservation_dir().glob("*.json")), [])

    def test_cross_version_and_stale_policy_ballots_fail_closed(self) -> None:
        v1_digest = self.build_v1_ledger(
            "v1-history-plan", workspace=self.extra_repo("v1-history")
        )
        self.create_managed()
        for role in ROLES:
            self.submit("b1-plan", role, 1)
        for role in ROLES:
            self.submit("b1-plan", role, 2)
        v2_digest = self.freeze("b1-plan")
        self.assertNotEqual(v1_digest, v2_digest)
        # A ballot minted for the historical policy version is stale here.
        stale = self.vote("b1-plan", "codex", v1_digest, "AGREE", expected=2)
        self.assertIn("stale", stale.stderr)
        self.assertEqual(len(self.event_paths()), 8)  # enroll + 3 + 3 + freeze

        # A version 2 plan cannot replay a candidate bound with the historical
        # policy version or its four-role roster.
        b1 = runner.b1_module()
        forged = self.create_managed(
            plan_id="forged-binding", workspace=self.extra_repo("forged-binding")
        )
        self.assertEqual(forged["policy"]["version"], 2)
        for role in ROLES:
            self.submit("forged-binding", role, 1)
        for role in ROLES:
            self.submit("forged-binding", role, 2)
        path = self.plan_path("forged-binding")
        state = b1.replay_events(path)
        binding = {
            "policy": {"name": b1.POLICY_NAME, "version": 1},
            "plan_id": "forged-binding",
            "plan_sha256": state["static"]["plan_sha256"],
            "manifest_digest": state["static"]["manifest_digest"],
            "step_id": "step-one",
            "cycle": 1,
            "vote_round": 3,
            "dependency_references": [],
        }
        candidate = self.candidate(["O001"])
        spec = {
            "type": "candidate_frozen",
            "step_id": "step-one",
            "cycle": 1,
            "round": 3,
            "payload": {
                "digest": b1._candidate_digest(binding, candidate),
                "binding": binding,
                "candidate": candidate,
                "objection_ids": ["O001"],
            },
        }
        b1._append_specs(
            path, state, [spec], "forged-binding-freeze", b1._digest(spec)
        )
        rejected = self.run_cli(
            "plan-checkpoint", "forged-binding", "--json", expected=2
        )
        self.assertIn("binding does not match", rejected.stderr)

        # A version 2 plan cannot replay a ballot from the removed role.
        self.create_managed(
            plan_id="forged-roster", workspace=self.extra_repo("forged-roster")
        )
        for role in ROLES:
            self.submit("forged-roster", role, 1)
        for role in ROLES:
            self.submit("forged-roster", role, 2)
        roster_digest = self.freeze("forged-roster")
        roster_path = self.plan_path("forged-roster")
        roster_state = b1.replay_events(roster_path)
        ballot = {
            "type": "ballot_recorded",
            "step_id": "step-one",
            "cycle": 1,
            "round": 3,
            "payload": {
                "role": "antigravity",
                "vote": "AGREE",
                "rationale": "removed provider ballot must never count",
                "digest": roster_digest,
                "provenance": {"job_id": "job-antigravity", "leader": None},
                "retry_id": None,
            },
        }
        b1._append_specs(
            roster_path,
            roster_state,
            [ballot],
            "forged-antigravity-ballot",
            b1._digest(ballot),
        )
        rejected_roster = self.run_cli(
            "plan-checkpoint", "forged-roster", "--json", expected=2
        )
        self.assertIn("not in the policy version 2 roster", rejected_roster.stderr)

    def test_live_child_survives_missing_result_and_malformed_heartbeat(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.addCleanup(self.kill_pid, child.pid)
        job = self.state / "jobs" / "live-child"
        runner.write_json(
            job / "meta.json",
            {
                "job_id": "live-child",
                "workspace": str(self.workspace),
                "canonical_workspace": str(self.workspace.resolve()),
                "state": "starting",
                "worker_pid": 999_999_999,
                "provider_pid": 999_999_999,
                "child_pid": child.pid,
            },
        )
        # No result.json; the secondary heartbeat is malformed, so get_status
        # would raise. The live recorded child must be observed first.
        (job / "heartbeat.json").write_text("{broken", encoding="utf-8")
        self.project_mode()
        denied = self.run_cli(*self.create_managed_args(), expected=2)
        self.assertIn("active job", denied.stderr)
        self.assertIn("live-child", denied.stderr)
        self.assertFalse(self.plan_path().exists())

        self.kill_pid(child.pid)
        child.wait(timeout=10)
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_unprobeable_recorded_processes_stay_active(self) -> None:
        canonical = str(self.workspace.resolve())
        job_ids = ["perm-worker", "perm-provider", "perm-child"]
        keys = ["worker_pid", "provider_pid", "child_pid"]
        for job_id, key in zip(job_ids, keys):
            runner.write_json(
                self.state / "jobs" / job_id / "meta.json",
                {
                    "job_id": job_id,
                    "workspace": str(self.workspace),
                    "canonical_workspace": canonical,
                    "state": "succeeded",
                    key: os.getpid(),
                },
            )
        # A terminal-looking meta with no result and an unprobeable process is
        # still active; a permission failure is never treated as death.
        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ), mock.patch.object(runner.os, "kill", side_effect=PermissionError):
            active = runner.active_jobs_for_canonical_workspace(canonical)
        self.assertEqual(sorted(active), sorted(job_ids))
        for job_id in job_ids:
            shutil.rmtree(self.state / "jobs" / job_id)
        # Without a recorded live process, a malformed heartbeat is not an
        # active job and does not wedge enrollment forever.
        dead = self.state / "jobs" / "dead-malformed"
        runner.write_json(
            dead / "meta.json",
            {
                "job_id": "dead-malformed",
                "workspace": str(self.workspace),
                "canonical_workspace": canonical,
                "state": "succeeded",
            },
        )
        (dead / "heartbeat.json").write_text("{broken", encoding="utf-8")
        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ):
            self.assertEqual(
                runner.active_jobs_for_canonical_workspace(canonical), []
            )
        created = self.create_managed()
        self.assertFalse(created["idempotent"])

    def test_blocked_worker_meta_and_result_are_consistent(self) -> None:
        self.create_managed()
        job = self.state / "jobs" / "blocked-meta"
        runner.write_json(
            job / "meta.json",
            {
                "job_id": "blocked-meta",
                "agent": "fake",
                "workspace": str(self.workspace),
                "plan_id": "b1-plan",
                "state": "starting",
            },
        )
        worker = subprocess.run(
            [sys.executable, str(RUNNER), "_worker", "--job-dir", str(job)],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
            check=False,
        )
        self.assertEqual(worker.returncode, 2, worker.stderr)
        result = runner.read_json(job / "result.json")
        meta = runner.read_json(job / "meta.json")
        self.assertEqual(result["state"], "failed")
        self.assertEqual(meta["state"], "failed")
        self.assertEqual(meta["exit_code"], 2)
        self.assertEqual(meta["finished_at"], result["finished_at"])
        self.assertEqual(meta["blocked_reason"], result["blocked_reason"])
        self.assertIn("managed", meta["blocked_reason"])
        self.assertIn("managed", worker.stderr)
        # The terminal blocked state is durable; a restart sees a failed job
        # and the reservation was released.
        self.assertEqual(
            list(self.reservation_dir().glob("blocked-meta.*.json")), []
        )
        events = [
            json.loads(path.read_text())
            for path in (job / "events").glob("*.json")
        ]
        self.assertTrue(
            any(event.get("type") == "worker_blocked" for event in events)
        )


if __name__ == "__main__":
    unittest.main()
