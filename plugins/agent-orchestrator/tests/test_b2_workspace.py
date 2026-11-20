from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


RUNNER = Path(__file__).resolve().parents[1] / "scripts" / "cli_agent_job.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "agent_orchestrator_runner_b2", RUNNER
)
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


class B2WorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.env = {**os.environ, "AGENT_ORCHESTRATOR_HOME": str(self.state)}
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git(self.repo, "init", "-q")
        self.git(self.repo, "config", "user.email", "worker@example.test")
        self.git(self.repo, "config", "user.name", "Worker")
        (self.repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        self.git(self.repo, "add", "tracked.txt")
        self.git(self.repo, "commit", "-qm", "baseline")
        (self.repo / "subdir").mkdir()
        self.task = self.root / "task.md"
        self.task.write_text("implement the bounded change\n", encoding="utf-8")
        self.pids: list[int] = []
        self._sleepers: list[subprocess.Popen] = []
        self.addCleanup(self._reap_sleepers)

    def git(self, cwd: Path, *args: str) -> None:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def kill(self, pid: int) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def kill_group(self, pid: int) -> None:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def track(self, pid: int, group: bool = False) -> int:
        self.pids.append(pid)
        self.addCleanup(self.kill_group if group else self.kill, pid)
        return pid

    def agent_config(self, name: str, code: str) -> Path:
        path = self.root / f"agents-{name}.json"
        path.write_text(
            json.dumps(
                {
                    "agents": {
                        name: {
                            "argv": [sys.executable, "-c", code],
                            "prompt_transport": "stdin",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        return path

    def _sleepy_config(self, name: str, seconds: float, ready: Path) -> Path:
        code = (
            "import os,sys,time\n"
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
                            "argv": [sys.executable, "-c", code, str(ready)],
                            "prompt_transport": "stdin",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        return path

    def run_cli(
        self,
        *args: str,
        env: dict[str, str] | None = None,
        expected: int = 0,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(RUNNER), *args],
            capture_output=True,
            text=True,
            env=env or self.env,
            timeout=timeout,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr or result.stdout)
        return result

    def launch_args(
        self,
        job_id: str,
        config: Path,
        *,
        workspace: Path | None = None,
        name: str = "provider",
        extra: tuple[str, ...] = (),
    ) -> list[str]:
        return [
            "launch",
            "--cli",
            name,
            "--config",
            str(config),
            "--approved-executor",
            name,
            "--workspace",
            str(workspace or self.repo),
            "--task-file",
            str(self.task),
            "--allow-unstructured-task",
            "--no-notify",
            "--json",
            "--job-id",
            job_id,
            *extra,
        ]

    def launch(
        self,
        job_id: str,
        config: Path,
        *,
        env: dict[str, str] | None = None,
        workspace: Path | None = None,
        name: str = "provider",
        extra: tuple[str, ...] = (),
        expected: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            *self.launch_args(
                job_id, config, workspace=workspace, name=name, extra=extra
            ),
            env=env,
            expected=expected,
        )

    def wait_for(self, predicate, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail("Timed out waiting for condition")

    def wait_file(self, path: Path, timeout: float = 20) -> str:
        # Waiting for the inode alone races writers that create the file
        # before populating it. Read once per poll and return what was seen.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                text = path.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                text = ""
            if text:
                return text
            time.sleep(0.05)
        self.fail(f"Timed out waiting for nonempty file: {path}")

    def wait_pid(self, pid: int, timeout: float = 20) -> None:

        def gone() -> bool:
            try:
                data = Path(f"/proc/{pid}/stat").read_bytes()
            except (FileNotFoundError, ProcessLookupError):
                return True
            except OSError:
                return False
            tail = data.rsplit(b")", 1)[-1].split()
            return bool(tail) and tail[0] == b"Z"

        self.wait_for(gone, timeout)

    def job_path(self, job_id: str, home: Path | None = None) -> Path:
        return (home or self.state) / "jobs" / job_id

    def result(self, job_id: str, home: Path | None = None) -> dict:
        return json.loads(
            (self.job_path(job_id, home) / "result.json").read_text(
                encoding="utf-8"
            )
        )

    def wait_result(
        self, job_id: str, home: Path | None = None, timeout: float = 30
    ) -> dict:
        path = self.job_path(job_id, home) / "result.json"
        self.wait_for(path.is_file, timeout)
        return json.loads(path.read_text(encoding="utf-8"))

    def wait_final(self, job_id: str, timeout: float = 30) -> dict:
        path = self.job_path(job_id) / "final-check.json"
        self.wait_for(path.is_file, timeout)
        return json.loads(path.read_text(encoding="utf-8"))

    def wait_result_state(
        self, job_id: str, state: str, timeout: float = 30
    ) -> dict:
        def matches() -> bool:
            path = self.job_path(job_id) / "final-check.json"
            result = self.job_path(job_id) / "result.json"
            if not path.is_file() or not result.is_file():
                return False
            try:
                return (
                    json.loads(result.read_text(encoding="utf-8")).get("state")
                    == state
                )
            except (OSError, json.JSONDecodeError):
                return False

        self.wait_for(matches, timeout)
        return self.result(job_id)

    def meta(self, job_id: str, home: Path | None = None) -> dict:
        return json.loads(
            (self.job_path(job_id, home) / "meta.json").read_text(encoding="utf-8")
        )

    def owner(self, repo: Path | None = None) -> dict:
        path = (
            (repo or self.repo)
            / ".git"
            / "agent-orchestrator"
            / "lease"
            / "owner.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def wait_owner_state(
        self, state: str, timeout: float = 30, repo: Path | None = None
    ) -> dict:
        self.wait_for(lambda: self.owner(repo).get("state") == state, timeout)
        return self.owner(repo)

    def reservations(self, repo: Path | None = None) -> list[Path]:
        directory = (
            (repo or self.repo) / ".git" / "agent-orchestrator" / "active-jobs"
        )
        if not directory.is_dir():
            return []
        return sorted(directory.glob("*.json"))

    def wait_settled(
        self,
        job_id: str,
        home: Path | None = None,
        *,
        repo: Path | None = None,
        timeout: float = 30,
    ) -> dict:
        """Wait until the supervisor finished writing and released the lease.

        A worker publishes ``result.json`` before the supervisor records its
        final check and completion; without this wait a temporary repository can
        be removed while the supervisor is still updating ``.git``.
        """
        result = self.wait_result(job_id, home=home, timeout=timeout)
        self.wait_owner_state("completed", timeout, repo=repo)
        # Only this job's reservation matters here: a deliberately unrecovered
        # incident from an earlier job remains as durable evidence.
        prefix = f"{job_id}."
        self.wait_for(
            lambda: not any(
                path.name.startswith(prefix)
                for path in self.reservations(repo)
            ),
            timeout,
        )
        # The reservation is unlinked while the supervisor is still in its
        # release path. Waiting for the recorded supervisor to exit prevents a
        # temporary-directory cleanup from racing its remaining filesystem
        # operations.
        meta = self.meta(job_id, home=home)
        supervisor = meta.get("supervisor_pid")
        if not isinstance(supervisor, int) or supervisor <= 0:
            lease = meta.get("workspace_lease")
            owner_path = lease.get("owner_path") if isinstance(lease, dict) else None
            if isinstance(owner_path, str):
                try:
                    owner = json.loads(Path(owner_path).read_text(encoding="utf-8"))
                    record = owner.get("supervisor") or {}
                    supervisor = record.get("pid")
                except (OSError, ValueError, TypeError):
                    supervisor = None
        if isinstance(supervisor, int) and supervisor > 0:
            self.wait_pid(supervisor, timeout)
        return result

    def lock_stat(self) -> os.stat_result:
        return (
            self.repo
            / ".git"
            / "agent-orchestrator"
            / "lease"
            / "writer.lock"
        ).lstat()

    def alternate_env(self, name: str) -> dict[str, str]:
        return {
            **os.environ,
            "AGENT_ORCHESTRATOR_HOME": str(self.root / name),
        }

    def _reap_sleepers(self) -> None:
        for process in self._sleepers:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass

    def sleeper(self, seconds: float = 60) -> int:
        process = subprocess.Popen(
            [sys.executable, "-c", f"import time; time.sleep({seconds})"],
            start_new_session=True,
        )
        self._sleepers.append(process)
        self.track(process.pid, group=True)
        return process.pid

    def write_reservation(
        self,
        job_id: str,
        job_dir: Path,
        coordinator_pid: int,
        *,
        home: Path | None = None,
    ) -> Path:
        """Publish a repository-local B1 reservation exactly as a runner would."""
        identity = runner.canonical_workspace(self.repo)
        directory = self.repo / ".git" / "agent-orchestrator" / "active-jobs"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        reservation_id = secrets.token_hex(16)
        path = directory / f"{job_id}.{reservation_id}.json"
        now = runner.utc_now()
        record = {
            "version": 2,
            "reservation_id": reservation_id,
            "job_id": job_id,
            "canonical_workspace": identity["root"],
            "git_common_dir": identity["git_common_dir"],
            "state_home": str(home or self.state),
            "plans_dir": str((home or self.state) / "plans"),
            "job_dir": str(job_dir.resolve()),
            "coordinator_pid": coordinator_pid,
            "worker_pid": None,
            "provider_pid": None,
            "created_at": now,
            "updated_at": now,
        }
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Readiness helper
    # ------------------------------------------------------------------

    def test_wait_file_waits_for_populated_readiness_record(self) -> None:
        ready = self.root / "ready-populated-late"
        ready.write_text("", encoding="utf-8")
        expected = "424242"

        def populate() -> None:
            time.sleep(0.3)
            ready.write_text(expected, encoding="utf-8")

        writer = threading.Thread(target=populate)
        writer.start()
        self.addCleanup(writer.join, 5)
        started = time.monotonic()
        observed = self.wait_file(ready, timeout=5)
        elapsed = time.monotonic() - started
        self.assertEqual(observed, expected)
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertEqual(int(observed), 424242)

        # A nonempty but malformed record is returned as observed and must
        # fail PID validation later rather than being retried until timeout.
        malformed = self.root / "ready-malformed"
        malformed.write_text("not-a-pid", encoding="utf-8")
        self.assertEqual(self.wait_file(malformed, timeout=1), "not-a-pid")
        with self.assertRaises(ValueError):
            int(self.wait_file(malformed, timeout=1))

    # ------------------------------------------------------------------
    # One writer across state homes, aliases and distinct repositories
    # ------------------------------------------------------------------

    def test_one_writer_serializes_state_homes_aliases_and_worktrees(self) -> None:
        ready = self.root / "ready-long"
        config = self._sleepy_config("provider", 30, ready)
        self.launch("long-job", config)
        provider = int(self.wait_file(ready))
        self.track(provider)
        inode = self.lock_stat().st_ino
        self.assertEqual(self.owner()["state"], "supervising")

        env_b = self.alternate_env("state-two")
        link = self.root / "repo-link"
        link.symlink_to(self.repo, target_is_directory=True)
        linked = self.root / "linked-worktree"
        self.git(self.repo, "worktree", "add", "-q", str(linked), "-b", "wt-branch")
        for workspace in (self.repo / "subdir", link, linked):
            denied = self.launch(
                "second-job",
                config,
                env=env_b,
                workspace=workspace,
                extra=("--allow-concurrent-workspace",),
                expected=2,
            )
            self.assertIn("writer lease", denied.stderr)
            self.assertIn("long-job", denied.stderr)
        self.assertEqual(self.reservations()[0].name.split(".")[0], "long-job")

        # A distinct Git repository has its own inode and admits its own writer.
        other = self.root / "other-repo"
        other.mkdir()
        self.git(other, "init", "-q")
        self.git(other, "config", "user.email", "worker@example.test")
        self.git(other, "config", "user.name", "Worker")
        (other / "seed.txt").write_text("seed\n", encoding="utf-8")
        self.git(other, "add", "seed.txt")
        self.git(other, "commit", "-qm", "seed")
        other_ready = self.root / "ready-other"
        other_config = self._sleepy_config("other", 30, other_ready)
        self.launch("other-job", other_config, env=env_b, workspace=other, name="other")
        other_provider = int(self.wait_file(other_ready))
        self.track(other_provider)
        other_lock = other / ".git" / "agent-orchestrator" / "lease" / "writer.lock"
        self.assertNotEqual(self.lock_stat().st_ino, other_lock.lstat().st_ino)

        # Clean completion releases the same never-unlinked inode.
        os.kill(provider, signal.SIGTERM)
        self.wait_result("long-job")
        self.wait_owner_state("completed")
        self.wait_for(lambda: not self.reservations())
        os.kill(other_provider, signal.SIGTERM)
        state_two = self.root / "state-two"
        self.wait_settled("other-job", home=state_two, repo=other)
        later_ready = self.root / "ready-later"
        later_config = self._sleepy_config("later", 30, later_ready)
        self.launch("later-job", later_config, env=env_b, name="later")
        later_provider = int(self.wait_file(later_ready))
        self.track(later_provider)
        self.assertEqual(self.lock_stat().st_ino, inode)
        self.assertEqual(self.owner()["state"], "supervising")
        os.kill(later_provider, signal.SIGTERM)
        self.wait_settled("later-job", home=state_two)

    def test_simultaneous_launch_admits_exactly_one_writer(self) -> None:
        ready = self.root / "ready-race"
        config = self._sleepy_config("provider", 30, ready)
        env_a = self.env
        env_b = self.alternate_env("state-two")
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    str(RUNNER),
                    *self.launch_args(job_id, config),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )
            for job_id, env in (("race-a", env_a), ("race-b", env_b))
        ]
        results = [process.communicate(timeout=60) for process in processes]
        codes = sorted(process.returncode for process in processes)
        self.assertEqual(codes, [0, 2], results)
        winner_index = next(
            index
            for index, process in enumerate(processes)
            if process.returncode == 0
        )
        loser_index = 1 - winner_index
        loser_stderr = results[loser_index][1]
        self.assertTrue(
            "writer lease" in loser_stderr or "held by" in loser_stderr,
            loser_stderr,
        )
        provider = int(self.wait_file(ready))
        self.track(provider)
        winning_home = (
            self.state if winner_index == 0 else self.root / "state-two"
        )
        winner_job = "race-a" if winner_index == 0 else "race-b"
        self.assertTrue(
            (winning_home / "jobs" / winner_job / "meta.json").is_file()
        )
        self.assertEqual(len(self.reservations()), 1)
        os.kill(provider, signal.SIGTERM)
        self.wait_result(winner_job, home=winning_home)
        self.wait_owner_state("completed")
        self.wait_for(lambda: not self.reservations())

    # ------------------------------------------------------------------
    # Crash safety while descendants live
    # ------------------------------------------------------------------

    def test_worker_crash_keeps_lease_until_provider_exits(self) -> None:
        ready = self.root / "ready-worker-crash"
        config = self._sleepy_config("provider", 30, ready)
        self.launch("crash-job", config)
        provider = int(self.wait_file(ready))
        self.track(provider)
        meta = self.meta("crash-job")
        worker_pid = meta["worker_pid"]
        self.assertIsInstance(worker_pid, int)

        os.kill(worker_pid, signal.SIGKILL)
        self.wait_pid(worker_pid)
        denied = self.launch("blocked-job", config, expected=2)
        self.assertIn("writer lease", denied.stderr)

        os.kill(provider, signal.SIGTERM)
        result = self.wait_result("crash-job")
        self.assertEqual(result["state"], "lost")
        self.assertTrue(result["supervisor_inferred"])
        self.wait_owner_state("completed")
        self.wait_for(lambda: not self.reservations())
        recovery = self.root / "ready-after-crash"
        recovery_config = self._sleepy_config("recovery", 30, recovery)
        self.launch("recovery-job", recovery_config, name="recovery")
        recovery_provider = int(self.wait_file(recovery))
        self.track(recovery_provider)
        os.kill(recovery_provider, signal.SIGTERM)
        self.wait_settled("recovery-job")

    def test_coordinator_crash_keeps_lease_until_descendants_exit(self) -> None:
        ready = self.root / "ready-coordinator-crash"
        config = self._sleepy_config("provider", 30, ready)
        coordinator = self.root / "coordinator.py"
        marker = self.root / "coordinator-launched"
        coordinator.write_text(
            "import importlib.util, sys, time\n"
            "from pathlib import Path\n"
            "spec = importlib.util.spec_from_file_location('runner', sys.argv[1])\n"
            "runner = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(runner)\n"
            "args = runner.build_parser().parse_args(sys.argv[3:])\n"
            "runner.validate_cli_args(args)\n"
            "code = runner.command_launch(args)\n"
            "Path(sys.argv[2]).write_text(str(code), encoding='utf-8')\n"
            "time.sleep(300)\n",
            encoding="utf-8",
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(coordinator),
                str(RUNNER),
                str(marker),
                *self.launch_args("coordinator-job", config),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.env,
            start_new_session=True,
        )
        self.addCleanup(self.kill_group, process.pid)
        provider = int(self.wait_file(ready))
        self.track(provider)
        self.wait_file(marker)
        supervisor_pid = self.meta("coordinator-job")["supervisor_pid"]
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        # The subreaper supervisor survives the coordinator and still holds the
        # repository, so another writer is refused.
        os.kill(supervisor_pid, 0)
        denied = self.launch("blocked-job", config, expected=2)
        self.assertIn("writer lease", denied.stderr)

        os.kill(provider, signal.SIGTERM)
        self.wait_result("coordinator-job")
        self.wait_owner_state("completed")
        self.wait_for(lambda: not self.reservations())
        after_ready = self.root / "ready-after-coordinator"
        after_config = self._sleepy_config("after", 30, after_ready)
        self.launch("after-job", after_config, name="after")
        after_provider = int(self.wait_file(after_ready))
        self.track(after_provider)
        os.kill(after_provider, signal.SIGTERM)
        self.wait_settled("after-job")

    def test_double_fork_setsid_descendant_is_adopted(self) -> None:
        grandchild_file = self.root / "grandchild-pid"
        code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            f"        Path({str(grandchild_file)!r}).write_text(str(os.getpid()))\n"
            "        time.sleep(30)\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        config = self.agent_config("daemon", code)
        self.launch("daemon-job", config, name="daemon")
        grandchild = int(self.wait_file(grandchild_file))
        self.track(grandchild, group=True)
        # The direct provider exited; the worker may even record success, but
        # the adopted setsid grandchild keeps the repository unavailable.
        self.wait_result("daemon-job")
        self.assertEqual(self.result("daemon-job")["state"], "succeeded")
        self.assertEqual(self.owner()["state"], "supervising")
        denied = self.launch("blocked-job", config, name="daemon", expected=2)
        self.assertIn("writer lease", denied.stderr)

        os.kill(grandchild, signal.SIGKILL)
        self.wait_owner_state("completed")
        self.wait_for(lambda: not self.reservations())
        final = self.wait_final("daemon-job")
        self.assertEqual(final["state"], "clean")
        self.assertEqual(final["report"]["count"], 0)
        self.wait_settled("daemon-job")

    # ------------------------------------------------------------------
    # Uncertain guardian loss and explicit recovery
    # ------------------------------------------------------------------

    def test_supervisor_sigkill_requires_evidence_backed_reconcile(self) -> None:
        ready = self.root / "ready-supervisor-kill"
        config = self._sleepy_config("provider", 60, ready)
        self.launch("uncertain-job", config)
        provider = int(self.wait_file(ready))
        self.track(provider, group=True)
        meta = self.meta("uncertain-job")
        supervisor_pid = meta["supervisor_pid"]
        worker_pid = meta["worker_pid"]
        inode = self.lock_stat().st_ino

        os.kill(supervisor_pid, signal.SIGKILL)
        self.wait_pid(supervisor_pid)
        denied = self.launch("blocked-job", config, expected=2)
        self.assertIn("Cannot prove", denied.stderr)
        self.assertIn("lease-reconcile", denied.stderr)

        status = json.loads(
            self.run_cli(
                "lease-status", "--workspace", str(self.repo), "--json"
            ).stdout
        )
        self.assertEqual(status["lease"]["state"], "uncertain_guardian_loss")
        self.assertTrue(status["lease"]["missing_evidence"])
        self.assertTrue(status["lock_inode_stable"])

        # Even after every recorded process exits, a released flock is not
        # proof: the durable unclean owner record still blocks admission.
        os.kill(worker_pid, signal.SIGKILL)
        os.kill(provider, signal.SIGKILL)
        self.wait_pid(worker_pid)
        self.wait_pid(provider)
        still_blocked = self.launch("blocked-again", config, expected=2)
        self.assertIn("Cannot prove", still_blocked.stderr)

        wrong_job = self.run_cli(
            "lease-reconcile",
            "--workspace",
            str(self.repo),
            "--job-id",
            "some-other-job",
            "--operator",
            "Operator",
            "--evidence",
            "Verified no processes remain.",
            expected=2,
        )
        self.assertIn("requested", wrong_job.stderr)

        reconciled = self.run_cli(
            "lease-reconcile",
            "--workspace",
            str(self.repo),
            "--job-id",
            "uncertain-job",
            "--operator",
            "Operator",
            "--evidence",
            "Verified no worker or provider process for uncertain-job remains.",
            "--json",
        )
        payload = json.loads(reconciled.stdout)
        self.assertTrue(payload["reconciled"])
        self.assertTrue(Path(payload["evidence_path"]).is_file())
        self.assertEqual(self.owner()["state"], "reconciled")
        self.assertEqual(self.lock_stat().st_ino, inode)

        after_ready = self.root / "ready-after-reconcile"
        after_config = self._sleepy_config("after", 30, after_ready)
        self.launch("after-job", after_config, name="after")
        after_provider = int(self.wait_file(after_ready))
        self.track(after_provider)
        os.kill(after_provider, signal.SIGTERM)
        self.wait_settled("after-job")

    def test_reconcile_refuses_while_supervisor_is_alive(self) -> None:
        ready = self.root / "ready-live-supervisor"
        config = self._sleepy_config("provider", 30, ready)
        self.launch("live-job", config)
        provider = int(self.wait_file(ready))
        self.track(provider, group=True)
        refused = self.run_cli(
            "lease-reconcile",
            "--workspace",
            str(self.repo),
            "--job-id",
            "live-job",
            "--operator",
            "Operator",
            "--evidence",
            "Trying while the writer still runs.",
            expected=2,
        )
        self.assertIn("currently held", refused.stderr)
        os.kill(provider, signal.SIGTERM)
        self.wait_settled("live-job")

    # ------------------------------------------------------------------
    # Protected branch and dirty-scope admission
    # ------------------------------------------------------------------

    def test_protected_branch_and_dirty_overlap_validation(self) -> None:
        protected_branch = self.git_output("rev-parse", "--abbrev-ref", "HEAD")
        self.git(self.repo, "checkout", "-q", "-b", "feature/work")
        clean = json.loads(
            self.run_cli(
                "validate-workspace",
                "--workspace",
                str(self.repo),
                "--target-branch",
                "feature/work",
                "--protected-branch",
                protected_branch,
                "--json",
            ).stdout
        )
        self.assertEqual(clean["validation"]["branch"], "feature/work")

        (self.repo / "allowed").mkdir()
        (self.repo / "allowed" / "note.txt").write_text("dirty\n", encoding="utf-8")
        overlap = self.run_cli(
            "validate-workspace",
            "--workspace",
            str(self.repo),
            "--target-branch",
            "feature/work",
            "--protected-branch",
            protected_branch,
            "--allow-path",
            "allowed/**",
            expected=2,
        )
        self.assertIn("overlap", overlap.stderr)
        (self.repo / "allowed" / "note.txt").unlink()
        (self.repo / "allowed").rmdir()

        self.git(self.repo, "checkout", "-q", protected_branch)
        protected = self.run_cli(
            "validate-workspace",
            "--workspace",
            str(self.repo),
            "--target-branch",
            "feature/work",
            "--protected-branch",
            protected_branch,
            "--json",
            expected=2,
        )
        self.assertIn("protected", protected.stderr)
        self.git(self.repo, "checkout", "-q", "-b", "feature/real-work")
        (self.repo / "feature.txt").write_text("feature\n", encoding="utf-8")
        self.git(self.repo, "add", "feature.txt")
        self.git(self.repo, "commit", "-qm", "feature")

        # The validator and launch never switch branches, reset, or stage.
        index_before = (self.repo / ".git" / "index").read_bytes()
        head_before = self.git_output("rev-parse", "HEAD")
        ready = self.root / "ready-protected"
        config = self._sleepy_config("provider", 30, ready)
        self.launch(
            "protected-job",
            config,
            extra=(
                "--target-branch",
                "feature/real-work",
                "--protected-branch",
                protected_branch,
            ),
        )
        provider = int(self.wait_file(ready))
        self.track(provider)
        os.kill(provider, signal.SIGTERM)
        self.wait_settled("protected-job")
        self.assertEqual(self.git_output("rev-parse", "HEAD"), head_before)
        self.assertEqual((self.repo / ".git" / "index").read_bytes(), index_before)

    def git_output(self, *args: str) -> str:
        result = subprocess.run(
            ["git", *args], cwd=self.repo, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    # ------------------------------------------------------------------
    # Content-aware integrity
    # ------------------------------------------------------------------

    def test_operator_content_and_index_are_preserved(self) -> None:
        (self.repo / "notes.txt").write_text("committed\n", encoding="utf-8")
        (self.repo / "staged.txt").write_text("committed\n", encoding="utf-8")
        self.git(self.repo, "add", "notes.txt", "staged.txt")
        self.git(self.repo, "commit", "-qm", "notes")
        (self.repo / "notes.txt").write_text(
            "operator dirty bytes\n", encoding="utf-8"
        )
        (self.repo / "staged.txt").write_text(
            "operator staged bytes\n", encoding="utf-8"
        )
        self.git(self.repo, "add", "staged.txt")
        note_bytes = (self.repo / "notes.txt").read_bytes()
        staged_bytes = (self.repo / "staged.txt").read_bytes()
        index_bytes = (self.repo / ".git" / "index").read_bytes()
        staged_state = runner.git_snapshot(self.repo)["staged"]

        code = (
            "from pathlib import Path\n"
            "Path('allowed').mkdir(exist_ok=True)\n"
            "Path('allowed/out.txt').write_text('worker out\\n', encoding='utf-8')\n"
        )
        config = self.agent_config("writer", code)
        self.launch(
            "preserve-job",
            config,
            name="writer",
            extra=("--allow-dirty", "--allow-path", "allowed/**"),
        )
        result = self.wait_result("preserve-job")
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual((self.repo / "notes.txt").read_bytes(), note_bytes)
        self.assertEqual((self.repo / "staged.txt").read_bytes(), staged_bytes)
        self.assertEqual((self.repo / ".git" / "index").read_bytes(), index_bytes)
        snapshot = runner.git_snapshot(self.repo)
        self.assertEqual(snapshot["staged"], staged_state)
        final = self.wait_final("preserve-job")
        self.assertFalse(final["report"]["index_changed"])
        self.assertEqual(final["violations"], [])
        self.assertEqual(final["report"]["paths"], ["allowed/out.txt"])
        self.wait_settled("preserve-job")

    def test_edit_to_already_dirty_denied_file_is_detected(self) -> None:
        (self.repo / "denied.txt").write_text("committed\n", encoding="utf-8")
        self.git(self.repo, "add", "denied.txt")
        self.git(self.repo, "commit", "-qm", "denied")
        (self.repo / "denied.txt").write_text(
            "operator baseline\n", encoding="utf-8"
        )
        code = (
            "from pathlib import Path\n"
            "path = Path('denied.txt')\n"
            "path.write_text(path.read_text() + 'provider edit\\n', encoding='utf-8')\n"
        )
        config = self.agent_config("denier", code)
        self.launch(
            "denied-job",
            config,
            name="denier",
            extra=("--allow-dirty", "--deny-path", "denied.txt"),
        )
        result = self.wait_result_state("denied-job", "scope_violated")
        self.assertIn(
            "denied path changed: denied.txt", result["scope_violations"]
        )
        self.assertIn("provider edit", (self.repo / "denied.txt").read_text())
        final = self.wait_final("denied-job")
        self.assertEqual(final["state"], "violations")
        changed = {item["path"]: item for item in final["report"]["changed"]}
        self.assertIn("denied.txt", changed)
        self.assertIn(
            "content or mode changed", changed["denied.txt"]["reasons"]
        )
        self.wait_settled("denied-job")

    def test_final_fast_write_from_escaped_descendant_is_detected(self) -> None:
        code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            "        time.sleep(0.7)\n"
            "        Path('outside.txt').write_text('fast last write')\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        config = self.agent_config("fastwriter", code)
        self.launch(
            "fast-job",
            config,
            name="fastwriter",
            extra=("--allow-path", "allowed/**"),
        )
        result = self.wait_result_state("fast-job", "scope_violated")
        self.assertIn(
            "out-of-scope path changed: outside.txt", result["scope_violations"]
        )
        final = self.wait_final("fast-job")
        self.assertEqual(final["state"], "violations")
        self.assertIn("outside.txt", final["report"]["paths"])
        self.wait_settled("fast-job")

    def test_rename_delete_and_new_file_attribution(self) -> None:
        (self.repo / "src").mkdir()
        for name in ("a.txt", "b.txt"):
            (self.repo / "src" / name).write_text("content\n", encoding="utf-8")
        self.git(self.repo, "add", "src")
        self.git(self.repo, "commit", "-qm", "src")
        code = (
            "import os, subprocess\n"
            "from pathlib import Path\n"
            "subprocess.run(['git', 'mv', 'src/a.txt', 'src/a-renamed.txt'], check=True)\n"
            "os.remove('src/b.txt')\n"
            "Path('allowed').mkdir(exist_ok=True)\n"
            "Path('allowed/ok.txt').write_text('allowed\\n')\n"
            "Path('outside').mkdir(exist_ok=True)\n"
            "Path('outside/new.txt').write_text('new\\n')\n"
        )
        config = self.agent_config("shuffler", code)
        self.launch(
            "shuffle-job",
            config,
            name="shuffler",
            extra=("--allow-path", "allowed/**"),
        )
        result = self.wait_result_state("shuffle-job", "scope_violated")
        violations = result["scope_violations"]
        for path in (
            "src/a.txt",
            "src/a-renamed.txt",
            "src/b.txt",
            "outside/new.txt",
        ):
            self.assertIn(f"out-of-scope path changed: {path}", violations)
        self.assertNotIn("out-of-scope path changed: allowed/ok.txt", violations)
        final = self.wait_final("shuffle-job")
        reasons = {
            item["path"]: item["reasons"] for item in final["report"]["changed"]
        }
        self.assertTrue(any("deleted" in value for value in reasons["src/b.txt"]))
        self.assertTrue(
            any("rename" in value for value in reasons["src/a-renamed.txt"]),
            reasons["src/a-renamed.txt"],
        )
        self.assertTrue(
            any("rename" in value for value in reasons["src/a.txt"]),
            reasons["src/a.txt"],
        )
        self.wait_settled("shuffle-job")

    def test_unsupported_snapshot_fails_closed(self) -> None:
        oversized = self.repo / "oversized.bin"
        with oversized.open("wb") as handle:
            handle.truncate(33 * 1024 * 1024)
        denied = self.launch(
            "oversized-job",
            self.agent_config("provider", "pass\n"),
            expected=2,
        )
        self.assertIn("snapshot refused", denied.stderr)
        self.assertIn("content-hash bound", denied.stderr)
        oversized.unlink()
        self.assertFalse(self.job_path("oversized-job").exists())

    # ------------------------------------------------------------------
    # Startup/hand-off failure and timeout
    # ------------------------------------------------------------------

    def test_supervisor_handoff_failure_releases_lease(self) -> None:
        config = self._sleepy_config("provider", 30, self.root / "never-ready")
        args = runner.build_parser().parse_args(
            self.launch_args("handoff-job", config)
        )
        runner.validate_cli_args(args)

        def intercept(argv, *popen_args, **popen_kwargs):
            if isinstance(argv, (list, tuple)) and "--lock-fd" in argv:
                class ExitedSupervisor:
                    pid = os.getpid()

                    def poll(self):
                        return 1

                return ExitedSupervisor()
            return real_popen(argv, *popen_args, **popen_kwargs)

        real_popen = subprocess.Popen
        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ), mock.patch.object(runner.subprocess, "Popen", side_effect=intercept):
            with self.assertRaises(runner.RunnerError) as caught:
                runner.command_launch(args)
        self.assertIn("before publishing ownership", str(caught.exception))
        result = self.result("handoff-job")
        self.assertEqual(result["state"], "failed")
        failed_status = self.status("handoff-job")
        self.assertEqual(failed_status["state"], "failed")
        self.assertTrue(failed_status["completion_finalized"])
        self.assertEqual(self.owner()["state"], "failed_admission")
        self.assertEqual(self.reservations(), [])
        # The same never-unlinked lock inode is immediately reusable.
        inode = self.lock_stat().st_ino
        ready = self.root / "ready-after-handoff"
        retry_config = self._sleepy_config("retry", 30, ready)
        self.launch("retry-job", retry_config, name="retry")
        provider = int(self.wait_file(ready))
        self.track(provider)
        self.assertEqual(self.lock_stat().st_ino, inode)
        os.kill(provider, signal.SIGTERM)
        self.wait_settled("retry-job")

    def test_cancel_releases_lease_after_provider_exit(self) -> None:
        ready = self.root / "ready-cancel"
        config = self._sleepy_config("provider", 30, ready)
        self.launch("cancel-job", config)
        provider = int(self.wait_file(ready))
        self.track(provider, group=True)
        cancellation = json.loads(
            self.run_cli("cancel", "cancel-job", "--json").stdout
        )
        self.assertEqual(cancellation["state"], "cancelling")
        result = self.wait_result("cancel-job")
        self.assertEqual(result["state"], "cancelled")
        self.wait_owner_state("completed")
        self.wait_for(lambda: not self.reservations())
        self.wait_pid(provider)
        retry_ready = self.root / "ready-after-cancel"
        retry_config = self._sleepy_config("retry", 30, retry_ready)
        self.launch("retry-job", retry_config, name="retry")
        retry_provider = int(self.wait_file(retry_ready))
        self.track(retry_provider)
        os.kill(retry_provider, signal.SIGTERM)
        self.wait_settled("retry-job")

    def test_cancel_terminates_escaped_descendant_after_result(self) -> None:
        grandchild_file = self.root / "cancel-grandchild"
        code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            f"        Path({str(grandchild_file)!r}).write_text(str(os.getpid()))\n"
            "        time.sleep(60)\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        config = self.agent_config("daemon", code)
        self.launch("escaped-cancel", config, name="daemon")
        grandchild = int(self.wait_file(grandchild_file))
        self.track(grandchild, group=True)
        self.wait_result("escaped-cancel")
        self.assertEqual(self.owner()["state"], "supervising")
        cancellation = json.loads(
            self.run_cli("cancel", "escaped-cancel", "--json").stdout
        )
        self.assertTrue(cancellation["lease_active"])
        self.wait_owner_state("completed", timeout=20)
        final = self.wait_final("escaped-cancel")
        self.assertEqual(final["descendants"]["terminated"], "cancel")
        self.wait_pid(grandchild)
        self.wait_for(lambda: not self.reservations())
        retry_ready = self.root / "ready-after-escaped-cancel"
        retry_config = self._sleepy_config("retry", 30, retry_ready)
        self.launch("retry-job", retry_config, name="retry")
        retry_provider = int(self.wait_file(retry_ready))
        self.track(retry_provider)
        os.kill(retry_provider, signal.SIGTERM)
        self.wait_settled("retry-job")

    def test_supervisor_subreaper_failure_is_recoverable(self) -> None:
        identity = runner.canonical_workspace(self.repo)
        b2 = runner.b2_module()
        job_id = "subreaper-job"
        job_dir = self.job_path(job_id)
        job_dir.mkdir(parents=True)
        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ):
            lease = b2.acquire_writer_lease(identity, job_id, job_dir)
            runner.write_json(
                job_dir / "meta.json",
                {
                    "job_id": job_id,
                    "workspace": str(self.repo),
                    "workspace_lease": lease.metadata(),
                    "state": "starting",
                },
            )
            # ``run_supervisor`` normally owns a dedicated process and ignores
            # terminal signals for that process's lifetime. This test calls it
            # in-process, so restore the test runner's dispositions; otherwise
            # later subprocesses inherit SIG_IGN for SIGTERM/SIGINT/SIGHUP.
            previous_signals = {
                name: signal.getsignal(name)
                for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
            }
            try:
                with mock.patch.object(
                    b2,
                    "set_child_subreaper",
                    side_effect=RuntimeError("subreaper unavailable"),
                ):
                    code = b2.run_supervisor(
                        job_dir, lease.descriptor, lease.epoch
                    )
            finally:
                for name, handler in previous_signals.items():
                    try:
                        signal.signal(name, handler)
                    except (OSError, ValueError, TypeError):
                        pass
        self.assertEqual(code, 3)
        owner = self.owner()
        self.assertEqual(owner["state"], "failed_admission")
        self.assertIn("subreaper unavailable", owner["error"])
        self.assertFalse((job_dir / "result.json").exists())
        # No worker was spawned, so the same inode admits the next launch.
        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ):
            retry = b2.acquire_writer_lease(identity, "retry-job", job_dir)
            self.assertNotEqual(retry.epoch, owner["epoch"])
            retry.abort("test cleanup")

    def test_timeout_terminates_escaped_descendants_and_releases(self) -> None:
        grandchild_file = self.root / "timeout-grandchild"
        code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            f"        Path({str(grandchild_file)!r}).write_text(str(os.getpid()))\n"
            "        time.sleep(60)\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        config = self.agent_config("escapee", code)
        self.launch(
            "timeout-job",
            config,
            name="escapee",
            extra=("--timeout-seconds", "1"),
        )
        grandchild = int(self.wait_file(grandchild_file))
        self.track(grandchild, group=True)
        result = self.wait_result_state("timeout-job", "timed_out", timeout=30)
        self.assertEqual(result["state"], "timed_out")
        self.assertTrue(result.get("descendant_timeout"))
        self.wait_owner_state("completed")
        self.wait_pid(grandchild)
        self.wait_for(lambda: not self.reservations())
        final = self.wait_final("timeout-job")
        self.assertEqual(final["descendants"]["terminated"], "timeout")


    # ------------------------------------------------------------------
    # B2-C1: preliminary worker results never authorize completion
    # ------------------------------------------------------------------

    def test_delayed_descendant_cannot_complete_before_final_check(self) -> None:
        marker = self.root / "late-child-ran"
        code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            "        time.sleep(4)\n"
            "        Path('outside.txt').write_text('late write')\n"
            f"        Path({str(marker)!r}).write_text('ran')\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        config = self.agent_config("late-writer", code)
        self.launch(
            "late-job",
            config,
            name="late-writer",
            extra=("--allow-path", "allowed/**"),
        )
        # The direct provider exited, so the worker published its preliminary
        # success while the adopted setsid child still runs.
        self.wait_result("late-job")
        status = json.loads(
            self.run_cli("status", "late-job", "--json").stdout
        )
        self.assertEqual(status["state"], "running")
        self.assertFalse(status["completion_finalized"])
        self.assertNotEqual(status["acceptance_state"], "awaiting_review")
        self.assertNotEqual(status["acceptance_state"], "accepted")
        waited = self.run_cli(
            "wait",
            "late-job",
            "--timeout-seconds",
            "1",
            "--poll-seconds",
            "0.1",
            "--json",
            expected=2,
        )
        self.assertNotEqual(json.loads(waited.stdout)["state"], "succeeded")
        refused = self.run_cli(
            "record-review",
            "late-job",
            "--verdict",
            "accepted",
            "--reviewer",
            "Independent",
            "--test",
            "focused: passed",
            "--json",
            expected=2,
        )
        self.assertIn("successful execution", refused.stderr)

        result = self.wait_result_state("late-job", "scope_violated", timeout=30)
        self.assertIn(
            "out-of-scope path changed: outside.txt", result["scope_violations"]
        )
        self.assertTrue(marker.is_file())
        final = self.wait_final("late-job")
        self.assertEqual(final["state"], "violations")
        self.assertIn("outside.txt", final["report"]["paths"])
        self.wait_settled("late-job")

    def test_preliminary_terminal_outcomes_wait_for_full_drain(self) -> None:
        # A direct nonzero exit still leaves an adopted setsid grandchild that
        # keeps the repository leased; the public status must stay pending and
        # the final failure must be preserved after the drain.
        failed_marker = self.root / "failed-grandchild"
        failed_code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            "        time.sleep(8)\n"
            f"        Path({str(failed_marker)!r}).write_text('ran')\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(1)\n"
        )
        failed_config = self.agent_config("fail-late", failed_code)
        self.launch("failed-late-job", failed_config, name="fail-late")
        raw = self.wait_result("failed-late-job")
        self.assertEqual(raw["state"], "failed")
        pending = self.status("failed-late-job")
        self.assertEqual(pending["state"], "running")
        self.assertFalse(pending["completion_finalized"])
        self.assertEqual(pending["preliminary_state"], "failed")
        early = self.run_cli(
            "wait",
            "failed-late-job",
            "--timeout-seconds",
            "1",
            "--poll-seconds",
            "0.1",
            "--json",
            expected=2,
        )
        self.assertEqual(json.loads(early.stdout)["state"], "running")
        finished = self.run_cli(
            "wait",
            "failed-late-job",
            "--timeout-seconds",
            "30",
            "--poll-seconds",
            "0.2",
            "--json",
            expected=1,
        )
        final_status = json.loads(finished.stdout)
        self.assertEqual(final_status["state"], "failed")
        self.assertTrue(final_status["completion_finalized"])
        self.assertTrue(failed_marker.is_file())
        self.wait_settled("failed-late-job")

        # Cancellation of a live direct provider with an escaped descendant:
        # result.json says cancelled, but status/wait remain pending until the
        # supervisor proves the adopted tree exited.
        cancel_marker = self.root / "cancel-grandchild"
        cancel_code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            f"        Path({str(cancel_marker)!r}).write_text(str(os.getpid()))\n"
            "        time.sleep(6)\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "time.sleep(60)\n"
        )
        cancel_config = self.agent_config("cancel-drain", cancel_code)
        self.launch("cancel-drain-job", cancel_config, name="cancel-drain")
        grandchild = int(self.wait_file(cancel_marker))
        self.track(grandchild, group=True)
        self.run_cli("cancel", "cancel-drain-job", "--json")
        raw_cancel = self.wait_result("cancel-drain-job")
        self.assertEqual(raw_cancel["state"], "cancelled")
        cancel_pending = self.status("cancel-drain-job")
        self.assertEqual(cancel_pending["state"], "running")
        self.assertFalse(cancel_pending["completion_finalized"])
        self.assertEqual(cancel_pending["preliminary_state"], "cancelled")
        early_cancel = self.run_cli(
            "wait",
            "cancel-drain-job",
            "--timeout-seconds",
            "1",
            "--poll-seconds",
            "0.1",
            "--json",
            expected=2,
        )
        self.assertNotEqual(
            json.loads(early_cancel.stdout)["state"], "cancelled"
        )
        cancelled = self.run_cli(
            "wait",
            "cancel-drain-job",
            "--timeout-seconds",
            "30",
            "--poll-seconds",
            "0.2",
            "--json",
            expected=1,
        )
        cancelled_status = json.loads(cancelled.stdout)
        self.assertEqual(cancelled_status["state"], "cancelled")
        self.assertTrue(cancelled_status["completion_finalized"])
        self.wait_pid(grandchild)
        self.wait_settled("cancel-drain-job")

        # An early scope violation is likewise preliminary: the adopted
        # descendant must finish before the final integrity report and the
        # externally visible scope_violated outcome.
        scope_marker = self.root / "scope-grandchild"
        scope_code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "Path('denied.txt').write_text('bad\\n', encoding='utf-8')\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            "        time.sleep(8)\n"
            f"        Path({str(scope_marker)!r}).write_text('ran')\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        scope_config = self.agent_config("scope-late", scope_code)
        self.launch(
            "scope-late-job",
            scope_config,
            name="scope-late",
            extra=("--deny-path", "denied.txt"),
        )
        raw_scope = self.wait_result("scope-late-job")
        self.assertEqual(raw_scope["state"], "scope_violated")
        self.assertIn(
            "denied path changed: denied.txt", raw_scope["scope_violations"]
        )
        scope_pending = self.status("scope-late-job")
        self.assertEqual(scope_pending["state"], "running")
        self.assertFalse(scope_pending["completion_finalized"])
        self.assertEqual(scope_pending["preliminary_state"], "scope_violated")
        early_scope = self.run_cli(
            "wait",
            "scope-late-job",
            "--timeout-seconds",
            "1",
            "--poll-seconds",
            "0.1",
            "--json",
            expected=2,
        )
        self.assertNotEqual(
            json.loads(early_scope.stdout)["state"], "scope_violated"
        )
        violated = self.run_cli(
            "wait",
            "scope-late-job",
            "--timeout-seconds",
            "30",
            "--poll-seconds",
            "0.2",
            "--json",
            expected=1,
        )
        violated_status = json.loads(violated.stdout)
        self.assertEqual(violated_status["state"], "scope_violated")
        self.assertTrue(violated_status["completion_finalized"])
        self.assertTrue(scope_marker.is_file())
        self.assertTrue((self.repo / "denied.txt").is_file())
        self.wait_settled("scope-late-job")

    def test_missing_or_corrupt_completion_evidence_blocks_acceptance(self) -> None:
        config = self.agent_config("noop", "pass\n")
        self.launch("evidence-job", config, name="noop")
        self.wait_settled("evidence-job")
        self.assertEqual(self.result("evidence-job")["state"], "succeeded")
        completed = json.loads(
            self.run_cli("status", "evidence-job", "--json").stdout
        )
        self.assertEqual(completed["state"], "succeeded")
        self.assertTrue(completed["completion_finalized"])

        final_path = self.job_path("evidence-job") / "final-check.json"
        original_final = final_path.read_bytes()
        final_path.unlink()
        missing = json.loads(
            self.run_cli("status", "evidence-job", "--json").stdout
        )
        self.assertNotEqual(missing["state"], "succeeded")
        self.assertFalse(missing["completion_finalized"])
        self.assertIn("final check", missing["completion_blocked"])
        refused = self.run_cli(
            "record-review",
            "evidence-job",
            "--verdict",
            "accepted",
            "--reviewer",
            "Independent",
            "--test",
            "focused: passed",
            "--json",
            expected=2,
        )
        self.assertIn("successful execution", refused.stderr)

        final_path.write_bytes(b"{not valid json")
        corrupt = json.loads(
            self.run_cli("status", "evidence-job", "--json").stdout
        )
        self.assertNotEqual(corrupt["state"], "succeeded")
        self.assertFalse(corrupt["completion_finalized"])
        self.assertIn("unreadable", corrupt["completion_blocked"])
        final_path.write_bytes(original_final)

        meta = self.meta("evidence-job")
        owner_path = Path(meta["workspace_lease"]["owner_path"])
        original_owner = owner_path.read_bytes()
        owner_path.write_bytes(b"{broken owner")
        corrupt_owner = json.loads(
            self.run_cli("status", "evidence-job", "--json").stdout
        )
        self.assertNotEqual(corrupt_owner["state"], "succeeded")
        self.assertFalse(corrupt_owner["completion_finalized"])
        self.assertIn("unreadable", corrupt_owner["completion_blocked"])
        owner_path.write_bytes(original_owner)

        recovered = json.loads(
            self.run_cli("status", "evidence-job", "--json").stdout
        )
        self.assertEqual(recovered["state"], "succeeded")
        self.assertTrue(recovered["completion_finalized"])

    # ------------------------------------------------------------------
    # B2-C5: immutable per-job completion receipts survive later epochs
    # ------------------------------------------------------------------

    def status(self, job_id: str, home: Path | None = None) -> dict:
        env = self.env if home is None else {**os.environ, "AGENT_ORCHESTRATOR_HOME": str(home)}
        return json.loads(
            self.run_cli("status", job_id, "--json", env=env).stdout
        )

    def review_accepted(self, job_id: str, home: Path | None = None) -> None:
        env = self.env if home is None else {**os.environ, "AGENT_ORCHESTRATOR_HOME": str(home)}
        self.run_cli(
            "record-review",
            job_id,
            "--verdict",
            "accepted",
            "--reviewer",
            "Independent",
            "--test",
            "focused: passed",
            "--notes",
            "Independent focused review.",
            "--json",
            env=env,
        )

    def test_sequential_epochs_keep_per_job_completion_receipts(self) -> None:
        noop = self.agent_config("noop", "pass\n")
        self.launch("history-one", noop, name="noop")
        self.wait_settled("history-one")
        receipt_one = self.job_path("history-one") / "lease-completion.json"
        self.assertTrue(receipt_one.is_file())
        receipt_one_bytes = receipt_one.read_bytes()
        self.review_accepted("history-one")
        first = self.status("history-one")
        self.assertEqual(first["state"], "succeeded")
        self.assertTrue(first["completion_finalized"])
        self.assertEqual(first["acceptance_state"], "accepted")

        # A second job replaces owner.json with a new epoch and depends on the
        # first job's accepted completion.
        self.launch(
            "history-two",
            noop,
            name="noop",
            extra=("--depends-on", "history-one"),
        )
        self.wait_settled("history-two")
        receipt_two = self.job_path("history-two") / "lease-completion.json"
        self.assertTrue(receipt_two.is_file())
        self.assertNotEqual(receipt_one.read_bytes(), receipt_two.read_bytes())
        self.assertEqual(receipt_one.read_bytes(), receipt_one_bytes)
        second = self.status("history-two")
        self.assertEqual(second["state"], "succeeded")
        self.assertTrue(second["completion_finalized"])

        # While the newest epoch is still running, every older receipt remains
        # verifiable and the accepted dependency remains accepted.
        ready = self.root / "ready-history-three"
        long_config = self._sleepy_config("provider", 30, ready)
        self.launch(
            "history-three",
            long_config,
            extra=("--depends-on", "history-one"),
        )
        provider = int(self.wait_file(ready))
        self.track(provider)
        owner = self.owner()
        self.assertEqual(owner["job_id"], "history-three")
        self.assertIn(owner["state"], {"admission", "supervising"})
        for job_id in ("history-one", "history-two"):
            historical = self.status(job_id)
            self.assertEqual(historical["state"], "succeeded", job_id)
            self.assertTrue(historical["completion_finalized"], job_id)
            if job_id == "history-one":
                self.assertEqual(historical["acceptance_state"], "accepted")
        self.assertEqual(receipt_one.read_bytes(), receipt_one_bytes)

        os.kill(provider, signal.SIGTERM)
        self.wait_settled("history-three")
        self.assertEqual(self.status("history-one")["state"], "succeeded")
        self.assertEqual(
            self.status("history-one")["acceptance_state"], "accepted"
        )
        self.assertEqual(self.status("history-two")["state"], "succeeded")
        self.assertEqual(receipt_one.read_bytes(), receipt_one_bytes)

    def test_malformed_or_mismatched_receipts_fail_closed(self) -> None:
        noop = self.agent_config("noop", "pass\n")
        self.launch("receipt-defect", noop, name="noop")
        self.wait_settled("receipt-defect")
        receipt_path = self.job_path("receipt-defect") / "lease-completion.json"
        original = receipt_path.read_bytes()
        record = json.loads(original)
        self.assertEqual(self.status("receipt-defect")["state"], "succeeded")

        def assert_blocked(fragment: str) -> None:
            status = self.status("receipt-defect")
            self.assertNotEqual(status["state"], "succeeded")
            self.assertFalse(status["completion_finalized"])
            self.assertIn(fragment, status["completion_blocked"])
            denied = self.launch(
                "receipt-dependent",
                noop,
                name="noop",
                extra=("--depends-on", "receipt-defect"),
                expected=2,
            )
            self.assertIn("Dependency", denied.stderr)
            self.assertFalse(self.job_path("receipt-dependent").exists())

        receipt_path.write_bytes(b"{not valid json")
        assert_blocked("unreadable")

        mismatched_job = {**record, "job_id": "another-job"}
        receipt_path.write_text(json.dumps(mismatched_job), encoding="utf-8")
        assert_blocked("another job")

        mismatched_epoch = {**record, "epoch": "f" * 32}
        receipt_path.write_text(json.dumps(mismatched_epoch), encoding="utf-8")
        assert_blocked("another lease epoch")

        mismatched_final = {
            **record,
            "final_check": {
                **record["final_check"],
                "sha256": "0" * 64,
            },
        }
        receipt_path.write_text(json.dumps(mismatched_final), encoding="utf-8")
        assert_blocked("does not match")

        receipt_path.unlink()
        assert_blocked("receipt is missing")

        receipt_path.write_bytes(original)
        recovered = self.status("receipt-defect")
        self.assertEqual(recovered["state"], "succeeded")
        self.assertTrue(recovered["completion_finalized"])

    def test_receipt_recovers_crash_between_terminal_publication_steps(self) -> None:
        noop = self.agent_config("noop", "pass\n")
        self.launch("owner-crash-job", noop, name="noop")
        self.wait_settled("owner-crash-job")
        receipt_path = self.job_path("owner-crash-job") / "lease-completion.json"
        receipt_bytes = receipt_path.read_bytes()
        owner = self.owner()
        self.assertEqual(owner["state"], "completed")

        # Simulate a supervisor crash after the durable receipt was published
        # but before owner.json became terminal: the lock is free, the receipt
        # and final check are intact, and the owner still says supervising.
        owner["state"] = "supervising"
        owner.pop("completed_at", None)
        runner.write_json(
            Path(self.meta("owner-crash-job")["workspace_lease"]["owner_path"]),
            owner,
        )
        still_succeeded = self.status("owner-crash-job")
        self.assertEqual(still_succeeded["state"], "succeeded")
        self.assertTrue(still_succeeded["completion_finalized"])

        # Without the durable receipt the very same crash state is unknowable:
        # completion is not exposed and admission stays fail-closed.
        receipt_path.unlink()
        missing = self.status("owner-crash-job")
        self.assertNotEqual(missing["state"], "succeeded")
        self.assertFalse(missing["completion_finalized"])
        denied = self.launch(
            "cannot-take-over", noop, name="noop", expected=2
        )
        self.assertIn("Cannot prove", denied.stderr)
        receipt_path.write_bytes(receipt_bytes)

        lease_status = json.loads(
            self.run_cli(
                "lease-status", "--workspace", str(self.repo), "--json"
            ).stdout
        )
        self.assertEqual(lease_status["lease"]["state"], "completed_receipt")
        self.assertFalse(lease_status["lease"]["blocked"])
        self.assertEqual(
            lease_status["lease"]["recovery"]["kind"], "completion_receipt"
        )
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

        # The proven receipt also permits the next admission and the new owner
        # record preserves why takeover was safe.
        self.launch("after-owner-crash", noop, name="noop")
        self.wait_settled("after-owner-crash")
        replacement = self.owner()
        self.assertEqual(replacement["job_id"], "after-owner-crash")
        self.assertEqual(replacement["recovery"]["kind"], "completion_receipt")
        self.assertEqual(replacement["recovery"]["job_id"], "owner-crash-job")
        self.assertEqual(
            self.status("owner-crash-job")["state"], "succeeded"
        )
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

    # ------------------------------------------------------------------
    # B2-C2: discoverable legacy/unleased writers block admission
    # ------------------------------------------------------------------

    def test_live_legacy_writer_blocks_git_admission(self) -> None:
        legacy_id = "legacy-live"
        legacy_dir = self.job_path(legacy_id)
        legacy_dir.mkdir(parents=True)
        sleeper = self.sleeper()
        runner.write_json(
            legacy_dir / "meta.json",
            {
                "job_id": legacy_id,
                "workspace": str(self.repo),
                "canonical_workspace": str(self.repo),
                "state": "running",
                "child_pid": sleeper,
                "created_at": runner.utc_now(),
            },
        )
        config = self.agent_config("noop", "pass\n")
        denied = self.launch(
            "new-job",
            config,
            name="noop",
            extra=("--allow-concurrent-workspace",),
            expected=2,
        )
        self.assertIn("writer lease", denied.stderr)
        self.assertIn(legacy_id, denied.stderr)

        os.kill(sleeper, signal.SIGKILL)
        self.wait_pid(sleeper)
        # Dead legacy metadata with no result is stale and cannot wedge
        # admission, while never having overlapped a live process.
        self.launch("new-job", config, name="noop")
        self.wait_result_state("new-job", "succeeded")
        self.wait_settled("new-job")

    def test_unreadable_lease_evidence_blocks_git_admission(self) -> None:
        blocked_id = "blocked-evidence"
        blocked_dir = self.job_path(blocked_id)
        blocked_dir.mkdir(parents=True)
        sleeper = self.sleeper()
        runner.write_json(
            blocked_dir / "meta.json",
            {
                "job_id": blocked_id,
                "workspace": str(self.repo),
                "canonical_workspace": str(self.repo),
                "state": "running",
                "child_pid": sleeper,
                "workspace_lease": {
                    "epoch": "0" * 32,
                    "owner_path": str(self.root / "missing-owner.json"),
                    "lock_path": str(self.root / "missing-lock"),
                },
                "created_at": runner.utc_now(),
            },
        )
        config = self.agent_config("noop", "pass\n")
        denied = self.launch("new-job", config, name="noop", expected=2)
        self.assertIn("durable lease evidence is unreadable", denied.stderr)
        self.assertIn(blocked_id, denied.stderr)
        os.kill(sleeper, signal.SIGKILL)
        self.wait_pid(sleeper)

    def test_cross_state_reservation_blocks_and_completed_handoff_admits(self) -> None:
        config = self.agent_config("noop", "pass\n")
        sleeper = self.sleeper()
        other_home = self.root / "other-state"
        other_job_dir = other_home / "jobs" / "cross-job"
        self.write_reservation(
            "cross-job", other_job_dir, sleeper, home=other_home
        )
        denied = self.launch("first-new-job", config, name="noop", expected=2)
        self.assertIn("writer lease", denied.stderr)
        self.assertIn("cross-job", denied.stderr)
        os.kill(sleeper, signal.SIGKILL)
        self.wait_pid(sleeper)
        # The dead reservation is pruned and admission proceeds.
        self.launch("first-new-job", config, name="noop")
        self.wait_result_state("first-new-job", "succeeded")
        self.wait_settled("first-new-job")

        env_b = self.alternate_env("state-two")
        self.launch("completed-handoff", config, env=env_b, name="noop")
        self.wait_settled("completed-handoff", home=self.root / "state-two")
        completed_meta = self.meta(
            "completed-handoff", home=self.root / "state-two"
        )
        completed_dir = self.job_path(
            "completed-handoff", home=self.root / "state-two"
        )
        self.assertIsInstance(completed_meta["workspace_lease"]["epoch"], str)
        # A release hand-off may leave a reservation whose recorded coordinator
        # PID (here the still-live test process) outlives the terminal owner.
        # The durable completed owner proves no writer remains, so admission
        # must proceed instead of mistaking the hand-off for a live writer.
        self.write_reservation(
            "completed-handoff",
            completed_dir,
            os.getpid(),
            home=self.root / "state-two",
        )
        self.launch("handoff-new-job", config, name="noop")
        self.wait_result_state("handoff-new-job", "succeeded")
        self.wait_settled("handoff-new-job")

        # A lingering old reservation can outlive the owner record it named:
        # the current owner now belongs to a later epoch. The old job's own
        # post-drain final check still proves it cannot own the checkout, so
        # the reservation is not mistaken for a live writer.
        self.write_reservation(
            "completed-handoff",
            completed_dir,
            os.getpid(),
            home=self.root / "state-two",
        )
        self.launch("later-owner-job", config, name="noop")
        self.wait_result_state("later-owner-job", "succeeded")
        self.wait_settled("later-owner-job")

    # ------------------------------------------------------------------
    # B2-C3: lease acquisition precedes the authoritative baseline
    # ------------------------------------------------------------------

    def test_lease_precedes_baseline_snapshot(self) -> None:
        config = self.agent_config("noop", "pass\n")
        args = runner.build_parser().parse_args(
            self.launch_args("ordering-job", config, name="noop")
        )
        runner.validate_cli_args(args)
        identity = runner.canonical_workspace(self.repo)
        b2 = runner.b2_module()
        real_snapshot = b2.snapshot_workspace
        real_spawn = runner.spawn_lease_supervisor
        observed: dict[str, object] = {}
        supervisors: list[subprocess.Popen] = []

        def spy(workspace, *, strict=True, extra_paths=None):
            owner = b2.read_owner(identity)
            observed["owner_state"] = owner.get("state") if owner else None
            observed["owner_job_id"] = owner.get("job_id") if owner else None
            return real_snapshot(
                workspace, strict=strict, extra_paths=extra_paths
            )

        def capture_spawn(path, lease):
            process = real_spawn(path, lease)
            supervisors.append(process)
            return process

        with mock.patch.dict(
            os.environ, {"AGENT_ORCHESTRATOR_HOME": str(self.state)}
        ), mock.patch.object(
            b2, "snapshot_workspace", side_effect=spy
        ), mock.patch.object(
            runner, "spawn_lease_supervisor", side_effect=capture_spawn
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                runner.command_launch(args)
        self.assertEqual(observed["owner_job_id"], "ordering-job")
        self.assertIn(observed["owner_state"], {"admission", "supervising"})
        meta = self.meta("ordering-job")
        self.assertEqual(
            meta["git_baseline"]["lease_epoch"],
            meta["workspace_lease"]["epoch"],
        )
        self.wait_result_state("ordering-job", "succeeded")
        self.wait_settled("ordering-job")

    def test_prior_writer_changes_become_next_baseline(self) -> None:
        writer_a = self.agent_config(
            "writer-a",
            "from pathlib import Path\n"
            "Path('tracked.txt').write_text('written by A\\n', encoding='utf-8')\n",
        )
        self.launch("writer-a-job", writer_a, name="writer-a")
        self.wait_settled("writer-a-job")
        self.assertEqual(
            (self.repo / "tracked.txt").read_text(encoding="utf-8"),
            "written by A\n",
        )

        noop = self.agent_config("noop", "pass\n")
        rejected = self.launch("writer-b-job", noop, name="noop", expected=2)
        self.assertIn("uncommitted changes", rejected.stderr)
        self.assertFalse(self.job_path("writer-b-job").exists())
        self.assertEqual(self.owner()["state"], "failed_admission")

        # The prior writer's dirty change is part of the admitted baseline, so
        # it is never attributed to this job and no snapshot was taken before
        # the lease was held.
        self.launch(
            "writer-c-job", noop, name="noop", extra=("--allow-dirty",)
        )
        result = self.wait_result_state("writer-c-job", "succeeded")
        self.assertEqual(result["scope_violations"], [])
        final = self.wait_final("writer-c-job")
        self.assertEqual(final["report"]["paths"], [])
        self.assertEqual(final["violations"], [])
        meta = self.meta("writer-c-job")
        self.assertEqual(
            meta["git_baseline"]["lease_epoch"],
            meta["workspace_lease"]["epoch"],
        )
        self.wait_settled("writer-c-job")

    # ------------------------------------------------------------------
    # B2-C4: bounded explicit scope observation includes ignored files
    # ------------------------------------------------------------------

    def test_ignored_denied_scope_paths_are_observed(self) -> None:
        secret = "SUPER-SECRET-VALUE-123"
        (self.repo / ".gitignore").write_text(
            ".env*\nmany/**\n", encoding="utf-8"
        )
        self.git(self.repo, "add", ".gitignore")
        self.git(self.repo, "commit", "-qm", "ignore rules")
        (self.repo / ".env.local").write_text(secret, encoding="utf-8")
        code = (
            "from pathlib import Path\n"
            "path = Path('.env.local')\n"
            "path.write_text(path.read_text() + 'provider-edit\\n', encoding='utf-8')\n"
            "Path('allowed').mkdir(exist_ok=True)\n"
            "Path('allowed/ok.txt').write_text('ok\\n', encoding='utf-8')\n"
        )
        config = self.agent_config("env-writer", code)
        self.launch(
            "ignored-denied",
            config,
            name="env-writer",
            extra=(
                "--allow-dirty",
                "--deny-path",
                ".env*",
                "--allow-path",
                "allowed/**",
            ),
        )
        result = self.wait_result_state("ignored-denied", "scope_violated")
        self.assertIn(
            "denied path changed: .env.local", result["scope_violations"]
        )
        final_text = (
            self.job_path("ignored-denied") / "final-check.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn(secret, final_text)
        self.assertNotIn("provider-edit", final_text)
        final = self.wait_final("ignored-denied")
        changed = {item["path"]: item for item in final["report"]["changed"]}
        self.assertIn(".env.local", changed)
        self.assertIn("content or mode changed", changed[".env.local"]["reasons"])
        # User bytes are preserved; nothing is restored automatically.
        self.assertTrue(
            (self.repo / ".env.local").read_text(encoding="utf-8").startswith(
                secret
            )
        )
        self.wait_settled("ignored-denied")

        # An unchanged preexisting ignored denied file is not a violation.
        noop = self.agent_config("noop", "pass\n")
        self.launch(
            "ignored-clean",
            noop,
            name="noop",
            extra=(
                "--allow-dirty",
                "--deny-path",
                ".env*",
                "--allow-path",
                "allowed/**",
            ),
        )
        clean = self.wait_result_state("ignored-clean", "succeeded")
        self.assertEqual(clean["scope_violations"], [])
        clean_final = self.wait_final("ignored-clean")
        self.assertEqual(clean_final["report"]["paths"], [])
        self.wait_settled("ignored-clean")

        # A late escaped descendant creating a new ignored denied file is
        # observed by the post-drain final check.
        late_code = (
            "import os,time\n"
            "from pathlib import Path\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    again = os.fork()\n"
            "    if again == 0:\n"
            "        time.sleep(1.0)\n"
            "        Path('.env.late').write_text('late secret', encoding='utf-8')\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n"
        )
        late_config = self.agent_config("late-env", late_code)
        self.launch(
            "ignored-late",
            late_config,
            name="late-env",
            extra=(
                "--allow-dirty",
                "--deny-path",
                ".env*",
                "--allow-path",
                "allowed/**",
            ),
        )
        late = self.wait_result_state("ignored-late", "scope_violated")
        self.assertIn(
            "denied path changed: .env.late", late["scope_violations"]
        )
        self.wait_settled("ignored-late")

    def test_bounded_scope_observation_refuses_oversized_enumeration(self) -> None:
        (self.repo / ".gitignore").write_text("many/**\n", encoding="utf-8")
        self.git(self.repo, "add", ".gitignore")
        self.git(self.repo, "commit", "-qm", "ignore many")
        many = self.repo / "many"
        many.mkdir()
        for index in range(runner.b2_module().MAX_SNAPSHOT_PATHS + 1):
            (many / f"file-{index:05d}.txt").write_text("", encoding="utf-8")
        config = self.agent_config("noop", "pass\n")
        refused = self.launch(
            "bounded-job",
            config,
            name="noop",
            extra=("--deny-path", "many/**"),
            expected=2,
        )
        self.assertIn("exceeds", refused.stderr)
        self.assertIn("paths", refused.stderr)
        self.assertFalse(self.job_path("bounded-job").exists())
        self.assertEqual(self.owner()["state"], "failed_admission")


if __name__ == "__main__":
    unittest.main()
