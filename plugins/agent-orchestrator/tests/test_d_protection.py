from __future__ import annotations

import errno
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


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("agent_orchestrator_runner_d1_protection_tests", RUNNER)
c = runner.c_module()
d = runner.d_module()
REAL_BWRAP = shutil.which("bwrap")


def _real_isolation_probe() -> tuple[bool, str | None]:
    if not REAL_BWRAP:
        return False, "bubblewrap is not installed"
    with mock.patch.object(c, "bwrap_executable", return_value=REAL_BWRAP):
        return c.isolation_status()


REAL_ISOLATION, REAL_ISOLATION_REASON = _real_isolation_probe()


def git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "tests@example.invalid"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Tests"], cwd=path, check=True
    )
    (path / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    (path / "allowed").mkdir()
    (path / "allowed" / "old.txt").write_text("old\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "tracked.txt", "allowed/old.txt"], cwd=path, check=True
    )
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=path, check=True)
    subprocess.run(
        ["git", "checkout", "-qb", "feature/d1-protection"], cwd=path, check=True
    )
    return path


def contract(*, allowed: list[str] | None = None) -> dict:
    return {
        "allowed_paths": allowed or ["allowed/**"],
        "denied_paths": [".env"],
        "max_changed_files": 8,
    }


def observe(workspace: Path, selected: dict | None = None) -> dict:
    return d._observe_workspace(
        workspace, selected or contract(), extra_paths=[]
    )


def derive(
    workspace: Path,
    *,
    allowed: list[str] | None = None,
    snapshot: dict | None = None,
    known_owned: tuple[str, ...] = (),
) -> dict:
    selected = contract(allowed=allowed)
    current = snapshot or observe(workspace, selected)
    return d.derive_protection_manifest(
        workspace,
        current,
        selected,
        plan_id="protection-plan",
        step_id="step-one",
        cycle=1,
        candidate_sha256="a" * 64,
        contract_digest="b" * 64,
        plan_sha256="c" * 64,
        b1_manifest_digest="d" * 64,
        known_owned=list(known_owned),
    )


def protection_inputs(manifest: dict) -> dict:
    return d._protection_inputs(manifest)


def write_exclude(workspace: Path, patterns: list[str]) -> Path:
    exclude = workspace / ".git" / "info" / "exclude"
    exclude.write_text("\n".join(patterns) + "\n", encoding="utf-8")
    return exclude


class ProtectionManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(tempfile.mkdtemp(dir=self.temp.name))
        self.repo = git_repo(self.root / "repo")

    def test_large_ignored_tree_and_sparse_file_are_metadata_only(self) -> None:
        write_exclude(self.repo, ["big/", "huge-sparse.bin", "local.sql"])
        big = self.repo / "big"
        big.mkdir()
        for index in range(50_001):
            descriptor = os.open(
                big / f"entry-{index}",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
        sparse = self.repo / "huge-sparse.bin"
        sparse.write_bytes(b"sparse-user-byte")
        os.truncate(sparse, 129 * 1024 * 1024)
        local = self.repo / "local.sql"
        local.write_bytes(b"ignored user database\n")

        started = time.monotonic()
        manifest = derive(self.repo)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 20.0, "manifest derivation must stay bounded")
        roots = {entry["path"]: entry for entry in manifest["roots"]}
        self.assertIn("big", roots)
        self.assertEqual(roots["big"]["kind"], "directory")
        self.assertIn("huge-sparse.bin", roots)
        self.assertIn("local.sql", roots)
        for name in ("big", "huge-sparse.bin", "local.sql"):
            self.assertNotIn(
                "observed_sha256",
                roots[name],
                "ignored roots are covered by mount identity, never content hashing",
            )
        self.assertFalse(
            manifest["coverage"]["recursive_ignored_content_hashes"]
        )
        self.assertLess(
            manifest["counts"]["extra_mount_argv_bytes"],
            128 * 1024,
        )
        # The B2 observation must not include the huge ignored tree or file.
        observed = set(d.implementation_observation_paths(self.repo, contract()))
        self.assertNotIn("big", observed)
        self.assertNotIn("huge-sparse.bin", observed)
        self.assertNotIn("local.sql", observed)
        snapshot = runner.b2_module().snapshot_workspace(
            self.repo,
            strict=True,
            extra_paths=sorted(observed),
        )
        self.assertNotIn("big", snapshot.get("entries") or {})
        self.assertNotIn("huge-sparse.bin", snapshot.get("entries") or {})
        self.assertEqual(local.read_bytes(), b"ignored user database\n")
        with open(sparse, "rb") as handle:
            self.assertEqual(handle.read(1), b"s")

    def test_ignored_root_mixed_with_writable_paths_is_refined(self) -> None:
        write_exclude(self.repo, ["data/"])
        private = self.repo / "data" / "private"
        private.mkdir(parents=True)
        cache = private / "cache.bin"
        cache.write_bytes(b"private cache bytes\n")
        manifest = derive(self.repo, allowed=["data/new/**"])
        paths = {entry["path"] for entry in manifest["roots"]}
        self.assertIn("data/private", paths)
        self.assertNotIn("data", paths)
        # Refinement keeps a missing approved directory writable.
        self.assertFalse(
            any(
                root == "data" or "data/new" == root or "data/new".startswith(root + "/")
                for root in paths
            )
        )
        new_file = self.repo / "data" / "new" / "existing.tmp"
        new_file.parent.mkdir(parents=True)
        new_file.write_bytes(b"ignored content in approved scope\n")
        with self.assertRaises(Exception) as raised:
            derive(self.repo, allowed=["data/new/**"])
        self.assertIn("overlaps", str(raised.exception))

    def test_ignored_file_inside_approved_scope_is_refused(self) -> None:
        write_exclude(self.repo, ["local.sql"])
        (self.repo / "local.sql").write_bytes(b"user bytes\n")
        with self.assertRaises(Exception) as raised:
            derive(self.repo, allowed=["local.sql"])
        self.assertIn("overlaps", str(raised.exception))

    def test_protection_root_bound_refuses_without_truncation(self) -> None:
        names = [f"ignored-{index}.tmp" for index in range(257)]
        write_exclude(self.repo, names)
        for name in names:
            (self.repo / name).write_bytes(b"x")
        with self.assertRaises(Exception) as raised:
            derive(self.repo)
        self.assertIn("256", str(raised.exception))

    def test_extra_mount_argv_bound_is_enforced(self) -> None:
        write_exclude(self.repo, ["local.sql"])
        (self.repo / "local.sql").write_bytes(b"x")
        with mock.patch.object(d, "MAX_EXTRA_MOUNT_ARGV_BYTES", 1):
            with self.assertRaises(Exception) as raised:
                derive(self.repo)
        self.assertIn("mount argv", str(raised.exception))

    def test_mutable_stat_bound_is_enforced(self) -> None:
        with mock.patch.object(d, "MAX_MUTABLE_STAT_PATHS", 1):
            with self.assertRaises(Exception) as raised:
                derive(self.repo)
        self.assertIn("stat bound", str(raised.exception))

    def test_preexisting_writable_hardlink_alias_is_refused(self) -> None:
        tracked = self.repo / "tracked.txt"
        alias = self.repo / "alias.txt"
        os.link(tracked, alias)
        with self.assertRaises(Exception) as raised:
            derive(self.repo)
        self.assertIn("hardlink alias", str(raised.exception))

    def test_untracked_symlink_user_content_is_refused(self) -> None:
        target = self.root / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")
        os.symlink(target, self.repo / "user-link")
        with self.assertRaises(Exception) as raised:
            derive(self.repo)
        self.assertIn("symlink", str(raised.exception).lower())

    def test_normal_directory_link_counts_are_not_rejected(self) -> None:
        nested = self.repo / "nested" / "deeper"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_text("normal\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "nested/deeper/file.txt"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "nested"], check=True
        )
        manifest = derive(self.repo)
        self.assertEqual(manifest["roots"], [])

    def test_protection_identity_drift_is_detected(self) -> None:
        write_exclude(self.repo, ["local.sql"])
        local = self.repo / "local.sql"
        local.write_bytes(b"original user bytes\n")
        manifest = derive(self.repo)
        d._validate_protection_identity(self.repo, manifest, "test")
        local.write_bytes(b"changed user bytes!\n")
        with self.assertRaises(Exception) as raised:
            d._validate_protection_identity(self.repo, manifest, "test")
        self.assertIn("identity changed", str(raised.exception))

    def test_manifest_is_versioned_and_deterministic(self) -> None:
        write_exclude(self.repo, ["local.sql"])
        (self.repo / "local.sql").write_bytes(b"x")
        first = derive(self.repo)
        second = derive(self.repo)
        self.assertEqual(first["version"], 1)
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        recomputed = d._digest(
            {
                key: value
                for key, value in first.items()
                if key != "manifest_sha256"
            }
        )
        self.assertEqual(recomputed, first["manifest_sha256"])


class ProtectionSeamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(tempfile.mkdtemp(dir=self.temp.name))
        self.repo = git_repo(self.root / "repo")
        write_exclude(self.repo, ["other/cache"])
        (self.repo / "other" / "cache").mkdir(parents=True)
        (self.repo / "other" / "cache" / "bytes.bin").write_bytes(b"cached\n")
        (self.repo / "local.sql").write_bytes(b"user database\n")
        manifest = derive(
            self.repo, allowed=["allowed/**", "other/new/**"]
        )
        self.manifest = manifest
        self.protection = protection_inputs(manifest)

    def _job_paths(self) -> tuple[Path, Path, Path]:
        job = self.root / "job"
        job.mkdir(exist_ok=True)
        scratch = job / "scratch"
        channel = job / "channel"
        scratch.mkdir(exist_ok=True)
        channel.mkdir(exist_ok=True)
        return job, scratch, channel

    def test_legacy_bwrap_argv_is_byte_compatible(self) -> None:
        job, scratch, channel = self._job_paths()
        shell = ["bash", "-c", "true"]
        command = c.bwrap_command(
            self.repo,
            "workspace_write",
            shell,
            scratch=scratch,
            channel=channel,
            git_dir=self.repo / ".git",
        )
        self.assertEqual(
            command[:11],
            [
                c.bwrap_executable(),
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
            ],
        )
        self.assertNotIn("--info-fd", command)
        self.assertNotIn("confinement", " ".join(command))
        bind_index = command.index("--bind")
        self.assertEqual(command[bind_index + 1], str(self.repo))
        git_index = command.index("--ro-bind", bind_index)
        self.assertEqual(command[git_index + 1], str(self.repo / ".git"))

    def test_empty_protection_inputs_preserve_legacy_argv(self) -> None:
        job, scratch, channel = self._job_paths()
        shell = ["bash", "-c", "true"]
        empty = c.normalize_protection(
            self.repo,
            {
                "version": 1,
                "manifest_sha256": "d" * 64,
                "roots": [],
                "anchors": [],
            },
            capability="workspace_write",
            scratch=scratch,
            channel=channel,
            git_dir=self.repo / ".git",
        )
        legacy = c.bwrap_command(
            self.repo,
            "workspace_write",
            shell,
            scratch=scratch,
            channel=channel,
            git_dir=self.repo / ".git",
        )
        protected = c.bwrap_command(
            self.repo,
            "workspace_write",
            shell,
            scratch=scratch,
            channel=channel,
            git_dir=self.repo / ".git",
            protection=empty,
        )
        self.assertEqual(protected, legacy)

    def test_protected_mount_order_and_evidence(self) -> None:
        job, scratch, channel = self._job_paths()
        normalized = c.normalize_protection(
            self.repo,
            self.protection,
            capability="workspace_write",
            scratch=scratch,
            channel=channel,
            git_dir=self.repo / ".git",
        )
        command = c.bwrap_command(
            self.repo,
            "workspace_write",
            ["bash", "-c", "true"],
            scratch=scratch,
            channel=channel,
            git_dir=self.repo / ".git",
            protection=normalized,
        )
        workspace_index = command.index(str(self.repo))
        anchor_index = command.index(str(self.repo / "other"))
        root_index = command.index(str(self.repo / "other" / "cache"))
        git_index = command.index(str(self.repo / ".git"))
        scratch_index = command.index(str(scratch))
        self.assertLess(workspace_index, anchor_index)
        self.assertLess(anchor_index, git_index)
        self.assertLess(git_index, root_index)
        self.assertLess(root_index, scratch_index)
        self.assertEqual(normalized["manifest_sha256"], self.manifest["manifest_sha256"])
        self.assertTrue(normalized["plan_sha256"])
        self.assertEqual(len(normalized["roots"]), len(self.manifest["roots"]))
        self.assertEqual(len(normalized["anchors"]), len(self.manifest["anchors"]))

    def test_readonly_capability_rejects_writable_anchors(self) -> None:
        with self.assertRaises(c.ProviderError) as raised:
            c.normalize_protection(
                self.repo,
                self.protection,
                capability="readonly",
            )
        self.assertIn("readonly", str(raised.exception).lower())

    def test_protection_rejects_unsafe_paths(self) -> None:
        base = {
            "version": 1,
            "manifest_sha256": "a" * 64,
            "roots": [],
            "anchors": [],
        }
        for path in ("/etc/passwd", "../escape", "other/../local.sql", ".git/index"):
            candidate = dict(base)
            candidate["roots"] = [{"path": path, "kind": "file"}]
            with self.assertRaises(c.ProviderError):
                c.normalize_protection(
                    self.repo, candidate, capability="workspace_write"
                )
        os.symlink(
            self.repo / "other" / "cache",
            self.repo / "link-root",
        )
        candidate = dict(base)
        candidate["roots"] = [{"path": "link-root", "kind": "directory"}]
        with self.assertRaises(c.ProviderError):
            c.normalize_protection(
                self.repo, candidate, capability="workspace_write"
            )
        candidate = dict(base)
        candidate["roots"] = [{"path": "local.sql", "kind": "file"}]
        candidate["anchors"] = [{"path": "local.sql"}]
        with self.assertRaises(c.ProviderError):
            c.normalize_protection(
                self.repo, candidate, capability="workspace_write"
            )

    def test_protection_bounds_are_enforced_in_c(self) -> None:
        with mock.patch.object(c, "MAX_PROTECTION_ROOTS", 1):
            candidate = {
                "version": 1,
                "manifest_sha256": "a" * 64,
                "roots": [
                    {"path": "local.sql", "kind": "file"},
                    {"path": "other/cache", "kind": "directory"},
                ],
                "anchors": [],
            }
            with self.assertRaises(c.ProviderError):
                c.normalize_protection(
                    self.repo, candidate, capability="workspace_write"
                )
        with mock.patch.object(c, "MAX_EXTRA_MOUNT_ARGV_BYTES", 1):
            with self.assertRaises(c.ProviderError):
                c.normalize_protection(
                    self.repo,
                    self.protection,
                    capability="workspace_write",
                )

    def test_availability_probe_is_confined_before_rcfile(self) -> None:
        rcfile = self.root / "probe-rc"
        rcfile.write_text("deepseek() { :; }\n", encoding="utf-8")
        rcfile.chmod(0o600)
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(c.subprocess, "run", return_value=completed) as run:
            available, reason = c.probe_provider(
                profile, workspace=self.repo
            )
        self.assertTrue(available, reason)
        command = run.call_args.args[0]
        self.assertEqual(command[0], c.bwrap_executable())
        self.assertIn("--unshare-net", command)
        self.assertIn("--unshare-pid", command)
        self.assertIn("--cap-drop", command)
        ro_index = command.index("--ro-bind")
        self.assertEqual(command[ro_index + 1 : ro_index + 3], ["/", "/"])
        self.assertIn("--rcfile", command)
        self.assertGreater(command.index("--rcfile"), ro_index)
        self.assertNotIn("--unshare-user", command)

    def _probe_profile(self, rcfile: Path) -> dict:
        rcfile.write_text("deepseek() { :; }\n", encoding="utf-8")
        rcfile.chmod(0o600)
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        return profile

    def test_probe_distinguishes_function_absence_from_startup_failure(self) -> None:
        profile = self._probe_profile(self.root / "probe-rc")
        absent = subprocess.CompletedProcess(
            args=[], returncode=c.PROBE_MISSING_FUNCTION_EXIT,
            stdout=b"", stderr=b"",
        )
        with mock.patch.object(c.subprocess, "run", return_value=absent):
            available, reason = c.probe_provider(profile, workspace=self.repo)
        self.assertFalse(available)
        self.assertEqual(reason, c.PROBE_MISSING_FUNCTION_REASON)
        # bubblewrap refusing before Bash is reached must not be reported as
        # a missing provider function.
        failed_start = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"", stderr=b"permission denied"
        )
        with mock.patch.object(c.subprocess, "run", return_value=failed_start):
            available, reason = c.probe_provider(profile, workspace=self.repo)
        self.assertFalse(available)
        self.assertEqual(reason, c.PROBE_STARTUP_FAILURE_REASON)
        self.assertNotIn(c.PROBE_MISSING_FUNCTION_REASON, reason)
        self.assertIn("isolation", reason)

    def test_probe_reports_timeout_and_spawn_failure_distinctly(self) -> None:
        profile = self._probe_profile(self.root / "probe-rc")
        with mock.patch.object(
            c.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd=["bwrap"], timeout=1),
        ):
            available, reason = c.probe_provider(
                profile, workspace=self.repo, timeout_seconds=1
            )
        self.assertFalse(available)
        self.assertEqual(reason, c.PROBE_TIMEOUT_REASON)
        with mock.patch.object(
            c.subprocess, "run", side_effect=OSError("spawn failed")
        ):
            available, reason = c.probe_provider(profile, workspace=self.repo)
        self.assertFalse(available)
        self.assertEqual(reason, c.PROBE_EXECUTION_REASON)

    def test_probe_real_startup_failure_never_reaches_rcfile(self) -> None:
        # Real subprocess path with a bwrap stand-in that fails the way an
        # inaccessible --chdir does, before Bash loads the rcfile.
        bin_dir = self.root / "probe-bin"
        bin_dir.mkdir()
        fake_bwrap = bin_dir / "bwrap"
        fake_bwrap.write_text(
            f"""#!{sys.executable}
import sys
sys.stderr.write("bwrap: Can't chdir to restricted: Permission denied\\n")
raise SystemExit(1)
""",
            encoding="utf-8",
        )
        fake_bwrap.chmod(0o755)
        marker = self.root / "probe-rc-executed"
        rcfile = self.root / "probe-rc"
        rcfile.write_text(
            "touch " + json.dumps(str(marker)) + "\n"
            "deepseek() { :; }\n",
            encoding="utf-8",
        )
        rcfile.chmod(0o600)
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + original
        try:
            available, reason = c.probe_provider(profile, workspace=self.repo)
        finally:
            os.environ["PATH"] = original
        self.assertFalse(available)
        self.assertEqual(reason, c.PROBE_STARTUP_FAILURE_REASON)
        self.assertFalse(marker.exists())

    def test_raw_protection_with_forged_plan_marker_is_renormalized(self) -> None:
        job, scratch, channel = self._job_paths()
        forged = {
            "version": 1,
            "manifest_sha256": "a" * 64,
            "roots": [{"path": "local.sql", "kind": "file"}],
            "anchors": [],
            "plan_sha256": "b" * 64,
        }
        with self.assertRaises(c.ProviderError):
            c.bwrap_command(
                self.repo,
                "workspace_write",
                ["bash", "-c", "true"],
                scratch=scratch,
                channel=channel,
                git_dir=self.repo / ".git",
                protection=forged,
            )
        # An anchor can never reopen Git custody or point at the workspace.
        candidate = {
            "version": 1,
            "manifest_sha256": "a" * 64,
            "roots": [{"path": "local.sql", "kind": "file"}],
            "anchors": [{"path": ".git"}],
        }
        with self.assertRaises(c.ProviderError):
            c.normalize_protection(
                self.repo, candidate, capability="workspace_write"
            )

    def _sleeping_confinement_bwrap(self) -> Path:
        bin_dir = self.root / "sleep-bin"
        bin_dir.mkdir(exist_ok=True)
        executable = bin_dir / "bwrap"
        executable.write_text(
            f"""#!{sys.executable}
import os
import sys
import time

args = sys.argv[1:]
if any("C1CONF" in value for value in args):
    time.sleep(60)
    raise SystemExit(0)
for index, value in enumerate(args):
    if value == "bash" or value.endswith("/bash"):
        os.execv(value, args[index:])
raise SystemExit(1)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return bin_dir

    def _run_protected_with_shim(
        self,
        *,
        timeout_seconds: float,
        cancel_after: float | None = None,
    ):
        import threading

        job, scratch, channel = self._job_paths()
        bin_dir = self._sleeping_confinement_bwrap()
        rcfile = self.root / "rc-sleep"
        rcfile.write_text("deepseek() { :; }\n", encoding="utf-8")
        rcfile.chmod(0o600)
        prompt = self.root / "prompt-sleep.md"
        prompt.write_text("prompt\n", encoding="utf-8")
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        binding = c.build_binding("deepseek", profile, "implementation")
        cancel_marker = job / "cancel-requested"
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + original
        result: dict = {}

        def invoke() -> None:
            started = time.monotonic()
            try:
                run = c.run_provider(
                    profile=profile,
                    binding=binding,
                    workspace=self.repo,
                    job_dir=job,
                    prompt_file=prompt,
                    timeout_seconds=timeout_seconds,
                    cancel_marker=cancel_marker,
                    scratch=scratch,
                    channel=channel,
                    git_dir=self.repo / ".git",
                    protection=self.protection,
                )
                result["error"] = run.error
                result["timed_out"] = run.timed_out
                result["cancelled"] = run.cancelled
            except BaseException as exc:  # pragma: no cover - diagnostic
                result["exception"] = exc
            result["elapsed"] = time.monotonic() - started

        try:
            if cancel_after is None:
                invoke()
            else:
                thread = threading.Thread(target=invoke)
                thread.start()
                time.sleep(cancel_after)
                cancel_marker.write_text("cancel")
                thread.join(timeout=20)
                self.assertFalse(thread.is_alive(), "cancellation did not finish")
        finally:
            os.environ["PATH"] = original
        self.assertNotIn("exception", result, result)
        return result

    def test_blocked_confinement_status_preserves_timeout_category(self) -> None:
        result = self._run_protected_with_shim(timeout_seconds=1.0)
        self.assertTrue(result["timed_out"], result)
        self.assertEqual((result["error"] or {}).get("code"), "timeout")
        self.assertLess(result["elapsed"], 10.0)

    def test_blocked_confinement_status_preserves_cancel_category(self) -> None:
        result = self._run_protected_with_shim(
            timeout_seconds=30.0, cancel_after=0.3
        )
        self.assertTrue(result["cancelled"], result)
        self.assertEqual((result["error"] or {}).get("code"), "cancelled")
        self.assertLess(result["elapsed"], 10.0)

    def test_confinement_status_reads_one_bounded_first_line(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"C1CONF nonce OK 3\nC1CONF forged OK 9\n")
        finally:
            os.close(write_fd)
        try:
            line, problem = c._read_confinement_status(
                read_fd, time.monotonic() + 5.0
            )
        finally:
            os.close(read_fd)
        self.assertIsNone(problem)
        self.assertEqual(line, b"C1CONF nonce OK 3")
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"x" * (c.MAX_CONFINEMENT_STATUS_BYTES + 10))
        finally:
            os.close(write_fd)
        try:
            line, problem = c._read_confinement_status(
                read_fd, time.monotonic() + 5.0
            )
        finally:
            os.close(read_fd)
        self.assertIsNone(line)
        self.assertIn("size bound", problem or "")

    def test_unconfined_transport_shim_refuses_before_provider_start(self) -> None:
        job, scratch, channel = self._job_paths()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake_bwrap = bin_dir / "bwrap"
        fake_bwrap.write_text(
            f"""#!{sys.executable}
import sys
args = sys.argv[1:]
for index, value in enumerate(args):
    if value == "bash" or value.endswith("/bash"):
        sys.exit(__import__("os").execv(value, args[index:]))
sys.exit(1)
""",
            encoding="utf-8",
        )
        fake_bwrap.chmod(0o755)
        marker = self.root / "provider-started"
        rcfile = self.root / "rc"
        rcfile.write_text(
            "deepseek() { touch "
            + json.dumps(str(marker))
            + "; }\n",
            encoding="utf-8",
        )
        rcfile.chmod(0o600)
        prompt = self.root / "prompt.md"
        prompt.write_text("protected prompt\n", encoding="utf-8")
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        binding = c.build_binding("deepseek", profile, "implementation")
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + original
        try:
            run = c.run_provider(
                profile=profile,
                binding=binding,
                workspace=self.repo,
                job_dir=job,
                prompt_file=prompt,
                timeout_seconds=30,
                cancel_marker=job / "cancel-requested",
                scratch=scratch,
                channel=channel,
                git_dir=self.repo / ".git",
                protection=self.protection,
            )
        finally:
            os.environ["PATH"] = original
        self.assertIsNotNone(run.error)
        self.assertEqual(run.error.get("code"), "isolation_unavailable")
        self.assertFalse(marker.exists())
        self.assertEqual(
            (self.repo / "local.sql").read_bytes(), b"user database\n"
        )
        self.assertEqual(
            (self.repo / "other" / "cache" / "bytes.bin").read_bytes(),
            b"cached\n",
        )
        confinement = run.result.get("confinement")
        self.assertEqual(
            confinement["manifest_sha256"], self.manifest["manifest_sha256"]
        )
        self.assertFalse(confinement["application"]["verified"])


@unittest.skipUnless(
    REAL_ISOLATION,
    "real bubblewrap namespaces and mount application are required",
)
class RealConfinementTests(unittest.TestCase):
    """Kernel-level protection claims, run only under real bwrap."""

    # The fixture declares exactly the writable paths its positive scenario
    # needs, as an approved writer contract would: the clean root file with its
    # native temporary name, and the new source directory beneath the mixed
    # ignored parent.  Without those declarations Git may correctly collapse
    # ``other/`` into one read-only root, which would deny ``other/new`` and
    # make the fixture call an undeclared path approved.
    POSITIVE_ALLOWED_PATHS = [
        "allowed/**",
        "README.md",
        "README.md.tmp-123",
        "other/new/**",
    ]

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(tempfile.mkdtemp(dir=self.temp.name))
        self.repo = git_repo(self.root / "repo")
        with open(self.repo / "README.md", "w", encoding="utf-8") as handle:
            handle.write("root readme\n")
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "README.md"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "readme"], check=True
        )
        write_exclude(self.repo, ["other/cache", "local.sql"])
        (self.repo / "other" / "cache").mkdir(parents=True)
        (self.repo / "other" / "cache" / "bytes.bin").write_bytes(b"cached\n")
        (self.repo / "local.sql").write_bytes(b"user database\n")
        self.manifest = derive(self.repo, allowed=self.POSITIVE_ALLOWED_PATHS)
        self.protection = protection_inputs(self.manifest)
        self.job, self.scratch, self.channel = (
            self.root / "job",
            self.root / "job" / "scratch",
            self.root / "job" / "channel",
        )
        self.job.mkdir()
        self.scratch.mkdir()
        self.channel.mkdir()

    def _sandbox_argv(
        self, argv: list[str]
    ) -> subprocess.CompletedProcess[bytes]:
        normalized = c.normalize_protection(
            self.repo,
            self.protection,
            capability="workspace_write",
            scratch=self.scratch,
            channel=self.channel,
            git_dir=self.repo / ".git",
        )
        with mock.patch.object(c, "bwrap_executable", return_value=REAL_BWRAP):
            command = c.bwrap_command(
                self.repo,
                "workspace_write",
                argv,
                scratch=self.scratch,
                channel=self.channel,
                git_dir=self.repo / ".git",
                protection=normalized,
            )
        return subprocess.run(
            command,
            capture_output=True,
            timeout=60,
            check=False,
            env={**os.environ, "PYTHON": sys.executable},
        )

    def _sandbox_python(
        self, script: str, *arguments: str
    ) -> subprocess.CompletedProcess[bytes]:
        """Run literal Python argv without a shell or JSON shell quoting.

        JSON serialization is not shell quoting: ``json.dumps`` keeps newlines
        as literal ``\\n`` escapes, which Bash passes through unchanged.  Passing
        the multiline script as one literal argv element preserves its exact
        bytes, including both quote styles and embedded newlines.
        """
        return self._sandbox_argv(
            [sys.executable, "-c", script, *arguments]
        )

    def test_protected_writes_renames_unlinks_and_links_are_denied(self) -> None:
        script = r"""
import errno, os, sys
repo = sys.argv[1]
p = os.path.join(repo, "local.sql")
d = os.path.join(repo, "other", "cache")
results = {}
def attempt(name, fn):
    try:
        fn()
        results[name] = "ok"
    except OSError as exc:
        results[name] = errno.errorcode.get(exc.errno, str(exc.errno))
def write_file():
    with open(p, "wb") as handle:
        handle.write(b"overwrite")
def truncate_file():
    os.truncate(p, 0)
def temp_rename():
    temp = os.path.join(repo, "other", "cache", ".tmp-user")
    with open(temp, "wb") as handle:
        handle.write(b"x")
    os.replace(temp, os.path.join(d, "bytes.bin"))
def unlink_file():
    os.unlink(os.path.join(d, "bytes.bin"))
def rmdir_protected():
    os.rmdir(d)
def rename_ancestor():
    os.rename(os.path.join(repo, "other"), os.path.join(repo, "other2"))
def cross_link():
    os.link(p, os.path.join(repo, "alias.sql"))
for name, fn in (
    ("direct_write", write_file),
    ("truncate", truncate_file),
    ("temp_rename", temp_rename),
    ("unlink", unlink_file),
    ("rmdir", rmdir_protected),
    ("ancestor_rename", rename_ancestor),
    ("cross_link", cross_link),
):
    attempt(name, fn)
print(repr(results))
"""
        completed = self._sandbox_python(script, str(self.repo))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        import ast

        results = ast.literal_eval(completed.stdout.decode().strip())
        for name in (
            "direct_write",
            "truncate",
            "temp_rename",
            "unlink",
            "rmdir",
            "ancestor_rename",
        ):
            self.assertNotEqual(results[name], "ok", (name, results))
        self.assertIn(results["cross_link"], {"EXDEV", "EPERM", "EACCES"})
        self.assertEqual(
            (self.repo / "local.sql").read_bytes(), b"user database\n"
        )
        self.assertEqual(
            (self.repo / "other" / "cache" / "bytes.bin").read_bytes(),
            b"cached\n",
        )
        self.assertFalse((self.repo / "other2").exists())

    def test_root_atomic_edit_and_new_mixed_parent_directory_work(self) -> None:
        # The declared writable paths must refine the collapsed ignored tree
        # to its actual protected child and keep the parent as a pinned RW
        # ancestor; a read-only root at or above other/new would make the
        # positive scenario depend on an undeclared path again.
        root_paths = {entry["path"] for entry in self.manifest["roots"]}
        anchor_paths = {entry["path"] for entry in self.manifest["anchors"]}
        self.assertIn("local.sql", root_paths)
        self.assertIn("other/cache", root_paths)
        self.assertIn("other", anchor_paths)
        self.assertFalse(
            any(
                "other/new" == root or "other/new".startswith(root + "/")
                for root in root_paths
            ),
            "the approved new mixed-parent path is covered by a read-only root",
        )
        script = r"""
import os, sys
repo = sys.argv[1]
payload = b"atomic root edit 'single' \"double\"\nsecond line\n"
temp = os.path.join(repo, "README.md.tmp-123")
with open(temp, "wb") as handle:
    handle.write(payload)
os.replace(temp, os.path.join(repo, "README.md"))
os.makedirs(os.path.join(repo, "other", "new", "sub"), exist_ok=True)
with open(os.path.join(repo, "other", "new", "sub", "file.txt"), "wb") as handle:
    handle.write(b"approved new directory\n")
print("ok")
"""
        completed = self._sandbox_python(script, str(self.repo))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            (self.repo / "README.md").read_bytes(),
            b"atomic root edit 'single' \"double\"\nsecond line\n",
        )
        self.assertEqual(
            (self.repo / "other" / "new" / "sub" / "file.txt").read_bytes(),
            b"approved new directory\n",
        )
        self.assertEqual(
            (self.repo / "other" / "cache" / "bytes.bin").read_bytes(),
            b"cached\n",
        )

    def test_confined_availability_probe_cannot_run_rcfile_side_effects(
        self,
    ) -> None:
        marker = self.root / "startup-marker"
        rcfile = self.root / "rc"
        rcfile.write_text(
            "touch " + json.dumps(str(marker)) + "\n"
            "deepseek() { claude \"$@\"; }\n",
            encoding="utf-8",
        )
        rcfile.chmod(0o600)
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        with mock.patch.object(c, "bwrap_executable", return_value=REAL_BWRAP):
            available, reason = c.probe_provider(
                profile, workspace=self.repo
            )
        self.assertTrue(available, reason)
        self.assertFalse(marker.exists())

    def test_confined_availability_probe_reports_missing_function(self) -> None:
        marker = self.root / "startup-marker"
        rcfile = self.root / "rc-missing"
        rcfile.write_text(
            "touch " + json.dumps(str(marker)) + "\n"
            "glm() { :; }\n",
            encoding="utf-8",
        )
        rcfile.chmod(0o600)
        profile = dict(runner.load_profiles(None)["deepseek"])
        profile["provider_rcfile"] = str(rcfile)
        with mock.patch.object(c, "bwrap_executable", return_value=REAL_BWRAP):
            available, reason = c.probe_provider(
                profile, workspace=self.repo
            )
        self.assertFalse(available)
        self.assertEqual(reason, c.PROBE_MISSING_FUNCTION_REASON)
        # The confined rcfile side effect stays denied, and no provider model
        # or unconfined start occurred.
        self.assertFalse(marker.exists())

    def test_large_ignored_root_is_one_read_only_mount(self) -> None:
        write_exclude(self.repo, ["vendor/"])
        vendor = self.repo / "vendor"
        vendor.mkdir()
        for index in range(50_001):
            descriptor = os.open(
                vendor / f"entry-{index}",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
        (vendor / "entry-0").write_bytes(b"pre-existing user data\n")
        manifest = derive(self.repo)
        self.assertLess(
            manifest["counts"]["extra_mount_argv_bytes"], 128 * 1024
        )
        self.assertIn(
            "vendor", {entry["path"] for entry in manifest["roots"]}
        )
        self.protection = protection_inputs(manifest)
        script = (
            "import os, sys\n"
            "try:\n"
            "    open(os.path.join(sys.argv[1], 'vendor', 'entry-0'), 'wb').write(b'x')\n"
            "    print('ok')\n"
            "except OSError:\n"
            "    print('denied')\n"
        )
        completed = self._sandbox_python(script, str(self.repo))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), b"denied")
        self.assertEqual(
            (self.repo / "vendor" / "entry-0").read_bytes(),
            b"pre-existing user data\n",
        )


if __name__ == "__main__":
    unittest.main()
