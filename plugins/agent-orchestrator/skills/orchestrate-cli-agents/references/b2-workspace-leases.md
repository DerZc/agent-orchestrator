# B2 repository writer leases and workspace integrity

B2 is a runtime primitive layered on the existing runner (`cli_agent_job.py`,
`b1_consensus.py`). It supplies one atomic writer for a Git checkout and
content-attributable integrity evidence for every admitted job. It is not a
task engine, provider adapter, review engine or GitHub workflow, and it does not
implement managed research items: managed plans remain gated by B1 until C/D.

## One writer per canonical repository

The lease is a `flock` on a stable, never-unlinked inode:

```
<git-common-dir>/agent-orchestrator/lease/writer.lock
<git-common-dir>/agent-orchestrator/lease/owner.json
<state-home>/jobs/<job>/lease-completion.json   # immutable per-job proof
```

`owner.json` is the live admission record and is replaced by every new epoch.
`lease-completion.json` lives in the job directory and is never rewritten, so a
completed job's proof survives later owners.

The canonical Git common directory is shared by the main checkout, every
subdirectory, a symlinked path, and every linked worktree. All of them
therefore serialize on one inode; distinct repositories (including bare
siblings, submodules and `--separate-git-dir` checkouts) keep distinct inodes.
The `AGENT_ORCHESTRATOR_HOME` state home is not part of identity, so two state
homes cannot admit two writers.

Admission acquires the lock non-blocking **inside** the B1 repository admission
lock, before the job record is published. `--allow-concurrent-workspace` cannot
defeat the lease: Git launches from a second state home or path alias fail with
the owner's job ID, epoch and state. Enrollment (`create-plan --research-team`
and legacy plan creation) also refuses while a lease is held or uncertain.

Before acquiring the lease, the same serialized admission also rejects
discoverable live writers that predate B2 or carry no lease:

- this state home's canonical job metadata is scanned for live recorded
  worker/provider/child processes (zombies and reused PIDs are not writers);
- the repository-local B1 reservations in
  `<git-common-dir>/agent-orchestrator/active-jobs` are consulted, so a writer
  admitted through another state home is visible here;
- a reservation whose job record names a well-formed, terminal B2 owner
  (`completed`, `failed_admission` or `reconciled`) or a valid immutable
  per-job completion receipt is a finished hand-off, not a live writer, so a
  release window cannot wedge the next launch;
- if such a reservation outlives the owner record and a later lease epoch has
  replaced it, the old job's own receipt or post-drain final check for its
  epoch still proves it cannot own the checkout;
- unreadable or inconsistent lease evidence without that proof fails closed
  instead of being treated as finished.

`--allow-concurrent-workspace` has no effect on this check or on the lease; it
is retained only for non-Git legacy directories.

### Supervisor lifetime

The launcher passes the locked descriptor to a small Python supervisor
(`_lease-supervisor`) that is the ancestor of the worker and every provider
descendant. The supervisor:

1. validates the inherited descriptor, inode and epoch against `owner.json`;
2. enables Linux child-subreaper semantics (`PR_SET_CHILD_SUBREAPER`);
3. publishes `state=supervising` and its own PID/start identity before the
   worker can start, then records the worker identity once it is spawned;
4. spawns the existing worker, which spawns the provider;
5. reaps every child and adopted descendant, including `setsid` and
   double-fork daemons, until the kernel reports `ECHILD`;
6. runs the final integrity check **while still holding the lease**;
7. writes the immutable per-job `lease-completion.json` receipt bound to the
   epoch, lock inode and exact final-check digest, then the durable
   `state=completed` marker, closes the descriptor, and releases the B1
   reservation.

Providers never receive the lease descriptor and are never trusted to preserve
it. Only inherited-descriptor hand-off between runner-owned processes is used.
Normal completion releases the lock; the inode is never unlinked, so the next
launch reacquires exactly the same inode.

### Externally visible completion

The worker publishes a preliminary `result.json` when the direct provider
exits -- including `failed`, `cancelled`, `timed_out` and `scope_violated` --
but that result never authorizes completion on its own. For a leased job,
`status`, `wait`, review acceptance and therefore dependency/plan completion
treat every terminal-looking result as still running until both of these
durable facts exist:

1. `lease-completion.json` for the job's lease epoch records the post-drain
   completion, the lock inode and the exact `final-check.json` digest; that
   final check records the post-drain integrity check and the full descendant
   drain evidence;
2. `owner.json` is terminal for this job's epoch (`completed`, or `reconciled`
   after an evidence-backed recovery), or a later epoch has replaced it and
   the immutable receipt still verifies, or the owner update crashed after the
   receipt and the lock is demonstrably free.

Because the receipt is per job and immutable, the completion of an older job
stays verifiable after any number of later jobs take the lease. A missing,
malformed, mismatched or unbound receipt fails closed: the job is reported as
`lost` with `completion_finalized=false` and a `completion_blocked` reason, and
`record-review` refuses acceptance. The sole exception is an explicit
`failed_admission` owner: the launcher/supervisor proved no worker was ever
spawned, so the recorded failure outcome is complete evidence with no
descendant tree or integrity check to wait for.

`record-review` fails while completion is not finalized, so a delayed `setsid`
writer cannot be accepted before its final denied-file write is observed.
Unleased non-Git legacy jobs keep their original behavior.

`command_wait` keeps polling while the public state is `running`; it does not
return a preliminary failure, cancellation or scope violation while an adopted
descendant tree is still alive. Once the supervisor publishes the receipt and
terminal owner, the preserved underlying outcome becomes externally visible.

The supervisor also enforces backstops for descendants that escape the
worker's process group: after the job timeout (+5s grace) or 5s after a
cancellation marker, it kills the remaining descendant tree. Completion is
still proven only by `ECHILD`; the termination is recorded durably.
`cancel` still reaches a live supervisor when `result.json` is already terminal
but the lease is active (for example, a provider left a double-fork daemon), so
an escaped descendant cannot hold the checkout until the full job timeout.

Coordinator and worker crashes are safe: the supervisor is a separate process
and keeps the lock while the provider tree lives. A killed worker produces an
`supervisor_inferred` terminal result (`lost`, `timed_out`, `cancelled` or
`scope_violated`) based on recorded evidence.

### Uncertain guardian loss (support branch)

If the supervisor itself is SIGKILLed, the kernel releases the `flock`. A free
lock, a stale PID and an empty process group are **not** proof that an adopted
descendant tree exited. Without a valid per-job completion receipt,
`owner.json` therefore remains in `supervising` (or `admission`) state and
every later admission fails closed:

```
Repository writer lease for <root> is blocked: job <id> epoch <epoch> is in
state supervising but the lock is free. Cannot prove that all writer
descendants exited: ... No writer will be admitted until that reconciliation
is recorded.
```

Inspect the state and the exact missing evidence:

```bash
agent-orchestrator lease-status --workspace <checkout> --json
```

`lease-status` reports the lock path/inode, owner epoch/state, recorded
coordinator/supervisor/worker identities and their `alive`/`dead`/`unknown`
probe results, plus `missing_evidence` and a recovery action. The lock inode
must still match the owner record (`lock_inode_stable`).

The supported recovery is either a valid completion receipt already published
after `ECHILD` (which proves drain and permits takeover with the epoch/receipt
recorded in the new owner) or an explicit, evidence-backed operator
reconciliation. Reconciliation requires a free lock, a matching job ID, and no
recorded process identity that is still alive or unprobeable:

```bash
agent-orchestrator lease-reconcile \
  --workspace <checkout> --job-id <job> --operator <name> \
  --evidence "Verified no worker or provider process for <job> remains; ..."
```

The record is written under `lease/reconciliations/<epoch>-<time>.json` with
the prior owner record and the process checks, and `owner.json` becomes
`state=reconciled`. Ownership is never cleared silently. Reconciliation
unblocks the repository for a new writer; it does not manufacture the missing
post-drain final check, so the interrupted job itself remains non-acceptable
(`completion_finalized=false`) unless a valid final check for its epoch already
exists. Full automatic recovery from an externally SIGKILLed supervisor with an
unknowable descendant tree is outside the demonstrated guarantee; a supported
blocked state is the correct outcome.

### Crash ordering

- Launcher crash before the supervisor spawn: the owner stays `admission` and
  the lock is free. B2 cannot distinguish this from a lost unpublished tree, so
  it fails closed with the same reconciliation path.
- Launcher spawn failure, or supervisor failure before it spawns the worker
  (including subreaper unavailability): no writer was started, so the launcher
  or supervisor writes `failed_admission` and admission is immediately
  recoverable.
- Supervisor crash after publishing supervision: fail closed (above), unless a
  valid per-job completion receipt was already written. The receipt is created
  only after `ECHILD`, so it proves the descendant tree drained even when the
  mutable owner record was not updated.
- Crash after `lease-completion.json` is written but before the owner becomes
  terminal: the lock is free and the receipt still proves completion. Status
  reports the job's preserved outcome as finalized, and the next admission may
  take over (its owner record names the recovered epoch and receipt as
  evidence). A missing or corrupt receipt in the same state is unknowable and
  fails closed until reconciliation.
- Crash after `state=completed` is written but before the descriptor closes:
  the next admission sees a terminal owner state and proceeds.
- Hand-off confirmation timeout: the launcher records
  `lease_handoff_unconfirmed` and returns; the durable owner record still
  governs. A supervisor that later exits before publishing supervision leaves a
  fail-closed `admission` record and needs reconciliation, while a live
  supervisor keeps the lock and proceeds normally.

## Content-aware integrity

Every Git launch records a bounded baseline **after** acquiring the exclusive
writer lease and before spawning any writer:

- HEAD, attached branch and detached state;
- raw index evidence (path, SHA-256, size, inode, mtime, `exists`);
- logical staged state (`git diff --cached --raw`, or the unborn-branch index);
- NUL-delimited dirty/untracked paths, including rename source/target pairs;
- actual content hashes (kind, size, mode, SHA-256) for every dirty path and
  every explicit allowed/denied scope path that must be compared later,
  including ignored files.

Taking the baseline under the lease closes the snapshot/acquisition race: a
prior writer's changes cannot appear between the snapshot and admission, and
the stored baseline carries its `lease_epoch`. If the snapshot or protected
validation fails after acquisition, the owner record becomes
`failed_admission`, the lock is released, and no runnable job directory is
left behind.

Explicit scope patterns are resolved to bounded concrete paths with
pathspec-scoped `git ls-files` (`--cached`, `--others` and `--others
--ignored`, with `--literal-pathspecs`). The enumeration is limited to each
pattern's literal directory prefix (the repository root when a pattern starts
with a glob), so a narrow scope does not scan the whole ignored tree. This
observes preexisting and newly created ignored files that `git status` never
reports without changing the index. Glob matches use the same `fnmatch` rules
as attribution. The resolution is capped at 64 patterns, 4,000
observed paths and 8 MiB of enumeration; exceeding a bound refuses the
observation (admission or the final check fails closed) rather than attesting a
partial set. Only path names, modes, sizes and hashes are persisted; file
contents are never stored or printed.

Observation uses `GIT_OPTIONAL_LOCKS=0`, `LC_ALL=C`,
`GIT_TERMINAL_PROMPT=0`, `-c status.relativePaths=false`, and no `--ignored`
scan. `git status`, `git diff --cached` and `git ls-files` do not refresh or
rewrite the index. The runner never resets, restores or checks out anything.

The final check runs after the direct provider exits (worker) and again after
every adopted descendant is gone (supervisor, under the lease). Attribution
compares content, staging, status and mode instead of subtracting status path
lists:

- modifications to already-dirty tracked and untracked files;
- staged-state changes, renames (including sources), deletions and new files;
- HEAD/branch changes and raw index changes (recorded as integrity evidence);
- new files inside newly created directories.

Scope rules (`--allow-path`, `--deny-path`, `--max-changed-files`) apply to the
attributed changed set. Paths are reported relative to the Git work-tree
top-level (with `status.relativePaths=false`), so a launch through a
subdirectory, symlink or linked worktree attributes the same repository path
instead of a cwd-relative alias. Violations are durable: `result.json`/`meta.json` become
`scope_violated`, `final-check.json` stores the complete report, and
`final_scope_violation`/`supervisor_finalized` events are appended. Detection is
not OS prevention: an arbitrary external process or provider with write access
can still modify the checkout. C supplies provider filesystem permission
enforcement and acceptance paths.

Bounds and refusal behavior: 4,000 dirty paths, 32 MiB per hashed file, 128 MiB
of hashed content per snapshot, and 20,000 staged paths. An unreadable path,
special file, oversized dirty content, unmerged index or otherwise unsupported
observation is refused for admission (and reported as an error final check)
rather than treated as clean. Legacy jobs admitted before B2 whose baseline has
no content version fall back to status subtraction for their remaining checks.

## Protected research validation

The callable validator and CLI reject admission before any writer starts when
explicit target/protected branch configuration does not hold:

```bash
agent-orchestrator validate-workspace \
  --workspace <checkout> --target-branch feature/step-1 \
  --protected-branch main --allow-path 'plugins/**' --json

agent-orchestrator launch ... \
  --target-branch feature/step-1 --protected-branch main --allow-path 'plugins/**'
```

Rules:

- `--target-branch` and at least one `--protected-branch` are required
  explicitly; no remote, default branch or remote-tracking name is invented;
- HEAD must be attached and exactly the target branch;
- a protected HEAD, or a target that equals a protected branch, is rejected;
- any preexisting dirty path overlapping the allowed writer scope is rejected
  (with no allowed paths, the scope is the whole checkout);
- nothing is staged, reset, checked out or otherwise mutated. The validator
  only reads Git state; it never switches branches or changes the index.

`launch` runs the same validation under the admission/repository lock **after**
acquiring the writer lease, against the lease-epoch baseline, so a concurrent
writer cannot invalidate the branch or dirty check between snapshot and
admission. The standalone `validate-workspace` command is read-only and takes
its own snapshot; it never holds or mutates a lease.

## Ordinary legacy behavior

Non-Git workspaces keep their legacy detached-worker topology, state-home-local
concurrency scan and allow-dirty semantics; they have no repository lease.
Git workspaces always take the lease, including unscoped legacy jobs; the
allow-concurrent override is retained only for non-Git directories.

Managed plans (`--research-team`) are still blocked from every writer and from
ordinary plan mutation by B1. B2 adds no managed implementation path.

## Failure policy summary

| Condition | Result |
| --- | --- |
| Another live writer holds the lease | Admission refused, owner named |
| Launcher dies before supervisor spawn | Fail closed; `lease-reconcile` required |
| Worker dies with live provider tree | Lease held until supervisor drains it |
| Supervisor dies with live/unknown tree | Fail closed; `lease-reconcile` required |
| Supervisor proves completion | Receipt + `completed` before unlock; same inode reusable |
| Crash after receipt, before owner update | Receipt proves drain; status finalized, admission recovers |
| Missing/corrupt receipt or final check | Reported `lost`; review/completion refused |
| Spawn/subreaper failure before worker | `failed_admission`; recoverable, failure outcome final |
| Job timeout / cancel with escaped descendants | Supervisor kills tree and records it |
| Unsupported/incomplete integrity snapshot | Admission or final check fails closed |
| Protected branch/dirty overlap | Lease acquired, validation fails, `failed_admission`, no job starts |
| Discoverable live legacy/unleased writer | Admission refused before acquisition; override has no effect |
| Preliminary worker result before drain | Reported running; review/completion refused |
| Missing/corrupt final-check or owner evidence | Reported `lost`; review/completion refused |

## Limitations

- Linux with `/proc`, `flock`, subreaper support and local POSIX filesystem
  semantics; unsupported environments fail closed with a diagnostic.
- Advisory coordination: other tools that write the checkout without using the
  runner are not prevented (only detected, if the job has a scope).
- Legacy writers are rejected only when discoverable: a pre-B1 process with no
  job metadata or repository reservation cannot be seen by admission. B2 lease
  holders are always serialized by the lock regardless of metadata.
- Full auto-recovery after an externally SIGKILLed supervisor is excluded when
  no completion receipt exists; the explicit reconciliation record is the
  supported recovery. A receipt already written after `ECHILD` is durable proof
  and does permit takeover.
- Detection is not permission enforcement; C/D owns provider sandboxing,
  implementation admission and acceptance.
