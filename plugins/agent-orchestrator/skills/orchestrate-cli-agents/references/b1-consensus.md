# B1 durable research-team consensus

B1 is an opt-in research-team workflow layered on the existing durable plan directory,
`record_lock`, project workspace mode, task contracts, dashboard and checkpoint. Ordinary
`create-plan` calls keep their legacy behavior. A plan created with `--research-team` is
managed: its `plan.json` and Markdown artifacts are projections of an immutable consensus
ledger, and every ordinary runner writer is fail-closed in the enrolled checkout.

B1 implements discussion, freeze and the unanimous ballot gate only. It starts no managed
writer, mints no merge receipt, and provides no implementation, review/repair, lease or
GitHub lifecycle. Those remain B2-F work. `CONSENSUS_REACHED` means the design is settled,
not that implementation may start.

## Policy versions

The policy version is explicit in the manifest, the enrollment event, the frozen candidate
binding and every computed view. Unknown versions fail closed.

- **Version 2 (active default)** — the fixed three-role team is Codex (leader and design
  participant), DeepSeek (design participant and sole source writer) and GLM (read-only
  design critic). Every implementation step needs all three independent proposals,
  cross-examinations and explicit AGREE ballots on one frozen design. DeepSeek cannot
  approve its own implementation; Codex independently reviews the complete candidate diff
  and reruns the required tests after implementation.
- **Version 1 (historical read-only)** — archived four-agent records (Codex, Antigravity,
  DeepSeek, GLM) remain replayable byte-for-byte with their original policy, roles, votes,
  digests and artifact files. The operator removed Antigravity, so no v1 action may launch
  that provider, synthesize its missing agreement, or add an event. Reads are in-memory
  only. Every mutation fails closed with historical-only guidance; create a new version 2
  replacement plan in a checkout that is not enrolled in the historical plan (the
  historical checkout stays protected and unchanged). There is no mid-cycle or implicit
  upgrade.

The candidate digest binds the explicit policy version, the fixed role roster, the plan and
plan digest, the manifest digest, the step ID, the cycle, the vote round and the declared
dependency references. A ballot from another policy version or cycle therefore fails as
stale, and a forged binding or removed-role ballot fails replay.

## D2 validation policy

Strict candidates may include `execution_constraints.version = 2` with an explicit ordered validation policy. It is voted before execution and matched by a version 2 execution contract. Version 1 candidates remain byte-identical and never gain D2 authority. See `d-review-repair.md`.

## Prerequisites

- `preferences --workspace-mode project` was saved. Worktree mode is rejected.
- The workspace is a Git work tree. Enrollment uses the canonical repository identity and
  a repository-level marker in the Git common directory, so the main checkout, a
  subdirectory, a symlinked path and a linked worktree resolve to one protected project.
  A different `AGENT_ORCHESTRATOR_HOME` therefore cannot admit the same checkout as
  legacy. A bare repository and its linked worktrees share that identity and stay
  protected; the Git administrative directory (`<repo>/.git`, its children) resolves to
  the same identity too, so admission cannot be bypassed by addressing it directly. Only
  a work tree can host a research-team plan; `.git` directories and bare repositories are
  rejected with a clear error. Sibling bare repositories, submodules and
  `--separate-git-dir` checkouts keep distinct identities.
- The plan file keeps the upstream required sections and a `- [ ]` checklist. Managed plans
  reject prechecked boxes (`- [x]`).
- A structured manifest is supplied separately; its step IDs are the plan item IDs.
- Git diagnostics are requested in the C locale, so a plain non-Git directory keeps its
  legacy behavior under any `LANG`/`LC_ALL` setting.

## Create a managed plan

```bash
agent-orchestrator preferences --workspace-mode project
agent-orchestrator create-plan \
  --workspace <checkout> --plan-file <plan.md> --title <title> \
  --plan-id <plan-id> --research-team --manifest-file <manifest.json> --json
```

`--policy-version` defaults to `2`. Version `1` is rejected for new plans because the
four-agent history is read-only; the error explains how to create a version 2 replacement.
A manifest whose `policy_version` does not match the requested version is rejected, and an
unknown version fails closed.

Manifest schema (exact keys; unknown keys are rejected):

```json
{
  "policy_version": 2,
  "steps": [
    {
      "id": "step-one",
      "objective": "At least twenty substantive characters.",
      "scope": ["path or scope statement"],
      "deliverables": ["non-empty deliverable"],
      "acceptance_criteria": ["non-empty check"],
      "depends_on": [],
      "brief": {
        "original_objective": "The coordinator's original long-term objective.",
        "repository_context": "Where this work lives and what already exists.",
        "constraints": ["project constraint carried into discussion"],
        "proposed_approach": "The coordinator's proposed technical approach.",
        "expected_changes": ["expected code or artifact change"],
        "acceptance_criteria": ["how the coordinator will judge the result"]
      }
    }
  ]
}
```

Every manifest step must carry the coordinator-authored `brief` object with exactly those
six fields. It is persisted verbatim in the enrollment event and rendered before round one
in `DISCUSSION_BRIEF.md`; it never changes after voting or when a later cycle opens. The
moderator uses it to reject hollow proposals that merely restate the objective.

Validation rejects unknown policy versions, duplicate IDs, `null` or duplicate dependency
entries, self/later/cyclic dependencies, prechecked boxes, missing scope/deliverables/
acceptance criteria/brief, oversized payloads, and any claimed `evidence`, `status`,
`merged`, `receipt` or similar unchecked assumption. A string `scope` is normalized to a
one-item list and enforces the same per-item byte bound as a list entry, so the published
enrollment event always replays identically. A dependent step must list earlier steps and is
reported as `DEPENDENCY_BLOCKED` until a future independently verified `MERGED` receipt
exists; B1 has no command that can mint one. Prior consensus in the predecessor is not
merge evidence, and every consensus command on a dependent step fails before publishing.

The create call is idempotent for identical content, including identical executor, team and
goal policy choices; timestamps are excluded from identity. Conflicting retries fail
without changing the original record. Enrollment uses a repository lock, a private
staging directory, an atomic first-event directory rename and a recoverable intent
record. The staged ledger is replayed before publication, so an unreplayable manifest can
never become a published plan. The staging marker is removed before the rename and the
empty staging parent is deleted afterwards; a published plan never contains staging
scaffolding.

The intent records the owning state home (`plans_dir`) and the normalized request digest.
An interrupted pre-event or post-event attempt keeps admission fail-closed and is
completed only by retrying the exact same create-plan from the state home that started it;
another state home, or a different manifest/policy request, fails closed and names the
owner and intent path. Deterministic in-process failures before publication remove their
own staging directory and intent so the checkout is not bricked; a genuine interruption
(no `finally` runs) leaves the intent for recovery. Only the recorded staging directory is
removed; a published plan is never deleted or replaced by cleanup. When a post-publication
projection regeneration runs, it holds the plan lock, so a concurrent consensus command
cannot interleave a stale view.

Enrollment also refuses to replace an existing enrollment or enroll over an active job in
the same canonical checkout, including a job admitted through another supported state
home. Every admitted launch publishes a uniquely named
`active-jobs/<job-id>.<reservation-id>.json` in the Git common directory with its
coordinator, worker and provider process IDs. The random reservation ID is an ownership
token: updates and release name the exact record they own, so two launches that share a
job ID in independent state homes never overwrite or release each other's evidence.
Enrollment prunes reservations whose recorded processes are all gone and fails closed
while any is alive, so startup, a dead launching coordinator and a still-running provider
are all covered. A launch's post-spawn registration is update-only; it never recreates a
record a worker already released. A worker started for a job admitted by an older runner
creates one valid reservation and persists its token in the job metadata, and a legitimate
worker restart updates the same record while preserving the recorded provider. Legacy
version 1 `<job-id>.json` records are read and pruned but never written by new code.

Job admission consults every recorded worker, provider and child process immediately after
canonical identity matching, before any terminal result or secondary heartbeat. A live or
unprobeable recorded process keeps the checkout reserved even when the worker died, the
result file is missing, or the heartbeat is malformed. A blocked worker publishes a
terminal failed `result.json` and merges the same state and reason into its durable
`meta.json`, so the two records never disagree.

## Protocol

All receipts are coordinator-submitted and trusted in B1. Each command accepts
`--operation-id`; retry the exact same command with the same ID to receive the published
events and `"idempotent": true`. Reusing an ID with different content fails. Use `--job-id`
or `--leader` as provenance on submissions, ballots and pauses. The active policy version
accepts exactly the `codex`, `deepseek` and `glm` roles; `antigravity` is rejected with the
active roster and is never launched.

Round 1 — three distinct proposals (`consensus-submit --round 1`). Submission JSON needs
`approach`, `rationale`, `assumptions`, `risks`, `alternatives`, `feasibility`, `tests`;
string fields must be substantive and list fields non-empty and bounded.

Round 2 — three cross-examinations (`consensus-submit --round 2`). Submission JSON needs
`responses`, `challenges` and `revisions`. Each challenge may contain `objection` and
`severity`; the runner numbers every objection (`O001`, `O002`, ...) in receipt order.
Callers must not supply `objection_id`.

Freeze — after all three round 2 receipts, `consensus-freeze --candidate-file <json>`
freezes exactly one candidate. It needs `final_design`, `important_decisions`,
`rejected_alternatives` (alternative + reason), `objection_dispositions` (every numbered
objection exactly once, with disposition + reason) and `remaining_risks`. The stable
canonical digest binds the policy version, role roster, plan and plan digest, manifest
digest, step ID, cycle, vote round and dependency references.

Round 3 — `consensus-vote` records one explicit `AGREE`, `DISAGREE` or
`NEEDS_DISCUSSION` for each of the three active roles against the frozen digest. Every
response is recorded even after an earlier dissent. A missing, invalid, duplicate,
wrong-role, cross-version or stale-digest ballot is never assent and never produces
consensus. The final tally is published only when all three ballots exist:
`consensus_reached` requires 3/3 AGREE; anything else records `consensus_failed` and
`HUMAN_DECISION_REQUIRED`. There is no fourth default round.

The default budget means the three protocol rounds above (proposals, cross-examination,
ballots). A provider pause/resume does not consume or complete a round; the paused slot
must still submit its own receipt.

Moderator criteria for rejecting hollow answers: each role's proposal must describe a
concrete mechanism and at least one step-specific assumption, risk, alternative and test;
round 2 must respond to the actual proposals and number real challenges or revisions;
ballots must reference the frozen digest. Boilerplate repetition across roles, empty
agreement and content that merely restates the objective are rejected before submission.
The runner additionally enforces structural substance, exact schemas and size bounds.

## Missing providers and human cycles

```bash
consensus-pause --plan-id <id> --step-id <id> --role <role> \
  --reason <why> --guidance <operator retry step> --job-id <job> --json
consensus-resume --plan-id <id> --step-id <id> --role <role> \
  --retry-id <recorded retry> --json
```

A pause records the slot, reason, operator guidance, provenance and a retry ID, and lists
the resume action in the checkpoint. The provider can either resume and submit normally, or
submit once with `--retry-id <id>` to clear the pause in the same receipt. A pause does not
complete a round and does not count as assent. Pause provenance is persisted in the ledger
and rendered in the discussion log.

A non-unanimous final tally preserves the cycle, ballots, digest and objections. To seek a
fresh design and fresh votes, an explicit human authorization must be recorded:

```bash
consensus-new-cycle --plan-id <id> --step-id <id> \
  --authorized-by <human> --authorization-file <text> --json
```

The same authorized amendment path is available after `CONSENSUS_REACHED`: a settled
design is immutable unless a human records a new cycle. This opens cycle N+1 with empty
round 1 receipts and records the actual previous outcome and digest. It cannot override
the 3/3 gate. The old cycle remains in the ledger as a complete, byte-stable bundle.
Never substitute an assumed human answer for this step. This command is available only for
active policy version 2 plans; historical version 1 ledgers cannot be reopened.

## Artifacts

Every active (policy version 2) step owns a deterministic directory `steps/<step-id>/`
containing exactly six files:

- `DISCUSSION_BRIEF.md` — the immutable pre-discussion brief for the current cycle,
  reproducing the coordinator-authored objective, repository context, constraints,
  proposed approach, expected changes and acceptance criteria verbatim.
- `PROPOSAL_CODEX.md`, `PROPOSAL_DEEPSEEK.md`, `PROPOSAL_GLM.md` — the three individual
  proposals.
- `DISCUSSION_LOG.md` — the complete chronological payloads for this step and cycle.
- `CONSENSUS.md` — the frozen candidate, dispositions, ballots with rationale and
  provenance, pauses, and the settled or pending outcome.

Each cycle is archived under `steps/<step-id>/cycle-<n>/` with the same six names. Closed
cycles are regenerated from the immutable ledger and remain byte-stable when a new cycle
opens. `plan-checkpoint` exposes every path under `step_artifacts`, along with the
plan-root dashboard summaries `proposals.md`, `discussion-brief.md`, `discussion-log.md`
and `consensus.md`.

Historical policy version 1 bundles retain their original seven artifacts, including
`PROPOSAL_ANTIGRAVITY.md`, and their original bytes. Reading a version 1 ledger never
regenerates, rewrites or deletes those files; `step_artifacts` reports
`historical_read_only: true` and `regenerated: false` for them.

## Inspect and recover

```bash
agent-orchestrator plan-status <plan-id> [--json]
agent-orchestrator plan-checkpoint <plan-id> [--json]
```

`plan-checkpoint` replays the published ledger and, for active policy version 2,
regenerates `plan.json`, `checkpoint.json`, `manifest.json`, the plan-root summaries and
every per-step/per-cycle bundle. It reports actual `missing_actions`, `next_action`,
`blocked_reasons`, `DEPENDENCY_BLOCKED` states, open pauses, freeze history and preserved
cycles. It is safe in a fresh process after a crash. A corrupted published event blocks the
plan; dot temporary files are unpublished and ignored. Published events must be named by
their ordered sequence, carry the expected round/type combinations and decode as UTF-8
JSON. Computed views are never the authority.

A historical policy version 1 plan is replayed in memory only. Its checkpoint reports
`policy_status: HISTORICAL_READ_ONLY`, `historical_read_only: true`, the original roles,
votes and digest, no continuation actions, and `replacement_guidance` explaining how to
create a new policy version 2 replacement plan. `plan-status` prints the same historical
flag and guidance. Every consensus mutation is rejected before any event is published and
without launching the removed provider.

## Fail-closed admission

B1 blocks, with an explanatory error, all of the following in an enrolled canonical
checkout, including through a second `AGENT_ORCHESTRATOR_HOME`: planned and unplanned
`launch`, `--allow-dirty`, `--allow-concurrent-workspace`, plan override flags, role labels,
subdirectory, symlink and linked-worktree path forms, the repository's `.git` directory and
children, the bare repository behind a linked worktree, and the administrative Git
directory (or its children) of a `--separate-git-dir` checkout or submodule; legacy
`create-plan`; `bind`
(including launch binding); legacy `record-review`/plan completion; `set-executors`; and
`_worker` entry with a managed plan or enrolled workspace. Enrollment in an un-enrolled
checkout still fails closed while any admitted job from any state home is alive. After
`CONSENSUS_REACHED`, every managed writer still fails closed and the checkpoint reports
the B2 implementation gate. B1 makes no security claim against an operator who edits local
state outside the runner.

## Limits and risks

- POSIX local-filesystem assumptions for locks, rename and fsync.
- Three protocol rounds are fixed by the active policy version 2; a dissent exhausts the
  default budget. Policy version 1 history keeps its original four-role semantics.
- Receipt identities are coordinator-trusted until a later slice connects provider results.
  B1 cannot verify locally that a supplied design digest matches external bytes.
- Schema evolution requires a new policy version or an explicit migration. Roster changes
  are fixed policy definitions, not arbitrary user configuration.
- The moderator must reject hollow answers before submission; the runner additionally
  enforces structural substance, exact schemas, per-item byte bounds and size bounds.
- Crash windows are covered by atomic first-event publication, recoverable intent and
  replay regeneration, not by assuming projections are current.
- Active-job reservations rely on process-ID liveness plus a shared repository lock; a
  recycled PID could keep a dead reservation live until the process exits. This delays
  enrollment but never admits a writer. B2 owns process-lifetime leases and dirty-checkout
  protections.
- Two simultaneously running coordinators in different state homes can still launch
  concurrently; B1 only guarantees that enrollment cannot start over an admitted job and
  that a launch cannot enter an enrolled checkout.

Focused tests live in `plugins/agent-orchestrator/tests/test_b1_consensus.py`; the upstream
suite remains in `test_cli_agent_job.py` and `test_dashboard_server.py`.
