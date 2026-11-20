# D1 managed execution: provenance, contract, writer admission and attempt evidence

Status: **D1 implementation-complete scope only**. D1 connects a genuine three-role B1
consensus to one reserved DeepSeek writer, using the existing B1 plan lock/ledger, B2 writer
lease and C provider primitives. It stops at `IMPLEMENTATION_COMPLETE`. Review acceptance,
formal repair dispatch, independent validation execution, PR/CI/MERGED completion and
dependency opening remain structurally closed until D2/E. Native multi-step release behavior
is provisional until Phase F.

B1 remains the sole authority for the plan, discussion, candidate, ballots and
`CONSENSUS_REACHED`. B2 remains the sole repository-writer lease and completion-receipt
authority. C remains the sole reserved-provider capability/result validator. D1 adds one
versioned append-only execution-fact journal inside the existing plan directory:

```
<plan>/execution/events/NNNNNN.json   # hash-chained, ordered facts
<plan>/execution/blobs/<sha256>       # content-addressed immutable evidence
```

Journal events reference immutable B1 plan/step/cycle/candidate digests. They never copy
consensus truth and impose no global ledger-head equality. Every composite eligibility check
and append holds the one existing B1 plan lock. Blobs are published and fsynced before the
events that reference them. Replay validates recorded hashes and fails closed on a missing,
corrupt or unsupported journal, a broken chain, a missing blob or an invalid binding. Identical
operation IDs with identical inputs are idempotent; changed content under the same ID is
rejected.

## Strict enrollment

A production plan must opt in before the first discussion:

```bash
agent-orchestrator create-plan \
  --workspace <checkout> --plan-file <plan.md> --title <title> \
  --plan-id <plan-id> --research-team --manifest-file <manifest.json> \
  --strict-execution --json
```

Legacy plans and manual discussion records never gain source-write authority. Enabling a flag
later does not upgrade an old manual cycle; a fresh verifiable strict cycle or a new strict
plan is required. Strict plans reject every ordinary legacy launch in the enrolled checkout,
including role, job-ID, allow-dirty and concurrent-workspace overrides. Bootstrap development
records are not retrofitted into production receipts.

## Discussion provenance

Codex participates as the active trusted coordinator (`--leader`, never a provider job
identity). DeepSeek and GLM participate only through settled readonly C jobs launched by D1:

```bash
agent-orchestrator execution-discussion --plan-id <plan> --step-id <step> \
  --role deepseek|glm --round 1|2|3 --task-file <task.md> \
  --timeout-seconds 3600 --config <agents.json> --json
agent-orchestrator wait <job-id> --json

agent-orchestrator consensus-submit --plan-id <plan> --step-id <step> \
  --role deepseek|glm --round 1|2 --submission-file <mapped.json> \
  --source-job <job-id> --json
agent-orchestrator consensus-vote --plan-id <plan> --step-id <step> \
  --role deepseek|glm --digest <candidate-sha256> --vote AGREE \
  --rationale '<exact provider rationale>' --source-job <job-id> --json
```

Before ingestion D1 verifies the protected assignment (plan, step, cycle, round, role,
operation), actual job identity/provider/operation/capability, terminal result, drained
processes, validated C result, protected result/payload hashes and unchanged source context.
The submitted JSON must equal the deterministic versioned C-to-B1 mapping:

- `proposal`: `problems -> risks`, `testing -> tests`, all other fields preserved.
- `cross_examination`: normalized `objections -> challenges`; B1 assigns objection IDs.
- `consensus`: `decision -> vote`, `candidate_sha256 -> digest`, rationale preserved.

Both the original C payload hash and the mapped hash are retained in the content-addressed
evidence blob. A valid-but-insufficient provider payload is rejected; no filler fields or
relaxed B1 minimums are used. Invalid, failed or missing participants never fill a slot.
Every old manual submit/vote path applies the same gate on strict plans.

## Frozen candidate constraints

Every strict candidate must include a version 1 `execution_constraints` object before
ballots, and all three roles approve its candidate digest:

```json
{
  "version": 1,
  "allowed_paths": ["plugins/agent-orchestrator/scripts/d_execution.py"],
  "denied_paths": [".env", "scripts/keys/**"],
  "criteria": [
    {"id": "C001", "text_sha256": "<sha256 of exact manifest criterion text>"}
  ],
  "required_validation": [
    {"argv": ["python3", "-m", "unittest", "discover", "-s", "tests"]}
  ],
  "max_changed_files": 12
}
```

`criteria` must cover exactly the manifest step's acceptance-criteria text digests using
stable IDs. This is structural coverage, not a semantic proof. Patterns are
repository-relative; absolute, escaping, NUL and `.git` patterns are rejected. The approved
constraints are rendered into `CONSENSUS.md`. Legacy candidates omit the field entirely and
keep their exact historical hashes and rendering.

## Frozen execution contract

After unanimous consensus, Codex freezes a separate detailed contract bound to the candidate:

```bash
agent-orchestrator execution-contract --plan-id <plan> --step-id <step> \
  --contract-file <contract.json> --json
```

The contract adds objective, why, relevant modules, exact allowed/denied patterns, required
behavior/interfaces, tests, stable acceptance criteria, literal validation argv, reporting and
the target/protected branches. Mechanical checks reject a wider allowed-pattern set, a weaker
denial set, a missing or substituted criterion/text digest, a dropped required argv, a raised
file bound, a protected/main target branch, or a target branch other than the current HEAD.
Glob patterns are compared as exact approved globs, never resolved as one path. A different
contract for the same candidate is refused; an identical retry is idempotent. Semantic review
of English requirements is D2 work.

## Writer admission and completion

Only `execution-implement` can start a D1 writer, and it always uses the reserved DeepSeek
`implementation` operation in the canonical shared checkout:

```bash
agent-orchestrator execution-implement --plan-id <plan> --step-id <step> \
  --task-file <task.md> --timeout-seconds 3600 --config <agents.json> --json
agent-orchestrator wait <job-id> --json
agent-orchestrator execution-finalize --plan-id <plan> --step-id <step> \
  --job-id <job-id> --json
```

The launch sequence is fixed:

1. A brief plan-lock section publishes an exact intent, deterministic job ID, issuer
   process-start identity and immutable input hashes. The intent is a fence, not write
   authority.
2. The existing C canonical admission runs and the existing B2 writer lease is attempted once,
   nonblocking, outside the plan lock.
3. With the actual lease held, a brief plan-lock section revalidates the intent and publishes
   a claim bound to the exact job, cycle, candidate, contract, B2 epoch and source/base
   snapshots. The existing protected reservation is published before spawn.
4. The existing supervisor/worker topology owns lifetime. The worker revalidates the protected
   assignment/claim, current B1 binding, C capability, B2 ownership and unchanged workspace
   immediately before the effectful provider invocation.

Pre-existing dirty, untracked, staged, ignored and hidden-index user content is frozen as an
original protected-user set, distinct from clean tracked approved source. The set is derived at
the intent under the plan lock and published as a versioned, content-addressed manifest bound to
the plan/step/cycle/candidate/contract/original base and observed user baseline. Ignored content
is enumerated at Git's directory level (`--ignored --directory`): a disjoint ignored tree is one
read-only root and its bytes are never recursively hashed, so a 50,000-entry environment or a
sparse file above 128 MiB stays usable. Raw B2 hashes are retained only for dirty, untracked,
staged and hidden-index material actually observed. Manifest coverage is honest: a root's
metadata and read-only mount identity are not a digest of every byte in its tree.

Before any provider startup, C builds the ordered confinement: whole-project RW, parent-first
same-path RW ancestor anchors, Git marker/admin/common RO, protected-user roots RO, then
validated external scratch/channel RW. All paths are canonical, workspace-relative and
symlink/special-file safe; Git, scratch, channel and protected-root collisions are refused.
A bounded writable-regular-file hardlink guard refuses pre-existing aliases that could bypass a
readonly root, while normal directory link counts are never rejected and huge readonly ignored
trees are not traversed. C adds a pre-provider in-namespace check (`/proc/self/mountinfo`) that
the declared roots are read-only and the declared anchors, workspace, scratch and channel are
writable; the provider rcfile is not loaded unless the check succeeds. C returns the actual
ordered mount plan, argv digest and application evidence in `provider-result.json`, held outside
the writable workspace; D1 verifies it against the manifest. A missing, stale, tampered or
unverified proof blocks completion. A non-confining transport shim is therefore explicitly
refused for a protected writer rather than accepted as protection.

In-scope protected user content is refused before provider startup. Roots that meet an approved
writable path are refined within bounds (protect the ignored children, leave the approved new
path writable) or refused before startup; there is no reopen or unprotected fallback. New
approved directories under mixed pinned parents and native root-file temp+rename work because
only the protected children are remounted read-only. Any change to a declared root or anchor
identity, including an out-of-scope overwrite, blocks completion as uncertain. Clean tracked
out-of-scope writes are not kernel-prevented by this narrow scheme: the kernel protection covers
the original protected-user set and Git custody, while B2's complete scope-delta gate records
such a write as a scope violation and blocks completion without rollback.

Default protection caps are 256 read-only roots, 1,024 ancestor anchors, 128 KiB encoded extra
mount argv and 100,000 remaining mutable stat paths. Each is validated independently; overflow
is an explicit pre-start refusal, never truncation, and caps cannot be widened by role or
configuration. Supported new/deleted/binary/mode/symlink changes are captured; unsupported
structures (including symlinked protected content) fail explicitly. Provider Git metadata is
readonly and no worktree/reset/stash/rollback is used.

`IMPLEMENTATION_COMPLETE` requires all of the following: a successfully validated C
implementation report from the reserved DeepSeek writer, matching versioned protection evidence
and actual C confinement application, a finalized immutable B2 receipt after all descendants
drained, clean branch/index/user/scope integrity, reconciled cumulative changed paths, and a
frozen original-base diff plus raw content, snapshots, contract, intent, claim, manifest, job
evidence and receipt hashes. A job exit code, process success or writer echo alone is never
completion. Reported paths that do not reconcile with the actual cumulative delta produce a
drained failure, not success.

## Recovery and same-attempt continuation

Every failure window is recorded as an explicit durable intent/claim/result/blocked/abort
state. Recovery reads recorded job, lease, process, result, receipt and content evidence; it
never infers success or "never started" from elapsed time or an exit code.

- A provable pre-invocation no-start can be closed with `execution-abort` only when no job
  process, live/uncertain lease or durable result/receipt exists.
- A drained post-invocation failure is recorded with attributable residue. It cannot be
  relabeled as never started.
- `execution-continue` authorizes one same-attempt retry only when the workspace exactly
  matches the drained residue digest and every protected user/index baseline is unchanged. The
  original protection manifest is reused, its root/anchor identities are revalidated, and only
  the exact B2-attributed prior delta outside the original protected set is treated as owned
  residue. Unknown/torn/user-edited residue blocks continuation; capturing its bytes never
  authorizes them. Attempts recorded before protection evidence existed are never upgraded
  silently.
- A missing/uncertain report, receipt, ownership record or unknown residue leaves the attempt
  `BLOCKED`/`SUSPECT`. Nothing is auto-reverted and no duplicate live writer is created.
- Each implementation attempt has a bounded invocation budget, default 3, honoring a stricter
  existing executor budget. Exhaustion requires guidance. Every partial result is retained.

## Cycles, views and closed gates

Reopening a cycle is refused while an owned intent/claim is pending or any prior attempt is
uncertain/blocked. A quiescent reopen (including after a drained failure or completion) is
explicit and preserves all history; the old binding immediately becomes ineligible because
eligibility always checks the current B1 cycle/candidate/contract. A non-unanimous
`HUMAN_DECISION_REQUIRED` cycle requires an honest `--authorization-kind human`; coordinator-
requested consensus is available only after a successful unanimous cycle. Human decision states
never auto-reopen.

The step-lineage formal-repair budget (limit 3) is reserved, monotonic across designs/restarts
and visible in checkpoint output. D1 consumes none and structurally refuses every repair or
acceptance path; D2 implements actual consumption.

`plan-status`, `plan-checkpoint` and `CONSENSUS.md` expose the derived D1 stage,
attempt, next action, missing evidence and blocked reasons. `dashboard --json` includes the
managed assignment and plan execution stage on each job row. These views never mark a plan
item done. Later source drift after completion sets `source_drift`, keeps the historical
completion fact, and makes the old evidence ineligible for acceptance or continuation. A
corrupt journal or missing evidence blob fails the derived view closed.

Closed in D1 and refused by both runner and journal structure:

- review acceptance / update-done,
- formal repair dispatch and repair-budget consumption,
- independent validation execution,
- PR/CI/MERGED completion,
- dependency opening.

These require later slices and their own consensus. `IMPLEMENTATION_COMPLETE` is not review
acceptance and does not make the plan or item complete.

## Validation notes

The D1 test suite executes actual mock CLI processes through the real runner/C/B2 pipeline for
DeepSeek/GLM proposals, cross-examinations, ballots, mapping, consensus and the DeepSeek root
implementation. Cases with an empty original protected-user set use an explicitly labeled
non-isolating transport shim and make no confinement claim. Cases that declare protected user
roots require real host bubblewrap: C refuses to start the provider when the declared read-only
mounts cannot be proven inside the namespace, so those cases skip honestly on hosts without
working namespaces and are run by Codex on a capable host. Real-namespace and full-host checks
remain authoritative; no provider quota is used by routine tests.
