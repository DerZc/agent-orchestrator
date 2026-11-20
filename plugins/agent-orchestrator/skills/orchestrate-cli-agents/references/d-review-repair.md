# D2 independent validation, active-Codex review and bounded formal repair

Status: **D2 implementation scope ends at `REVIEW_APPROVED`**. D2 extends the existing
D1 execution journal; it is not a second orchestrator, store, scheduler or supervisor.
PR/CI/MERGED completion, dependency opening, commit/index custody and the E/F lifecycle
remain closed. A D2 approval is never `done` and never opens dependencies.

## Authorities reused unchanged

- B1 owns the plan lock, consensus, candidate and the one immutable ledger.
- B2 owns the exclusive common-Git writer lease, admission ordering, supervisor,
  subreaper, descendant drain and per-epoch completion receipt. A validation job is a
  narrow worker kind under that same lifetime; it never starts a provider/model job.
- D1 owns the append-only execution journal, content-addressed blobs, writer intent,
  claim, result, original-base evidence, original-user protection and cumulative delta.
- C owns reserved-provider capability, binding, result validation and capture redaction.
  DeepSeek remains the sole product writer with its actual configured command, auth,
  provider and model. GLM remains a readonly critic. Codex remains the single active
  leader and independent reviewer; there is no native Codex provider job.

D2 adds `d_review.py` and narrow hooks in `d_execution.py`, `cli_agent_job.py`,
`b1_consensus.py`, `b2_workspace.py` and `c_providers.py` (validator classification only).
D2 facts live in the same journal under separate reducer namespaces and never carry a
top-level writer `attempt_id`.

## Explicit version 2 policy before ballots

Strict candidates may carry `execution_constraints.version = 2`. Version 1 candidates
keep their exact historical normalization, bytes and digests and never acquire D2
authority. Version 2 adds one ordered `validation_policy`:

- stable `invocation_id`, label, exact literal `argv`, repository-relative `cwd`;
- `context` `ordinary_ro` or `systems_trusted`;
- purpose, mandatory flag, expected exit, timeout, capture bound;
- explicit `environment_policy = minimal_private`;
- `ro_enforcement = required` only; `observed` or any unconfined context is refused
  by the schema and can never be made eligible by a field;
- evidence kind `command_check` or `structured_unittest`;
- for structured tests, the pinned coordinator adapter path/SHA-256, report env name,
  and positive collected/run floors.

At least one mandatory structured invocation is required for approval. `command_check`
can never invent test counts. The frozen version 2 contract must exactly equal the
approved policy and the mandatory `required_validation` mirror; it cannot add, drop or
widen an invocation. The contract is voted before execution. Missing/unknown fields,
versions or proof fail closed.

## Actual validation

```bash
agent-orchestrator execution-validate --plan-id <plan> --step-id <step> --config <agents.json> --json
agent-orchestrator execution-validation-finalize --plan-id <plan> --step-id <step> --job-id <job> --json
```

A validation intent binds the exact current writer source, contract, policy, source
evidence, base snapshot, original base and original user baseline. Launch acquires the
same B2 exclusive lease and publishes a validation claim after the authoritative
baseline. The worker revalidates the journal/lease/source immediately before execution,
then runs the frozen literal argv in order, without a shell, parser injection or hidden
argv rewriting.

Each entry records actual argv/cwd/executable identity, environment key digest, context,
RO mode, timestamps, exit/timeout/cancel/overflow, bounded capture digests and sizes,
evidence kind and reasons. Structured evidence comes only from the pinned stdlib
unittest adapter (`d_review.py _unittest-adapter ...`), which writes a bounded
machine-readable report into private per-run scratch. The validator checks the report's
run id, argv digest, cwd, adapter identity/SHA, counts/identities, positive floors, zero
mandatory skips/failures/errors, process-exit coherence and the B2 receipt. Prose,
JUnit, terminal summaries and exit 0 alone never establish success.

Both contexts require real bubblewrap mount namespaces proven by an in-sandbox
probe that distinguishes an actual `EROFS` refusal from a missing path or `EACCES`.
A pass-through shim fails the probe and the batch is `BLOCKED`; there is no
fallback, direct execution or third context. `ordinary_ro` runs with
`--unshare-pid` and `--cap-drop ALL`, and the probe records the concrete euid,
capability mask, PID and PID namespace. `systems_trusted` retains no more than the
current coordinator capabilities (no cap-add or setuid widening) and additionally
requires a distinct current active-Codex preflight exported by `execution-preflight`;
the preflight can only confirm an already voted invocation.

The measured mount order is root read-only, known coordinator/GitHub/SSH/provider
credential-root masks, a private `/tmp`, an explicit read-only rebind of the
canonical source, an exact literal rebind of the pinned adapter (and its sanitizer
sibling) only for `structured_unittest` invocations that declared it in the ballot, and
finally the private writable scratch. A plain `command_check` declares no adapter grant,
so the masked coordinator state must actually hide the adapter from it; adapter exposure
is never inferred from arbitrary command arguments. The whole coordinator state is never
re-exposed to make the adapter reachable.
Known-root masks and environment filtering are not a whole-host credential closure.
Read-only is an accidental-write guard, not adversarial confinement; privileged
contexts can reach host `/proc`, parent processes and the shared network. Captures
are sanitized with the shared C redactor (known sensitive environment values are
collected in memory only) before any capture file, blob, head text or structured
identity/diagnostic is persisted.

Any capture overflow, source/index/user drift, missing/duplicate/foreign invocation,
corrupt evidence, tampered report/capture, non-clean B2 final check or unsupported
context records a failed/blocked batch. The latest durable batch is authoritative: a
later pending, failed, cancelled or incomplete batch invalidates an older approval.

A claimed batch is classified from actual durable/runtime evidence. B2 can prove it is
still running, fully drained and finalizable, fully drained while missing a proof file,
or unreconciled. A dead batch whose `validation-evidence.json` (or another proof) was
never published is recorded by finalize as a durable `blocked` result with the exact
missing files; it never stays `VALIDATING` forever and never invents positive evidence.
Finalizing the same dead batch again is idempotent, and a fresh validation batch against
the unchanged exact source is the supported retry. If ownership or drain cannot be
proven, the projection is a precise `BLOCKED` requiring explicit reconciliation; a
potentially live lease is never reopened and an older approval is never reused.

## Actual active-Codex review

```bash
agent-orchestrator execution-review-begin \
  --plan-id <plan> --step-id <step> --purpose <why> \
  --leader <active-codex-id> --session-file <private-file> --json
agent-orchestrator execution-review \
  --plan-id <plan> --step-id <step> \
  --review-file <review.json> --session-file <private-file> \
  --leader <active-codex-id> --json
```

The session is single-use and bound to the exact current source/design/contract,
validation batch, input bundle and review purpose. Only the token hash is public; the
token stays in the caller's private file and never in argv or logs. The review event
records the leader and process provenance. Session structure is coordinator authority,
not mathematical proof of reasoning.

The active leader inspects the objective, consensus, contract, full cumulative
original-base diff, changed files, author report, validation outcomes and regressions.
The normalized review persists every stable finding (defect/suggestion, severity,
files, evidence, required change, test recommendation), every acceptance-criterion
disposition and every prior-finding disposition. Every open actionable finding is
derived by replaying the actual review/design-link lineage: a review opens its own
defects, `resolved`/`obsolete` dispositions with evidence close one, and `carried`
keeps it open across same-source re-reviews, repeated rejections, repairs and design
links. A new review must dispose every still-open finding; changing IDs or carrying
only the newest parent cannot drop an older finding, and repair contracts/tasks cover
all open findings. `APPROVE` requires a complete implementation/repair, a valid author
report, the latest passing mandatory validation, all criteria satisfied, no open defect
and exact current source. `REQUEST_CHANGES` requires an actionable defect or actual
failed validation and explicit unsatisfied criteria; style preference alone is refused.
An explicit evidence-backed false-positive resolution or obsolescence is trusted actual
reviewer judgment, not a silent drop. A newer batch/source/contract/review invalidates
a derived approval without rewriting history.

The derived `REVIEW_APPROVED` projection re-observes the live source, branch, HEAD, Git
index and original-user custody on every checkpoint through the existing D1 primitives.
Owned, unowned, user, index or HEAD drift after approval sets `BLOCKED`, reports the
exact mismatch and invalidates only current approval; the immutable historical review
and report evidence remain recorded. Restoring the exact attributed source regenerates
the projection; nothing is auto-reverted or recaptured as authority.

## Bounded formal repair

```bash
agent-orchestrator execution-repair-contract --plan-id <plan> --step-id <step> \
  --review-id <review> --contract-file <repair-contract.json> --json
agent-orchestrator execution-repair-allocate --plan-id <plan> --step-id <step> \
  --review-id <review> --json
agent-orchestrator execution-repair --plan-id <plan> --step-id <step> \
  --allocation-id <allocation> --config <agents.json> --json
agent-orchestrator execution-finalize --plan-id <plan> --step-id <step> --job-id <job> --json
```

A contract is immutable and mechanically restricted from the approved design: allowed
patterns are an exact subset, denials are preserved, criteria and mandatory literal
validation are exact, and finding IDs cover every open actionable finding after the
current rejection, including carried findings. The sole DeepSeek writer runs the
existing `repair` operation.

A durable `repair_allocation` event consumes one formal slot under the plan lock at
allocation time. Used is derived from unique immutable allocations for the step across
all cycles and restarts; generation is monotonic; the idempotency key binds
step/generation/rejection/contract/source; identical retries return the same slot and
conflicting reuse refuses. There is no refund, reset or new-cycle reset. A fourth
allocation is refused.

Within one slot at most three pre-claim setup/transport attempts are allowed. Facts
consume the budget immediately; no-start must be proven from actual D1/B2 facts, and
ambiguity blocks. Once a durable reservation/claim/start exists, the fully drained
result is final for that slot: a new attempt requires a fresh actual Codex rejection and
a new available slot. Initial implementation continuation semantics remain historical
and cannot be used to evade this rule.

Repair admission is exact-parent only: prior reviewed parent/root lineage, genuine
immutable B2 completion/drain proof, unchanged original user bytes, exact branch/HEAD/
index custody and the exactly attributed cumulative owned delta. Unknown, torn or
user-edited residue blocks; recapture never authorizes it. The repair attempt keeps the
original implementation base and user baseline, so the cumulative diff stays
original-base to exact current owned source.

## Design-cycle lineage

`execution-design-link` journals a proven link from a previous frozen design to a new
unanimous design only when the exact previous owned source is current and every open
actionable finding has an explicit `resolved`/`carried`/`obsolete` disposition with
evidence. The repair budget is per step across designs and is never reset, and the old
rejection/approval is never relabeled as authority under the new design.

This implementation does not execute linked source carry: no validation, review or
managed initial-writer route accepts a previous-design source under a new contract.
A linked new cycle therefore reports a precise `BLOCKED` with actual original/new
design, source and budget evidence plus explicit human guidance; it never reports
`READY_TO_IMPLEMENT` while every permitted route refuses. Unlinked/unknown lineage
blocks as well.

## Derived state and recovery

`plan-status`/`plan-checkpoint` expose derived `AWAITING_VALIDATION`, `VALIDATING`,
`VALIDATION_FAILED`, `VALIDATION_BLOCKED`, `AWAITING_REVIEW`, `REPAIR_REQUIRED`,
`REPAIR_PREPARED`, `REPAIRING`, `REVIEW_APPROVED` and `BLOCKED` views plus the per-step
durable repair budget and the latest pending validation's actual runtime classification.
Version 1 plans keep their exact D1 view. The D2 stage is derived only from journal
events and immutable B2 evidence; no done/MERGED/dependency/legacy acceptance gate can
be minted. Crashes recover from the actual receipt + journal: allocation survives
restarts, retries never duplicate a slot, unused intents can be reissued only when no
start is provable, a fully drained batch with missing proof becomes a durable blocked
result instead of an eternal `VALIDATING` stage, and uncertainty returns a precise
BLOCKED state with next guidance instead of a skipped agent.

## Closed routes and limits

- E commit/index custody is interface-only and CLOSED; no appender, manual SHA,
  `verified=true` string or schema helper grants eligibility.
- PR, CI, MERGED, dependency opening and legacy review-to-done remain CLOSED.
- Trusted Codex judgment and session provenance cannot be mathematically authenticated.
- Privileged validation retains unavoidable host access despite read-only guards.
- Kernel/path/cache/tool behavior may make a context unsupported; the batch reports
  BLOCKED rather than downgrading a mandatory invocation.
- Native provider/nested release integration remains provisional until F.

Baseline D2 tests use mock provider CLIs and synthetic repositories only; they consume
no provider quota and make no live Oracle or GitHub claim.
