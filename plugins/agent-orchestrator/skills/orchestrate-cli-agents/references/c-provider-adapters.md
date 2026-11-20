# C named provider adapters

Status: Phase C primitive. Full provider integration and managed research acceptance remain
provisional until Phase D adds authorization/review gates and Phase F passes the complete
multistep mock workflow. C starts no review lifecycle, grants no merge authority and does not
mint any acceptance or cryptographic evidence.

C adds two reserved profiles, `deepseek` and `glm`, that invoke the user's existing Claude Code
Bash functions through the actual interactive startup context. It preserves the native
`deepseek-harness` profile and every legacy adapter unchanged.

## Operations and capability

Version 1 operations are explicit launch input (`launch --operation ...`); freeform task text,
role labels and model names are never used to infer capability.

| Provider | proposal | cross_examination | consensus | implementation | repair |
| --- | --- | --- | --- | --- | --- |
| `deepseek` | readonly | readonly | readonly | workspace_write | workspace_write |
| `glm` | readonly | readonly | readonly | denied | denied |

The versioned table digest is recorded in every binding and normalized result:

- `capability_table_version`: `1`
- `capability_table_sha256`:
  `19e48f237f766991e18e130979c7ebba48c82fc34a19dbd3488dc878d78d6787`

Among the reserved named providers, only DeepSeek `implementation`/`repair` receives workspace-write capability; legacy adapters keep their pre-existing behavior. The binding also records `binding_version`, `provider`, `profile`, `operation`, `capability`,
the wrapper shell/function/startup facts, and a canonical `binding_sha256`. The worker rebuilds
the expected binding from the persisted profile and operation and rejects any mismatch before
spawning a provider. A readonly job that carries a writer lease, a workspace-write job without
a B2 writer lease, a GLM writer operation, or a changed capability table fails closed with
`unauthorized_role`.

## Profile configuration

The reserved profiles are built in:

```json
{
  "agents": {
    "deepseek": {"provider_rcfile": "/absolute/path/to/interactive-rc"},
    "glm": {"provider_rcfile": "/absolute/path/to/glm-rc"}
  }
}
```

Only `provider_rcfile` may be overridden for a reserved name. `argv` is fixed to the single
function name, `prompt_transport` is fixed to `stdin`, and model/agent/turn/cost/effort fields
are rejected. Without an override, the real `bash -ic` startup context is used, so the user's
installed `deepseek` and `glm` definitions require no migration or new token file. A relative,
missing or non-regular rcfile fails before provider execution.

Named launches require `--operation` and the ordinary explicit executor approval
(`--approved-executor deepseek` or the same entry in a plan's durable pool). Passing
`--operation` to a legacy profile is rejected. Reserved launches also reject `--model`,
`--cli-agent`, `--max-turns`, `--max-cost-usd`, `--reasoning-effort`, Terra fallback,
feedback overrides and `--allow-concurrent-workspace`. Legacy profiles never gain named
provider rights.

## Wrapper grammar and credential capture

Supported wrapper grammar is deliberately small and lexical, never evaluated or rewritten:

```bash
deepseek () {
    export ANTHROPIC_AUTH_TOKEN="literal"
    export ANTHROPIC_BASE_URL='literal'
    export ANTHROPIC_MODEL=literal
    claude "$@"
}
```

- Zero or more `export NAME=LITERAL` or `NAME=LITERAL` statements followed by exactly
  `claude "$@"`. Sensitive static assignments are seeded whether or not they use `export`:
  Bash preserves an existing export attribute across a plain reassignment
  (`export TOKEN=old; TOKEN=new; claude "$@"` sends `new`), and a startup context may enable
  `set -a`. Over-seeding a genuinely local assignment only redacts a value that never reaches
  the provider.
- Single-quoted, double-quoted and unquoted literal values. Double-quoted `\"`, `\$`, `` \` ``,
  `\\` and line continuations are decoded literally.
- No parameter/command/arithmetic expansion, globbing operators, tilde expansion,
  redirections, pipelines, `eval`, `exec`, `command claude`, extra arguments, extra commands,
  or a function other than the reserved provider name. Any unsupported syntax fails with
  `credential_capture_unavailable` before the provider is released.
- Immediately before capture, the execution shell resolves `claude` in that same startup
  context. It must resolve to a direct external executable (a regular executable file,
  including a symlink). A Bash function, alias, builtin or any other shadow is unsupported
  delegation: the run fails closed with `credential_capture_unavailable` before the provider
  function or the delegated command is invoked, so a credential injected after capture can
  never reach the provider. A missing or non-executable external backend fails with
  `provider_unavailable`. The guard writes only one fixed nonsecret `ERR` reason over the
  private channel; it never reads, prints or persists the delegated body, environment or
  values.
- A missing provider function fails with `provider_unavailable`.

The actual execution shell sources the configured startup context, captures the function
definition and the complete exported environment as NUL-framed records over an anonymous
private `AF_UNIX` socketpair passed to bubblewrap as an ordinary inherited descriptor
(`pass_fds`); the descriptor number is supplied to the wrapper script as data. It is
deliberately neither the shell's stdin nor a descriptor declared with `--sync-fd`: bubblewrap
preserves ordinary inherited descriptors for the sandboxed command, while a `--sync-fd`
descriptor is held by bubblewrap and closed before the command runs. There is no filesystem
name and no temporary file. The shell then blocks for an acknowledgement on that same private
channel. The worker parses the definition, seeds an in-memory redactor from every sensitive
static assignment (exported or plain) plus sensitive inherited environment values, and only
then writes the acknowledgement. The shell closes the control descriptor and redirects the
provider function's stdin from the immutable task file before the function runs. Provider
stdout/stderr use standard descriptors and are preceded by a NUL barrier written after
acknowledgement, so bash startup diagnostics are discarded by stream position rather than by
timing. The terminating `END` record is recognized only in tag position by an incremental
framing parser, so a legal environment value that ends in `END` (such as `BACKEND` or `END`)
cannot end the capture in the middle of an environment record. An `ERR` record (reason,
optionally followed by the terminal `END`) is recognized in tag position across arbitrary
read splits; a truncated, extended or unknown error record remains a capture failure rather
than a trusted reason. Raw bodies and environments are
never written to argv, metadata, events, logs or task files. The whole-run deadline and an
explicit cancellation are polled during capture, before acknowledgement; either outranks a
missing, malformed or oversized capture and is classified as `timeout` or `cancelled`. If both
are observable at the same control check, the deadline is classified first, matching the state
precedence below.

Sensitive name classification is conservative:

- compound markers: `AUTH_TOKEN`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`;
- underscore-delimited segments: `TOKEN`, `PASSWORD`, `SECRET`, `CREDENTIAL`, `CREDENTIALS`;
- token-pattern backstop: Anthropic/OpenAI-style `sk-*`, GitHub `gh*_*`, Slack `xox*_*`,
  Google `AIza*`, AWS `AKIA*`, JWT-shaped values, and `Bearer` tokens.

Benign model/role names (`deepseek-chat`, `claude-opus`, `glm`) are preserved.
`TOKENIZERS_PARALLELISM` is not treated as a credential. C does not claim to detect arbitrary
undeclared secrets and does not control provider network egress.

## Isolation and process lifetime

The outer invocation is wrapped by `bwrap`, not only a selected child:

- read-only root bind; PID/IPC/UTS namespaces; `--die-with-parent`; all capabilities dropped;
- readonly jobs: workspace, job directory, coordinator state, Git administrative paths,
  home configuration/sessions and outside-project paths are read-only;
- workspace-write jobs: the workspace is the only shared writable tree; the job's `scratch/`
  and `channel/` are additionally writable; the workspace `.git` entry (including a linked
  worktree's regular marker file), the resolved Git administrative directory, the
  linked-worktree common directory, coordinator state and outside paths are remounted
  read-only after the workspace bind;
- canonical realpath and symlink-escape validation rejects job/state/rcfile paths inside a
  writable workspace and scratch/channel paths outside the job directory;
- the workspace root `/` is rejected, and an unavailable or non-functional bubblewrap probe
  fails with `isolation_unavailable` before any provider process starts. The probe verifies
  namespace creation and that an ordinary inherited descriptor reaches the sandboxed command,
  because the capture handshake depends on the same mechanism.

Reserved-provider availability probes are themselves confined. `doctor`, `catalog`, `choices`
and the legacy/launch admission paths run `bash --rcfile ... -ic 'declare -F <provider>'` inside
bubblewrap with a read-only root and an unshared network namespace, before any provider function
or model dispatch. Missing bubblewrap is an explicit `isolation_unavailable`; there is no
direct-shell fallback, so an rcfile startup side effect cannot write the workspace or consume a
provider quota during an availability check.

### D1 protected-execution seam (optional, typed)

`run_provider` accepts an optional typed `protection` object containing a version, a manifest
SHA-256 and workspace-relative `roots`/`anchors` (the C mount plan is derived and owned by C,
never by the writer):

```json
{
  "version": 1,
  "manifest_sha256": "<64 hex>",
  "roots": [{"path": "local.sql", "kind": "file"}],
  "anchors": [{"path": "other"}]
}
```

Validation is bounded and fail-closed: 256 roots, 1,024 anchors and 128 KiB encoded extra mount
argv; paths must be relative, canonical, strictly inside the workspace, free of symlinked or
special ancestors, non-nested, and free of Git/scratch/channel collisions. Readonly capability
never accepts writable anchors. Empty/default inputs preserve the historical argv byte-for-byte.
For workspace-write jobs the mount order is: whole-project RW, parent-first same-path RW
ancestor anchors, Git RO, protected roots RO, then scratch/channel RW.

When roots are declared, C writes a private check script and check set into the job directory
and prepends a small wrapper command. The wrapper reads the actual mount table inside the
claimed namespace (`/proc/self/mountinfo`) before the provider rcfile is loaded, verifies that
each protected root is read-only (and has no writable mount beneath it), and that each anchor,
workspace, scratch and channel is writable. It reports a nonce-bound status line on a dedicated
inherited descriptor; C refuses to acknowledge the capture handshake or start the provider if
the status is missing, malformed, timed out or failed. The provider-result gains a versioned
`confinement` object containing the manifest digest, mount-plan digest, extra-argv byte count,
actual bubblewrap argv digest, and application evidence (`verified`, checked count, nonce/status
digests). D1 compares that object to the coordinator-owned manifest and rejects provider echoes,
argv assertions alone, or a non-confining transport shim as protection. A run with an empty
declared protected set records an explicit `empty-protected-set` coverage statement instead of
claiming a mount was applied.

Claude Code is invoked through the unchanged user function with:
`-p --output-format stream-json --verbose --permission-mode ... --tools ... --allowedTools ...
--disallowedTools ... --strict-mcp-config --mcp-config '{"mcpServers":{}}'
--disable-slash-commands --no-session-persistence`. Discussions use `plan` mode and
`Read,Glob,Grep`. Writers use `acceptEdits` plus `Read,Write,Edit,Glob,Grep,Bash` and may add
scratch/channel directories. No `bypassPermissions` or skip-permissions flag is used, and no
model/provider/auth environment value is overridden.

The existing B2 supervisor remains the durable lifetime anchor for writers; worker cancellation,
timeout, status and completion receipts are unchanged. Readonly jobs never acquire or release
the B2 writer lease and use the existing canonical admission lock plus unique repository
reservations. A readonly launch is refused while a writer lease is live or unprovable; a writer
launch is refused while any readonly provider job is live, including across state homes.
`--allow-concurrent-workspace` cannot bypass this. Readonly PID isolation and
`--die-with-parent` prevent leaked descendants.

## Result v1

A named job succeeds only when the worker persists a normalized, sanitized
`provider-result.json` whose `validated` field is true. The provider's exit code alone is never
success evidence. `provider-result.json` is written by the worker (mode 0600) in the job
directory, which is not provider-writable.

```json
{
  "result_version": 1,
  "provider": "deepseek",
  "profile": "deepseek",
  "operation": "proposal",
  "capability": "readonly",
  "binding": {"...": "versioned capability binding"},
  "binding_sha256": "<64 hex>",
  "capability_table_version": 1,
  "capability_table_sha256": "<64 hex>",
  "validated": true,
  "envelope": {
    "subtype": "success",
    "is_error": false,
    "num_turns": 1,
    "duration_ms": 1,
    "duration_api_ms": 1,
    "session_id": "...",
    "total_cost_usd": 0.0,
    "usage": {}
  },
  "payload": {"...": "operation payload"},
  "payload_sha256": "<64 hex>",
  "error": null,
  "exit_code": 0,
  "timed_out": false,
  "cancelled": false,
  "scope_violations": [],
  "diagnostics": {
    "stdout_bytes": 0,
    "stderr_bytes": 0,
    "stdout_truncated": false,
    "stderr_truncated": false,
    "stderr_tail": "optional sanitized tail"
  },
  "captured_at": "ISO-8601",
  "confinement": {
    "version": 1,
    "manifest_sha256": "<bound D1 manifest digest>",
    "plan_sha256": "<ordered mount plan>",
    "capability": "workspace_write",
    "counts": {"protected_roots": 1, "ancestor_anchors": 1, "extra_mount_argv_bytes": 185},
    "bwrap_argv_sha256": "<actual argv>",
    "application": {
      "method": "in-namespace-mountinfo",
      "verified": true,
      "checked": 5,
      "nonce_sha256": "<nonce digest>",
      "status_sha256": "<status line digest>",
      "errors": []
    }
  }
}
```

`confinement` is present only for protected D1 invocations; legacy calls that pass no typed
protection keep the original result shape and argv.

`result.json` and job metadata receive a compact `provider_result` summary and a
`provider_error` object; they do not duplicate the full payload. The sanitized `stdout.log` and
`stderr.log` are the only raw stream surfaces and are bounded. The full envelope must be exactly
one Claude `type: "result"` event with `subtype: "success"`, `is_error: false`, and a non-empty
`result`. Every other non-empty stdout line must be a JSON object. Exit zero with a missing,
malformed, empty or oversized envelope is a failure.

The completion `result` text must be exactly one JSON object, optionally inside one
` ```json ` fence:

```json
{"result_version": 1, "operation": "<bound operation>", "payload": {}}
```

Payload schemas (exact keys):

- `proposal`: `approach`, `rationale` (non-empty strings); `assumptions`, `problems`,
  `alternatives`, `testing` (non-empty string arrays); `feasibility` (non-empty string).
- `cross_examination`: `objections` (array of strings or objects with `objection` and optional
  `severity` in `low|medium|high`); `responses`, `revisions` (non-empty string arrays).
- `consensus`: `decision` in `AGREE|DISAGREE|NEEDS_DISCUSSION`; `candidate_sha256` (64
  lowercase hex); `rationale` (non-empty string).
- `implementation` / `repair`: `changed_paths` (array of relative repository paths; `..`,
  absolute paths and backslashes are rejected); `validation_commands`, `validation_outcomes`
  (non-empty string arrays); `remaining_issues` (may be empty).

Payload text is limited to 8 KiB per string/entry, 100 entries per array and 32 KiB of JSON;
a completion result is limited to 128 KiB. The sanitized result is re-parsed after redaction,
so malformed data can never become accepted evidence. Reports are evidence only; C performs no
independent validation of the claimed commands, paths or decisions.

### Error enum

`provider_error.code` and the normalized `error.code` are one of:

| Code | Meaning |
| --- | --- |
| `provider_unavailable` | reserved function, command or external backend is not available |
| `isolation_unavailable` | bubblewrap or a required mount/layout is unavailable |
| `unauthorized_role` | profile, operation, capability, binding, spoof or lease mismatch |
| `credential_capture_unavailable` | unsupported grammar, unsupported backend delegation or capture failure |
| `auth_failed` | provider-reported authentication failure |
| `rate_limited` | rate limiting / overload |
| `quota_exceeded` | quota, credit or billing exhaustion |
| `timeout` | job timeout won; no automatic fallback |
| `cancelled` | cancellation won |
| `execution_failed` | provider crash, nonzero exit or scope violation |
| `invalid_output` | missing/invalid envelope or payload |
| `output_limit` | bounded capture or line/payload limit exceeded |

Existing state precedence remains scope violation > timed out > cancelled > failure, and a
successful writer still requires B2's final integrity check and completion receipt.

## Stream limits and sanitization

Raw provider stdout/stderr is drained into bounded in-memory buffers (4 MiB stdout, 1 MiB
stderr) and sanitized by one redactor before any persisted surface. Because sanitization sees
the complete retained buffer, values split across provider write chunks are removed as units.
The redactor removes the raw value and bounded JSON-escaped spellings of it (quotes,
backslashes, control characters and non-ASCII, in both `ensure_ascii` forms, up to three
nesting layers for small values and two for larger values). This is required because a provider
result document is itself a JSON string inside the Claude completion envelope, so an echoed
credential can appear only in escaped form. A JSON encoder may also spell any character as
`\uXXXX`, including plain ASCII, in any literal/escaped mixture, so finite canonical variants
are not sufficient. Every persisted stdout/stderr line containing such escapes is therefore
verified through bounded JSON and escape-layer decoding against the known secrets; a leaking
line is canonicalized, re-verified, and withheld entirely if it still decodes to a credential.
A withheld result line cannot become accepted evidence. After stream redaction, the validated
payload and envelope strings are sanitized again and the payload is revalidated against its
schema before persistence. Truncated captures drop a secret-length holdback and mask any
remaining secret prefix.
A token pattern can never straddle a chunk boundary into persisted output. Startup stdout/stderr
(including `bash -i` job-control warnings) is discarded and never persisted. Oversized output is
killed and reported as `output_limit`; incomplete output is `invalid_output`.

## D contract boundary and known limits

- C owns canonical path/symlink validation, capability binding, capture, isolation, result
  validation and the evidence primitive. D supplies immutable task/evidence entries and the
  authorization/review gates that consume these results.
- B2 keeps content/scope attribution and completion receipts. The D1 protection seam adds
  OS-level read-only prevention for the declared original protected-user set and Git custody;
  clean tracked out-of-scope writes remain B2 detection (scope violation with no rollback), not
  a claim of universal per-file prevention.
- The wrapper function and startup context are trusted local user configuration. C confines the
  outer invocation, including rcfile startup and availability probes, but does not audit or
  redact arbitrary rcfile behavior beyond the sandbox. Availability probes never dispatch the
  provider function or a model, and do not persist startup output.
- The workspace `.git` entry (directory or linked-worktree marker file) and the resolved
  administrative/common directories are protected as mount policy; B2 remains authoritative
  for content attribution. This is OS-level mount prevention for those paths, not general
  file-scope enforcement.
- No automatic provider/model fallback exists. A missing or failing provider is a terminal
  categorized result for the coordinator to handle.
- Real sandbox tests require a working bubblewrap namespace implementation. Test runs report
  accurate `skipped` evidence when the host blocks namespaces; a non-isolating transport shim
  tests pipeline behavior only and is never used by the product.
- Only `claude --version`/`--help`-class local probes are quota-free provider checks. Mock tests
  do not prove real DeepSeek/GLM API integration; Phase F's complete mock E2E remains the gate.
