---
name: el-gas-amp-audit
description: "Audits Ethereum execution-layer client source (go-ethereum, Nethermind, Besu) on master/main for gas-to-resource amplification bugs — operations where the attacker pays O(1) gas but the client allocates O(N) memory or spends O(N) CPU within EIP-7825's 30M per-tx gas cap and the 45M mainnet block limit. Use when asked to audit an EL client for DoS, OOM, memory-amplification, or CPU-DoS bugs; when investigating suspicious precompile or opcode resource usage; or when hunting for bugs in the shape of the ECADD precompile-cache OOM class. Produces a filtered candidate list, runs fp-check on survivors, and emits a Kurtosis PoC for confirmed findings."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Task
  - Skill
  - Write
  - Edit
  - AskUserQuestion
  - TaskCreate
  - TaskUpdate
  - TaskList
  - TaskGet
  - WebFetch
---

# Auditing execution-layer clients for gas-to-resource amplification

## Bug class in one paragraph

An **amplification bug** exists when an EVM operation — a precompile,
an opcode, a state access, a block- or tx-level cache, a mempool
bookkeeping step, a journal entry — charges a low, gas-bounded amount
per call but causes the host client to allocate memory or spend CPU
in proportion to attacker-controlled input of unbounded size. The
attacker's budget is capped at **EIP-7825** (30 M gas per transaction,
effective in Osaka) and **~45 M per block** (current mainnet limit).
The client's resource cost is not. If the ratio
`client_resource_per_gas` exceeds a realistic host's tolerance
(roughly: ≥ 100 bytes/gas for memory; ≥ 100 μs/gas for CPU), two
ordinary mempool transactions land a consensus-valid block that
OOM-kills or stalls the client. Fix direction: price the operation
by its actual client-side cost, or bound the allocation independently
of the input.

**The vector is not restricted to precompiles.** Any code path the
EVM touches is in scope. See `references/candidate-enumeration.md`
for the six categories (precompile cache wrappers, opcode
handlers with retained copies, block-level caches, state retention
surfaces, CPU-bound primitives, and recently-merged code). Anything
a gas-paying call can nudge into super-linear client work qualifies.

The publicly-disclosed canonical instance is a precompile wrapper
(Nethermind's `CachedPrecompile` keying a block-scoped cache on full
input bytes that the underlying precompile trims away), but that's
just the first finding, not the shape of the whole class. The
specific *mechanism* there — "wrapper keys on bytes the callee
ignores" — generalises to any layered component where the inner
layer trims or parses-then-discards and the outer layer retains.
Journals, receipts builders, snapshot stacks, tx-pool lookups,
access-list materialisers, all fit the pattern.

## When to use

- "Audit geth/Nethermind/Besu master for gas amplification / DoS /
  memory-amplification / OOM bugs in the EVM path."
- "Check if precompile X is vulnerable to the ECADD OOM class."
- "Investigate suspicious resource usage in the EL after a recent
  change."
- "Hunt for operations that pay O(1) gas but cost O(N) client resource."
- User hands you a suspected amplification pattern and wants a rigorous
  audit pipeline rather than ad-hoc opinion.

## When NOT to use

- Consensus-layer (CL) bugs — use `cl-consensus-bugs` and friends.
- Correctness/divergence bugs where the primitive returns the wrong
  value — use a differential fuzzer (`goevmlab`, `eest`); this skill's
  oracle is resource usage, not output correctness.
- Pure CPU micro-optimization hunts — if the attack requires a specific
  victim host configuration (e.g. swap off, 2 GB RAM) rather than any
  realistic mainnet node, de-scope.
- Anything gated behind a privileged RPC or admin API — the attack
  surface for this class is the mempool (ordinary EIP-1559 txs).

## Threat model — the numbers that bound the attacker

Before any audit, internalise the caps. An attacker controls:

| Cap | Value | Source |
|---|---|---|
| Per-transaction gas | **30,000,000** | EIP-7825 (active on Osaka mainnet) |
| Per-block gas | **~45,000,000** | Current mainnet block gas limit |
| Tx calldata per tx | bounded by intrinsic cost | 4 gas/zero byte, 16 gas/non-zero byte → ~1.9 MB max calldata per 30 M-gas tx of pure calldata |
| EVM memory per frame | quadratic expansion cost `3·w + w²/512` | Yellow Paper; attacker pays ONCE per frame, then reuses |

Practical consequences:

- The attacker can **pre-expand ~1.5 MB of EVM memory for ~5.6 M gas**,
  then loop inside it at ~300 gas/iter. That leaves a 24 M-gas budget
  for ~80,000 precompile or opcode calls *operating on the same 1.5 MB
  region*.
- Tx calldata is paid per-byte; EVM memory contents are not. If the
  amplification vector is "calldata gets copied", the attacker pays 16
  gas/byte — a per-byte tax that usually kills the attack. If the
  vector is "EVM memory gets copied or hashed", the attacker pays
  nothing per byte after the one-shot memory expansion.

Any bug reasoning must respect these caps. A "PoC" that needs 1 GB of
calldata to trigger is not exploitable — don't bother with the
Kurtosis step.

## The three-trigger rubric

Regardless of whether the surface is a precompile, an opcode, a
cache, or a journal, a candidate must satisfy **all three** to be
viable:

1. **Client-side resource allocation is proportional to
   attacker-controlled input size or iteration count**, with no
   bound independent of the attacker. Typical shapes: `input.ToArray()` /
   `copy(dst, input)` / `make([]byte, len(input))` in a retention
   path; map/dictionary insertions keyed on the full input; stack
   pushes to a journal that never rewinds; state-snapshot entries
   that copy whole slots rather than deltas.
2. **Per-call gas cost is flat or sublinear in the allocation size.**
   Flat-gas operations with `BaseGasCost = constant` and zero
   per-byte tax are the worst offenders. Operations that pay per-word
   or per-byte (SHA-256's `60 + 12·word_count`, memory expansion's
   quadratic-in-words cost) are generally safe *for per-byte tax*
   — but don't confuse per-byte memory-expansion with per-byte
   retention cost. The attacker only pays expansion once per frame.
3. **The allocation survives across calls within a single block.**
   If every call's allocation is released before the next call
   starts, there's no amplification. Block-scoped caches,
   dictionaries, journals, and snapshot stacks are prime offenders;
   short-lived per-frame buffers usually are not.

Miss any one and the bug doesn't ignite. All three, and you have a
hammer.

For CPU-DoS the rubric is the same with "CPU time ≥ 100 μs/gas" in
place of bytes/gas. CPU-DoS is most commonly found in cryptographic
primitives (pairing, modexp-on-huge-modulus) and in tight inner
loops over attacker-controlled-size collections (access-list
expansion, delegation chains on EIP-7702, journal replay during
reversion). See `references/amplification-math.md` for the math.

## The pipeline

```
  1. Enumerate candidates          2. Compute amplification      3. fp-check
  ───────────────────────          ──────────────────────       ──────────
  (per client, per category)  ──►  (bytes/gas, μs/gas)     ──► (mandatory)
                                     threshold filter                │
                                                                     ▼
                                                              4. Kurtosis PoC
                                                              ──────────────
                                                              hammer contract +
                                                              multi-EL devnet +
                                                              OOMKilled oracle
```

### Step 1 — Enumerate candidates

Read `references/candidate-enumeration.md` for the **exact grep
patterns, file paths, and category rubrics** for each client on
master/main. Short version:

- Precompile dispatch and cache-wrapper code
- Opcode handlers that copy/return calldata, code, memory
- Block-level and tx-level caches that key on input
- State retention surfaces (SELFDESTRUCT graveyard, tx-pool
  retention, access-list materialisation)
- CPU-heavy primitive paths (modular arithmetic with
  attacker-controlled moduli, pairing with attacker-controlled pair
  counts)

Each candidate is recorded as:

```
client: geth|nethermind|besu
site:   path/to/file.go:LINE
op:     <opcode or precompile address>
input:  <what the attacker controls>
alloc:  <what gets allocated/computed>
gas:    <flat cost or formula>
```

### Step 2 — Compute amplification math

Read `references/amplification-math.md`. Short version:

- `bytes_per_gas = alloc_bytes_per_call / gas_per_call`
- `calls_per_block = 45_000_000 / gas_per_call` (upper bound; real
  budget is lower after intrinsic + memory-expansion costs)
- `total_alloc_per_block = bytes_per_gas × 45_000_000`
- **Flag if** `bytes_per_gas ≥ 100` and
  `total_alloc_per_block ≥ 10 GB`. Below that, even a fleet-wide
  attack is absorbed by normal GC headroom.

For CPU-DoS: `us_per_gas = wall_clock_us_per_call / gas_per_call`.
Flag if `us_per_gas ≥ 100` or if one transaction can cause
`total_block_wallclock_s ≥ 12` (a full slot time).

### Step 3 — fp-check

**Every surviving candidate MUST pass `fp-check` before a Kurtosis
PoC is built.** Amplification candidates fail at this step more often
than people expect — common failure modes:

- The "unbounded allocation" is actually gated by a caller that
  validates length.
- The per-call gas cost turns out to be per-byte when computed for
  the attacker's input size.
- The allocation is short-lived — released before the next call in
  the same tx — so no amplification actually accrues.
- The "cache" is per-tx rather than per-block, so it clears before
  the attacker loops.

Invoke `fp-check` as a skill with a full evidence package:

```
Skill(fp-check) with args:
  "Verify [client]:[site] amplification candidate. Bug claim:
   [op] charges [gas] per call while allocating [bytes_per_call]
   bytes in [cache-structure]. Allocation is [not] released between
   calls. Attacker's 30M-gas-per-tx budget yields [calls_per_tx]
   calls × [bytes_per_call] bytes = [total_bytes_per_tx]
   of sustained heap growth."
```

Consume its verdict:
- `TRUE POSITIVE` → proceed to Step 4.
- `FALSE POSITIVE` → archive the candidate with fp-check's
  rationale in `findings/false_positive/<id>.md`; do NOT build a
  PoC.

### Step 4 — Kurtosis PoC

Read `references/kurtosis-harness.md`. Short version:

- A three-participant devnet: one honest proposer EL (opposite client
  from the victim), victim EL paired with a validating CL, a second
  victim EL paired with a **non-validating** CL (the "bystander"
  importer).
- `port_publisher.nat_exit_ip` must be UNSET — setting it to
  `127.0.0.1` breaks inter-container CL peering (ENR loopback
  self-dial). See the `kurtosis-devnet` skill's peering-pitfall
  reference.
- A `hammer(iters, size, seed)` contract built with Foundry, matching
  the amplification target (adjust `InputLength` prefix and the
  mutating-suffix offset per precompile).
- Two transactions to the public RPC of the proposer EL: Foundry
  `cast send --async` with explicit nonces. Natural mempool flow; no
  Engine-API manual injection needed once CL peering works.
- Oracle: `docker inspect <victim> --format '{{.State.OOMKilled}}
  {{.State.ExitCode}}'` prints `true 137`. Also watch:
  - Per-second `VmRSS` samples from `/proc/<pid>/status`.
  - Victim container's Prometheus `nethermind_memory_used_by_cache`
    (or geth / besu equivalent) — if the gauge doesn't move while
    RSS explodes, that's its own finding ("operators can't see this
    coming").
- A healthy run of the PoC shows baseline RSS → 20+ GB within ~6
  seconds → `OOMKilled=true, ExitCode=137`, with the honest
  proposer EL continuing to build the chain.

The Kurtosis template lives in the companion swarm task at
`claude-swarm/tasks/el-gas-amp-audit/kurtosis/`.

## Rationalizations to reject

Read `references/rationalizations-to-reject.md` for the full list.
Most common:

- "The cache clears at end of block." Too late — allocation happens
  *during* block processing, kernel OOM-kills before the clear runs.
- "Gas bounds the allocation." No — at 3 kB/gas the 45 M cap buys
  the attacker ~135 GB of allocation requests.
- "State-test runners don't reproduce it." Many test-CLI binaries
  run with the block-processing prewarmer off (Nethermind's
  `nethtest` is the specific case). The wrapper is never installed
  in that mode; the bug is invisible to it. This is *not* evidence
  the bug isn't real — see `references/rationalizations-to-reject.md`
  for how to assert a repro under production config.
- "The attacker can't get the block included." They don't need to.
  Any non-Nethermind (or non-victim) proposer's vanilla builder will
  pack two ordinary EIP-1559 txs paying priority fees; no privileged
  position required.

## Working with this skill

1. If a user gives you a specific suspected site, jump to Step 2
   (math) and Step 3 (fp-check) on that site directly. Don't re-enumerate.
2. If a user asks for a full audit, fan out over the three clients in
   parallel using the `Task` tool with one sub-task per client + per
   category; consolidate findings; then serialise through `fp-check`
   and Kurtosis PoC.
3. When invoking `fp-check`, hand it the complete math, not a vague
   description — its verdicts are only as good as the evidence it
   gets.
4. When building the Kurtosis PoC, START from a *working* config
   (the `kurtosis-devnet` skill's templates), not from the
   ethereum-package defaults, to avoid the `nat_exit_ip` peering
   trap.
5. When reporting a confirmed finding, route severity through the
   `ethereum-bounty-severity` skill.

## References

- [`references/candidate-enumeration.md`]({baseDir}/references/candidate-enumeration.md) — Per-client grep patterns, file paths, and category rubric for geth/nethermind/besu on master/main.
- [`references/amplification-math.md`]({baseDir}/references/amplification-math.md) — EVM gas model, EIP-7825 caps, memory expansion cost, per-precompile gas tables, worked examples (ECADD: 150 gas, 10 kB/gas, 90 GB/block).
- [`references/kurtosis-harness.md`]({baseDir}/references/kurtosis-harness.md) — Three-participant devnet config, hammer-contract skeleton, OOMKilled oracle, `nat_exit_ip` trap, multi-client verification.
- [`references/rationalizations-to-reject.md`]({baseDir}/references/rationalizations-to-reject.md) — Bad defences you'll hear, with counter-evidence for each.
