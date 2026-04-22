# Rationalizations to reject

When auditing this bug class, pattern-match on people saying any of
the below — including yourself. Each one is a claim that needs
evidence, not acceptance at face value.

## "The cache clears at end of block, so it's bounded."

**Counter.** The cache clearing runs *after* block processing
finishes. Allocation happens *during* block processing. The question
is: at the peak of allocation (some point mid-block), is the resource
ceiling hit? If yes, the end-of-block clear never gets to run because
the process dies first.

**Evidence to demand.** A measured RSS trajectory across block
processing. If peak > 80 % of victim host RAM for any realistic
mainnet host spec (32–64 GB RAM), the clear is too late.

## "Gas limits it — the attacker can't afford that much."

**Counter.** Compute `bytes_per_gas` or `us_per_gas` and multiply by
the attacker's budget (30 M per tx, 45 M per block, EIP-7825). If the
product exceeds the victim's realistic headroom, the gas limit does
not bound it. ECADD's 3000 bytes/gas × 45 M = ~135 GB of allocation
requests per block. Gas buys the attacker everything they need.

**Evidence to demand.** The amplification math, explicitly. If the
defender can't produce numbers, they haven't done the audit.

## "It only happens when precompile caching is enabled, and tests don't enable it."

**Counter.** This is actually strong evidence *against* the
defender: the bug is reachable in production and invisible in tests.
That's a coverage-gap finding on top of the amplification finding.
The `fp-check` and Kurtosis steps must be run against the production
configuration, not the test default.

**Evidence to demand.** The DI wiring / feature flag that controls
the wrapper, and the default value for mainnet vs. test runners.
Call out when stock fuzz binaries disable the feature (Nethermind's
`nethtest` is the concrete case — `BlockchainTestBase.cs:133-134`
and `GeneralTestBase.cs` default `ConfigProvider` leave
`PreWarmStateOnBlockProcessing = false`, so the wrapper is never
installed in state-test fuzzing).

## "State-test or benchmark fuzzing didn't find it, so it's not real."

**Counter.** State-test runners bypass block processing — they call
the transaction processor directly. Any amplification that lives in
the block-level wrapper (cache, prewarmer, state prefetcher) is
invisible to that path. See the ECADD case: Holiman's ModExp fuzz
target found bugs in `ModExpPrecompile.DataGasCostInternal` because
that method is on every state-test execution path, but the ECADD
cache-wrapper bug lives a layer up and no state-test fuzzer reaches
it today.

**Evidence to demand.** Did the fuzz target run with the production
DI configuration, specifically with the block-level caches installed?
If not, the absence of findings is meaningless.

## "The attacker can't get the block included."

**Counter.** The attacker doesn't need to be the proposer. Any two
ordinary EIP-1559 transactions paying priority fees will be included
by any honest mainnet proposer (geth, reth, besu, erigon) whose
vanilla builder picks up profitable txs from the public mempool.
Nethermind is ~25 % of validator stake; the next non-Nethermind slot
is ~4 s away on average. The 75 % of proposers who run non-victim
clients will cheerfully produce the attack block.

**Evidence to demand.** Name a specific tx-pool filter or builder
heuristic that would reject the hammer txs. If the txs look normal
(small calldata, standard EIP-1559, paying priority fee), no
filter triggers.

## "mev-boost / private orderflow prevents this."

**Counter.** mev-boost is proposer-side. The attacker doesn't need
their tx routed via mev-boost — they broadcast to the public mempool
and rely on any honest proposer. Even if mev-boost is 100 %
penetrated, a single local-builder proposer eventually wins a slot
and includes the tx. And in fact a malicious builder on mev-boost is
a strictly worse case: they can craft the block deterministically
and win specific slots.

**Evidence to demand.** "mev-boost prevents X" is never an adequate
defence without a measurement of mev-boost penetration AND an
argument that the attack needs the tx to propagate through exactly
one channel.

## "The OOM isn't deterministic — depends on host RAM."

**Counter.** The amplification *is* deterministic — same input, same
bytes-per-gas ratio, same number of cache entries on every run.
Whether a specific host has enough RAM to absorb it is
host-dependent, but a sufficiently-padded mainnet node goes down,
and a smaller node goes down faster. The amplification oracle in
`PrecompileCacheAmp` or your harness should be
`bytes_per_entry > SemanticInputLength`, not `RSS > cgroup_limit`.

**Evidence to demand.** A measured `bytes_per_cache_entry` vs. the
effective semantic-input size that would suffice to compute the
primitive's result. If the ratio is > 10×, it's a finding regardless
of RAM.

## "I can't reproduce it on my machine."

**Counter.** Check:

1. `PreWarmStateOnBlockProcessing` (or equivalent feature flag) is
   true.
2. The attack block was actually built by the proposer, not by the
   victim's own CL (check `extraData`).
3. CL peering is working (each node has ≥ 1 peer; see
   `kurtosis-devnet` skill's peering-debug reference; the
   `nat_exit_ip` trap is the most common cause of 0 peers).
4. The attack block was *imported*, not produced — look at the
   victim's docker logs for `Received New Block: … Extra Data:
   <proposer-ID>`.

If all four are true and the victim still doesn't OOM, the
allocation may genuinely be bounded somewhere you missed — send it
back through `fp-check` with the new evidence.

## "The fix is just to set SupportsCaching=false on this precompile."

**Counter.** That fixes one instance, not the class. The class
exists because the default is `SupportsCaching=true` (see
`IPrecompile.cs:14` in Nethermind) and because the cache keys on the
full input. Any future precompile introduced in a new fork inherits
the same vulnerability. Report the class, not the instance; insist on
a structural fix.

**Structural fixes that close the class:**

- Key the cache on `input[..EffectiveInputLength]` instead of on the
  full input. The precompile already knows how many bytes it reads;
  expose that as an `EffectiveInputLength(input)` method and use it
  for the cache key.
- Bound the cache by bytes, not by count. An LRU-by-byte-footprint
  eviction under a per-block cap rejects amplification by
  construction.
- Invert the default — `SupportsCaching=false` unless a precompile
  explicitly opts in with proof of idempotent-cacheable inputs.

Argue for one of these in the finding's "recommended fix" section.
Do not accept "we set the flag to false on this one" as a resolution.

## "But the code has been like this for years without being exploited."

**Counter.** Pre-EIP-7825 (Osaka), the per-tx gas cap was whatever a
miner would include (often tighter than 30 M). The attack surface
expanded when the per-tx cap was raised to 30 M. Some amplification
bugs that weren't exploitable at 10 M gas become exploitable at 30 M.
"No one's exploited it yet" is not evidence it's safe; the
cost-benefit changed recently.

**Evidence to demand.** Compute the amplification ratio against the
current mainnet EIP-7825 cap, not the historical one. If it's above
threshold now, the bug is now.
