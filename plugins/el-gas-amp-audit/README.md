# el-gas-amp-audit

An auditor plugin for the **gas → memory-OOM or gas → CPU-DoS amplification**
bug class in Ethereum execution-layer clients (go-ethereum, Nethermind,
Besu). Covers the pattern where an on-chain operation costs O(1) gas but
causes the execution client to allocate or compute something O(N), with
the attacker controlling N within the effective per-transaction
(EIP-7825: 30M) and per-block (45M current mainnet) gas caps.

The canonical instance today is the Nethermind ECADD precompile cache
OOM: the underlying precompile charges 150 gas per call while the cache
wrapper above it retains a full copy of whatever calldata the caller
passed, at zero per-byte cost. Two ordinary mempool transactions
allocate tens of GB of heap in a single consensus-valid block.

This plugin provides:

- A **skill** (`skills/el-gas-amp-audit/`) that encodes the audit
  methodology and points at the client-specific search patterns,
  amplification math, and Kurtosis verification harness.
- A companion **claude-swarm task** (at
  `tasks/el-gas-amp-audit/` in the `claude-swarm` repo) that automates
  the audit across geth / Nethermind / Besu master branches, runs
  `fp-check` on each candidate, and promotes survivors to a Kurtosis
  PoC.

## Pipeline

```
  Client source (master)          Candidate list        Triage
  ────────────────────     ────►  ──────────────   ────►  ─────────
  geth/core, core/vm,                                     fp-check
  nethermind/Nethermind.Evm,                              gate review
  besu/evm, besu/cache                                    │
                                                          ▼
                                                       Kurtosis PoC
                                                       (hammer contract +
                                                        3-node devnet,
                                                        OOMKilled oracle)
```

## How to drive it

- **Manual** — ask Claude to "audit geth for gas-to-memory amplification
  bugs"; the skill will fire, enumerate candidates, compute amplification
  math, invoke `fp-check` on survivors, and assemble a Kurtosis repro.
- **Automated / swarm** — use the companion claude-swarm task under
  `claude-swarm/tasks/el-gas-amp-audit/`, which fans out one auditor
  per client, consolidates findings, and runs `fp-check` + Kurtosis
  before reporting.

## Related skills

- `fp-check` — mandatory pre-PoC gate review. Every candidate goes
  through it.
- `audit-context-building` — used inline for deep reads of cache
  wrapper code where a cursory pattern-match would miss context.
- `dimensional-analysis` — useful for the amplification-ratio
  arithmetic (bytes allocated per gas unit charged).
- `ethereum-bounty-severity` — for final severity assignment on
  confirmed findings.
