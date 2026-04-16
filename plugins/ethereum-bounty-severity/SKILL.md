---
name: ethereum-bounty-severity
description: Use when assigning a severity tier (Critical/High/Medium/Low) to an
  Ethereum execution-layer or consensus-layer client bug report. Encodes the official
  Ethereum bug bounty rubric, weighted by current mainnet client-share data, and
  defines when to defer to "unsure" rather than guess.
---

# Ethereum bounty severity assessment

You are assigning one of `critical | high | medium | low | unsure` to a single
PII-anonymized bug report. You have ONLY the report markdown (title, claimed
targets, attack scenario, reproduction, suggested fix). No source code. No PoC
execution. Your output feeds a human triager who uses your rating to decide
whether to spend hours on this report; over-rating wastes their time, under-rating
buries Criticals.

## Inputs

The report markdown at `reports/<id>.md`. Nothing else. Do not invoke web tools.
Do not assume access to client source.

## Methodology — execute in order

### Step A: Identify claimed target(s)

Which client(s) does the report name? Recognize: `geth | go-ethereum | nethermind |
besu | erigon | reth | lighthouse | prysm | teku | lodestar | grandine | nimbus`.

If the report is about a specification bug, library bug (`py_ecc`, `web3.js`,
etc.), smart contract bug, deposit contract, or tooling bug — STOP. Emit
`agent_severity: "unsure"` with `notes: "out of scope for severity rubric"`.

### Step B: Identify attack vector

One of: `single onchain tx`, `single P2P packet`, `gradual / requires staked
validator`, `state-injected`, `unclear`. Read the Reproduction and Attack Scenario
sections of the report. The vector determines which rubric tier you can reach.

### Step C: Identify damage class

One of: `slash`, `network split`, `network downtime`, `ETH theft from EOAs`,
`ETH burn from EOAs`, `infinite ETH`, `total network crash`. Each damage class
has its own threshold ladder in `references/rubric.md`.

If the damage class is unclear from the PoC, STOP. Emit `agent_severity: "unsure"`
with `notes: "damage class unclear from PoC"`.

### Step D: Weight by client share

Read `references/client-shares.md`. Look up the affected client(s) and form a
qualitative judgement of `% of network` affected. The aggregator computes a
numeric `blast_radius_pct` host-side; you do NOT emit a number. You DO use the
table to pick the rubric tier (e.g. "Lighthouse-only crash" maps to ~53% which
satisfies the High criterion ">33%").

### Step E: Cross-check against rubric

Read `references/rubric.md`. Pick the highest tier whose criterion is met by your
(vector, damage class, %-network) tuple. Tie-break to the more specific criterion.

### Step F: Confidence floor

If ANY of the following hold, downgrade to `unsure` with an explicit reason:
- claimed target is unclear
- damage class is unclear
- attack vector is unclear
- PoC is absent (no Reproduction section, or Reproduction is "see gist" with no
  inline detail)

Better to under-rate confidently than over-rate sloppily. Unsure surfaces in a
separate "needs human glance" section, not buried with Lows.

## Anti-patterns — do NOT

- Do NOT infer severity from report tone. Reporters routinely overstate.
- Do NOT reward verbose Reproduction with higher severity. PoC quality is a
  separate field (`poc_quality`).
- Do NOT trust the reporter's self-assigned severity. It is captured separately
  as `claimed_severity` so the human can compare gaps.
- Do NOT compute percentages. The aggregator does that from the static table.
- Do NOT consult web resources or client source. You only see the report text.

## Calibration

See `references/calibration-examples.md` for one anchored example per tier.

## References

- `references/rubric.md` — the four-tier rubric verbatim.
- `references/client-shares.md` — mainnet share table, dated.
- `references/calibration-examples.md` — one worked example per tier.
