# Mainnet client share — used as the source of % weighting

data_as_of: 2026-04-16
source: migalabs.io (CL), supermajority.info (EL)

Refresh procedure: when material drift is observed (≥5pp on any client),
update both this file AND scripts/aggregate.py's CLIENT_SHARES table.
Same numbers; mechanically duplicated for v1.

## Consensus Layer
  lighthouse  52.97%   (majority — single-bug crash trips >50% threshold)
  prysm       24.61%
  teku        11.24%
  erigon       5.49%
  lodestar     3.37%
  grandine     1.75%
  nimbus       0.12%

## Execution Layer
  geth        41%      (assumed-largest; uncovered network share treated as geth)
  nethermind  38%
  besu        16%
  erigon       3%
  reth         2%

## Tier-mapping shortcuts (qualitative, for the Skill consumer)
- Single client at >50% share = Critical-eligible if crash via single tx/packet.
- Two-client co-bug at combined >33% = High-eligible.
- Single-client at 5-33% = Medium-ceiling for crash class.
- Single-client at <5% = Low-ceiling for crash class.
- Slash thresholds (0.01% / 1% / 33% / 50%) are validator percentages, not client
  percentages. A bug that slashes a single client's validators inherits that
  client's CL share approximately.
