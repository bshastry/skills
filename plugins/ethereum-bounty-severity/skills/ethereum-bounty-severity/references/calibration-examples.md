# Calibration examples — one per tier

These are synthetic anchors. Use them to calibrate when a real report sits
near a tier boundary.

## Critical example

**Report excerpt:** "A malformed RLP transaction causes geth, nethermind, besu,
reth, and erigon to dereference a null pointer in the receipt-trie commit path.
PoC: send the attached transaction; all five EL clients crash within one block."

- **Damage class:** total network crash
- **Attack vector:** single onchain transaction
- **Matched criterion:** "Take down the entire network by sending a single
  malicious onchain transaction that ends up crashing all clients"
- **Assigned tier:** critical
- **Justification:** All EL clients crash on the same single tx → satisfies
  the "all clients" Critical criterion verbatim.

## High example

**Report excerpt:** "Lighthouse panics on slot N when processing a crafted
attestation aggregate. Reproduction: kurtosis enclave with one Lighthouse
beacon node, send the attached SSZ blob via gossipsub. Beacon node terminates."

- **Damage class:** network downtime
- **Attack vector:** single P2P packet
- **Matched criterion:** "Be able to bring down >33% of the network by sending
  a single network packet" (Lighthouse share 53%)
- **Assigned tier:** high
- **Justification:** Single-packet crash on Lighthouse-only path; Lighthouse
  share 53% > 33% threshold.

## Medium example

**Report excerpt:** "Geth state divergence on EIP-XXXX path. Sending a tx with
a malformed access list causes geth to compute a different state root than
nethermind/besu, splitting the network."

- **Damage class:** network split
- **Attack vector:** single onchain tx
- **Matched criterion:** "Trivially cause network splits affecting >5% of the
  network" (geth 41% splits off)
- **Assigned tier:** medium
- **Justification:** Geth-only divergence triggers a 41%/59% split. Below
  33% threshold (which would require >33% of the network to split off in a
  *new* direction; here 41% is on the minority chain). Medium fits the >5%
  criterion.

## Low example

**Report excerpt:** "Nimbus crashes on receipt of a truncated ENR record over
discv5. Reproduction: send the attached udp packet to the node's discv5 port."

- **Damage class:** network downtime
- **Attack vector:** single P2P packet
- **Matched criterion:** "Be able to bring down >0.01% of the network by
  sending a single network packet" (nimbus 0.12% > 0.01% but well below 5%)
- **Assigned tier:** low
- **Justification:** Single-packet crash on nimbus-only path; nimbus share
  0.12% — clears Low's 0.01% threshold but not Medium's 5%.

## Unsure example (for calibration of when to refuse)

**Report excerpt:** "Prysm has a bug in attestation handling. See attached
gist for PoC."

- **Damage class:** unclear (no specifics)
- **Attack vector:** unclear
- **PoC:** absent (gist link, no inline reproduction)
- **Assigned tier:** unsure
- **Justification:** Cannot identify damage class or attack vector from the
  report text. PoC requires fetching an external gist, which is out of scope.
