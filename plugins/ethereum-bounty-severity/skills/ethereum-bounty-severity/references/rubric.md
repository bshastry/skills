# Ethereum bug bounty severity rubric

Source: ethereum.org/bug-bounty (program rules). Pin date: 2026-04-16.

Severity is assessed based on each discovered vulnerability's unique ability to do
the following:

## Low severity
- Slash >0.01% of validators
- Trivially cause network splits affecting >0.01% of the network
- Be able to bring down >0.01% of the network by sending a single network packet
  or an onchain transaction

## Medium severity
- Slash >1% of validators
- Trivially cause network splits affecting >5% of the network
- Be able to bring down >5% of the network by sending a single network packet or
  an onchain transaction

## High severity
- Slash >33% of validators
- Trivially cause network splits affecting >33% of the network
- Be able to bring down >33% of the network by sending a single onchain transaction

## Critical severity
- Slash >50% of validators
- Exploit an EIP/specification or client bug to easily create an infinite amount of
  ETH which is finalized by the network
- Steal ETH from all EOAs
- Burn ETH from all EOAs
- Take down the entire network by sending a single malicious onchain transaction
  that ends up crashing all clients
