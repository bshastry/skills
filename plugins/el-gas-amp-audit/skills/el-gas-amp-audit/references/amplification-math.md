# Amplification math

Every candidate gets turned into a single ratio number plus a
block-level total. This reference gives you the constants and the
worked examples.

## Caps on the attacker

| Cap | Value | Source |
|---|---|---|
| Per-tx gas | 30,000,000 | EIP-7825 (active Osaka mainnet) |
| Per-block gas | 45,000,000 | Current mainnet limit (see `eth_gasLimit` on a recent block) |
| Intrinsic tx cost | 21,000 + (4·zero_bytes) + (16·nonzero_bytes) of calldata | Yellow Paper + EIP-2028 |
| EVM memory expansion (per frame) | `3·w + w²/512` gas for `w` words | Yellow Paper |
| STATICCALL base | 100 (warm) / 2600 (cold) | EIP-2929 |
| Per-byte input cost for precompiles | precompile-specific `DataGasCost`; may be 0 | per client's `IPrecompile`/`PrecompiledContract` |

**Important:** tx calldata pays per-byte; EVM memory contents do
NOT. If the amplification vector is "contract memory gets copied",
the attacker pays the memory-expansion cost *once* and then reuses
the region at no per-byte cost. If it's "tx calldata gets copied",
the 16 gas/byte tax usually kills the attack.

## Budgets an attacker actually has

In a single 30 M-gas tx, after:

- ~21 K intrinsic
- ~5.6 M to expand EVM memory to 1.5 MB
  (52,976 words: `3·52976 + 52976²/512 = 158,928 + 5,481,360 = 5,640,288`)

the attacker has **~24 M gas** remaining to loop inside the expanded
memory region. At 300 gas per loop iteration (a typical
STATICCALL+ECADD+loop body), that's **~80,000 iterations per tx**.
Two txs per block ≈ **160,000 calls per block**, all hitting the same
1.5 MB region with a mutating suffix.

## Per-precompile gas table (mainnet post-Prague)

| Precompile | Address | BaseGasCost | DataGasCost | Tail-reading? |
|---|---|---|---|---|
| ECRecover | 0x01 | 3000 | 0 | Reads first 128 B only |
| SHA256 | 0x02 | 60 | 12 · `word_count` | **Reads all** (per-byte tax) |
| RIPEMD160 | 0x03 | 600 | 120 · `word_count` | **Reads all** (per-byte tax) |
| Identity | 0x04 | 15 | 3 · `word_count` | **Reads all** (per-byte tax; Nethermind additionally opts out via `SupportsCaching=false`) |
| ModExp | 0x05 | min 200; `max(1, modulus_bytes/8)² · max(exp_len, 1) / 20` after EIP-2565 | 0 | Reads header-implied |
| BN254Add | 0x06 | 150 (EIP-1108) | 0 | **Reads first 128 B only** ← amplifier |
| BN254Mul | 0x07 | 6000 (EIP-1108) | 0 | **Reads first 96 B only** ← amplifier |
| BN254Pairing | 0x08 | 45000 | 34000 · pair_count | Rejects non-192-multiple length |
| Blake2F | 0x09 | 0 | `rounds` (from input) | Fixed 213-byte input |
| KZG Point Eval | 0x0A | 50000 | 0 | Fixed 192-byte input |
| BLS12-381 family | 0x0B–0x11 | fixed/per-pair | mostly 0 | Length-rejected |
| P256 (SECP256r1) | 0x100 | 3450 | 0 | Fixed 160-byte input |

Source for the Nethermind numbers:
`nethermind/src/Nethermind/Nethermind.Evm.Precompiles/*.cs` (each
implements `BaseGasCost` and `DataGasCost`). Geth and Besu have
equivalent files under `core/vm/contracts.go` and
`evm/src/main/java/.../precompile/`.

## The three ratios you compute

For each candidate:

1. **`bytes_per_gas`** =
   `alloc_bytes_per_call / gas_per_call`.

   Memory-amplification threshold: **≥ 100 bytes/gas is concerning;
   ≥ 1000 bytes/gas is a confirmed amplifier.**

2. **`calls_per_block`** =
   `45_000_000 / gas_per_call` (crude upper bound).

   Refined: `(45_000_000 − 2·intrinsic − 2·memexp) / gas_per_call`.

3. **`total_alloc_per_block`** =
   `bytes_per_gas × (gas_per_block − fixed_overheads)`.

   DoS threshold: **≥ 10 GB per block crashes a host with 32 GB
   RAM running Nethermind + Teku + OS + peers. ≥ 40 GB crashes
   a generous host. Two ordinary txs producing ≥ 40 GB of
   amplification is a critical finding.**

## CPU-DoS math

Same template, replace bytes with CPU time:

1. **`us_per_gas`** = `wall_clock_us_per_call / gas_per_call`.

   CPU threshold: **≥ 100 μs/gas.** At 30 M gas/tx that's 3 s of
   single-thread CPU per tx, which alone is over a mainnet slot
   budget.

2. **`total_wallclock_per_block`** ≥ 12 s is a full-slot DoS.

Measurement: write a microbenchmark that invokes the primitive with
the worst-case attacker input N times, subtract constant-time overhead,
divide by N, divide by the client's gas formula for that input. Do this
differentially — if geth's `us_per_gas` is 10 and Nethermind's is 400
for the same input, the gas formula is wrong on Nethermind.

## Worked example: ECADD precompile-cache OOM

Given:

- `BaseGasCost = 150`, `DataGasCost = 0`.
- `CachedPrecompile.Run` on miss calls `inputData.ToArray()` —
  allocates one `byte[]` of size `input.Length`.
- Attacker supplies `input.Length = 1,695,232`.

Compute:

- `gas_per_call = 150 + staticcall_overhead(100) + loop_body(~40)
  ≈ 290` (observed: ~515 gas/iter in the real PoC; difference is
  intrinsic amortisation and outer MSTOREs).
- `bytes_per_gas = 1,695,232 / 515 ≈ 3,292` bytes/gas. **Flag: well
  above the 1000 bytes/gas threshold.**
- `calls_per_30M_tx ≈ (30,000,000 − 21,000 − 5,640,288) / 515
  ≈ 47,260` calls (real PoC uses 32,598; conservative).
- `total_alloc_per_tx = 1,695,232 × 32,598 ≈ 55 GB`.
- Two txs per block → **~93 GB per block**.

This trivially exceeds any realistic host's RAM. Confirmed by the
Kurtosis repro: RSS climbs 500 MB → 20 GB in 6 seconds → OOMKilled.

## Worked example: hypothetical safe case (SHA-256 hammer)

Given:

- `BaseGasCost = 60`, `DataGasCost = 12 · word_count`.
- Attacker supplies 1,695,232-byte input = 52,976 words.

Compute:

- `gas_per_call = 60 + 12·52976 = 635,772`.
- `bytes_per_gas = 1,695,232 / 635,772 ≈ 2.7` bytes/gas. **Below
  100 bytes/gas threshold — not an amplifier.**

The per-byte tax makes suffix amplification economically unviable.

## What to write in a finding

Every candidate that passes the thresholds gets a block like this
in the finding record, verbatim:

```
Gas per call:      <N> gas
Alloc per call:    <B> bytes
bytes_per_gas:     <B/N>
Calls per 30M tx:  <K>
Alloc per 30M tx:  <B·K> bytes = <human-readable>
Block total (2×):  <2·B·K> bytes = <human-readable>
Threshold:         bytes_per_gas >= 100 (flag), >= 1000 (confirm)
Verdict:           <PASS|FAIL> Step 2 filter
```

Then hand the whole record to `fp-check` and let it challenge each
number.
