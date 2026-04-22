# Candidate enumeration — per-client search patterns

**The bug class is not precompile-exclusive.** Any code path the EVM
nudges — opcode handlers, memory/bytes copies, state snapshots,
journals, tx-pool bookkeeping, access-list materialisation, mempool
indexes, CL↔EL payload buffers — can be the site of an amplification
bug. Precompile caches are the first publicly-known instance, not
the shape of the whole class. Audit all six categories below for
every client.

Work against the latest master/main of each client. Fresh clone or
`git pull && git log -1` before starting; amplification code shifts
around often, especially after fork-activation refactors.

| Client | Repo | Default branch | Notable recent surface |
|---|---|---|---|
| go-ethereum | `https://github.com/ethereum/go-ethereum` | `master` | `core/vm/contracts.go`, `core/vm/interpreter.go`, `core/state/statedb.go`, `core/txpool/` |
| Nethermind | `https://github.com/NethermindEth/nethermind` | `master` | `src/Nethermind/Nethermind.Evm.Precompiles/`, `src/Nethermind/Nethermind.Blockchain/PrecompileCached*`, `src/Nethermind/Nethermind.Evm/State/PreBlockCaches.cs` |
| Besu | `https://github.com/hyperledger/besu` | `main` | `evm/src/main/java/org/hyperledger/besu/evm/precompile/`, `evm/src/main/java/org/hyperledger/besu/evm/operation/`, `ethereum/core/src/main/java/org/hyperledger/besu/ethereum/vm/` |

## Category 1 — Precompile cache wrappers

The ECADD-OOM class. Look for any wrapper around `IPrecompile` /
`PrecompiledContract` that memoises results in a `map` / `ConcurrentDictionary` /
`LoadingCache` keyed by the full input.

**Nethermind — the known instance:**

```
src/Nethermind/Nethermind.Blockchain/PrecompileCachedCodeInfoRepository.cs
src/Nethermind/Nethermind.Evm/State/PreBlockCaches.cs  (PrecompileCacheKey)
src/Nethermind/Nethermind.Init/Modules/PrewarmerModule.cs  (DI wiring)
```

Grep signals:
- `ConcurrentDictionary<.*PrecompileCacheKey.*>`
- `inputData.ToArray()` inside a `Run(ReadOnlyMemory<byte>, IReleaseSpec)` path
- `SupportsCaching` on `IPrecompile` (default `true` at `Nethermind.Evm/Precompiles/IPrecompile.cs`)

**Geth — not currently cached (verify on master before concluding):**

```
rg -n "precompile|Precompiled" go-ethereum/core/vm/contracts.go
rg -n "cache|Cache|memoize|memoise" go-ethereum/core/vm/contracts.go
```

`RunPrecompiledContract` in `core/vm/contracts.go` executes the primitive
directly without a per-block cache. If a cache is introduced in a new
PR (e.g. for KZG point-evaluation performance), re-run the audit.

**Besu — check for `PrecompiledContract` wrappers:**

```
rg -n "precompile" besu/evm/src/main/java/org/hyperledger/besu/evm/precompile/
rg -n "Caffeine|LoadingCache|ConcurrentHashMap" besu/evm/src/main/java/
```

Besu historically caches modexp results
(`ModExpPrecompiledContract` bookkeeping); check whether the cache
key includes padding bytes.

## Category 2 — Opcode handlers that copy or retain input

The handler for CALL/STATICCALL/DELEGATECALL, RETURNDATACOPY,
EXTCODECOPY, MCOPY (EIP-5656), CREATE/CREATE2/EOFCREATE, or
TLOAD/TSTORE that copies memory into a longer-lived buffer without
per-byte gas accounting.

**Geth:**

```
rg -n "^func (call|staticCall|delegateCall|callCode|create)" go-ethereum/core/vm/evm.go
rg -n "Memory\.Set|memory\.Set|makeMemCpy" go-ethereum/core/vm/
```

The `Memory.Set` path is bounded by memory-expansion gas; read
`core/vm/memory.go` and verify the copy uses `in`-place bytes, not a
cloned slice retained in `ScopeContext`.

**Nethermind:**

```
rg -n "ReadOnlyMemory<byte>.*Memory|inputBytes\.Length|input\.CopyTo" src/Nethermind/Nethermind.Evm/
```

Check `VirtualMachine.cs` CALL-family dispatch and
`EvmPooledMemory.cs` rental/return. The rented `byte[]` is returned
to `SafeArrayPool`; anything that retains a reference past frame
dispose is a candidate.

**Besu:**

```
rg -n "class .*Operation" besu/evm/src/main/java/org/hyperledger/besu/evm/operation/
```

Inspect `CallOperation.java`, `ReturnDataCopyOperation.java`,
`MCopyOperation.java`. Besu uses `Bytes` objects with reference
semantics — a retained `Bytes` view holds the underlying `byte[]`
alive.

## Category 3 — Block-level caches

Any cache that lives for the duration of block processing and is
cleared at the block boundary. These are the sweet spot for
amplification because allocations accumulate until the block
finishes, and finishes may never come if the kernel reaps first.

**Nethermind:**

```
grep -rn "class PreBlockCaches\|PerBlockCache\|_precompileCache\|_storageCache\|_stateCache\|_rlpCache" src/Nethermind/
```

`PreBlockCaches` in `src/Nethermind/Nethermind.Evm/State/` contains
four caches (storage, state, RLP, precompile). Audit each for the
same key-on-full-input anti-pattern.

**Geth:**

```
rg -n "journal|dirty|objectsPending|accessList" go-ethereum/core/state/
rg -n "type.*Cache" go-ethereum/core/vm/
```

`core/state/journal.go` journals state changes per transaction; if
the journal retains full-input buffers keyed by insertion order, it's
a candidate.

**Besu:**

```
rg -n "TransactionGasBudget|class .*Worldview\|protocolSpec\|worldUpdater" besu/ethereum/core/src/main/java/
```

Besu has a per-block `MutableWorldState` with a snapshot stack; check
whether the stack retains copies of full storage slots (or just
differences).

## Category 4 — State retention surfaces

Long-lived maps the attacker can grow. None of these are precompiles
— they're bookkeeping structures the EVM touches during ordinary
tx execution.

- **Tx-pool retention**: does the mempool keep a full copy of the
  tx's calldata after inclusion (until canonical finalisation)? A
  pending tx can be replaced with rising nonce+fee; each replacement
  may retain the old version in a cache for reorg tolerance.
  - Geth: `core/txpool/legacypool/legacypool.go`, `BlobPool` storage.
  - Nethermind: `src/Nethermind/Nethermind.TxPool/`, `Blob/BlobTxStorage.cs`.
  - Besu: `ethereum/eth/src/main/java/org/hyperledger/besu/ethereum/eth/transactions/`.
- **Journal / snapshot stacks** (state reversion bookkeeping): every
  state-modifying opcode pushes to a journal so `REVERT` can unwind.
  If the journal stores full-input deltas rather than diffs, a tight
  loop of TSTORE/SSTORE with attacker-controlled slot values can
  inflate it. Worth auditing post-EIP-1153 (transient storage) and
  under delegation cascades (EIP-7702).
  - Geth: `core/state/journal.go`.
  - Nethermind: `src/Nethermind/Nethermind.State/WorldState.cs` and
    journal stack.
  - Besu: `ethereum/core/src/main/java/.../MutableWorldState.java`.
- **SELFDESTRUCT graveyard**: EIP-6780 restricts SELFDESTRUCT
  post-Cancun, but the bookkeeping around "suicides queued this tx"
  may still allocate per-call.
- **Access-list materialisation** (EIP-2930, EIP-7702): do the
  access lists get copied into a persistent per-block structure?
  Long EIP-7702 delegation chains are attacker-controlled and cheap
  per step.
- **Receipt / log bookkeeping**: LOG0…LOG4 opcodes are gas-metered
  per-byte of topic+data, but the final receipts trie builder may
  re-copy the full log set. Check whether the builder retains
  references or deep-copies.

## Category 5 — CPU-bound primitives

These are gas-priced to be O(N) in CPU, so exploits require finding a
cost-function bug where the gas formula misrepresents the actual work:

- ModExp gas formula vs actual wall-clock on pathological moduli.
- BN254/BLS12-381 pairing cost per pair vs actual miller-loop cost.
- KZG point-evaluation with inputs that trip slow paths in the
  underlying BLS library.

Check each client's gas formula against the primitive's actual
execution time on adversarial inputs. A differential between
geth/Nethermind/Besu on the same input is often the signal.

## Category 6 — New and recently merged code

Diff the client since its last stable release. Any newly-introduced
precompile, cache, or state structure gets the Category 1–5 checks
applied fresh.

```
git log --oneline v<last-release>..HEAD -- core/vm/ core/state/
```

## Output format per candidate

Produce a YAML-ish record:

```yaml
id: CAND-<client>-<short-desc>
client: geth | nethermind | besu
branch: master | main
commit: <short SHA>
site:
  file: <relative path>
  line: <number>
category: 1 | 2 | 3 | 4 | 5 | 6
op: <opcode mnemonic or precompile address>
attacker_input: <bytes / iteration count / moduli choice>
client_alloc: <bytes per call> | <CPU us per call>
gas_per_call: <flat | formula>
bytes_per_gas: <computed>
calls_per_30M_tx: <computed>
total_resource_per_block: <computed>
flag: <PASS | FAIL Step 2 threshold>
next: fp-check | drop
```

Feed `PASS` candidates to the `fp-check` skill with the math
embedded, then the Kurtosis harness.
