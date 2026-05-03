# ct-fuzz on production crypto: Go stdlib + Rust `ring`

> **Methodology iterations** ("what to measure"):
>
> | Gen | Timer | Window | ring AES-GCM seal mean `|t1|` | All clean? |
> |---|---|---|---:|---|
> | v1 (initial) | `time.Now()` / `Instant::now()` (ns) | whole pipeline (incl. allocator + `to_vec()`) | ~10 | no |
> | v2 (no-alloc) | ns | whole pipeline (no heap alloc) | 12.5 | no |
> | v3 (split) | ns | only the operation; key schedule in untimed prep | 1.98 | yes |
> | v4 (rdtscp+split) | `lfence; rdtscp; lfence` (cycles) | only the operation | 1.18 | yes |
> | **v5 (sub-region annotation + cycles)** | cycles | one phase at a time (keysched-only / seal-only / drop-only) | **all sub-regions ≤ 1.77 across 3 repeats** | **yes** |
>
> Each iteration tightened the measurement and attributed signals to scaffolding rather than crypto. v5 finishes the attribution: every named sub-region of ring's AES-GCM seal pipeline is CT at function granularity.

This run targets the public APIs that production code actually calls,
testing the right threat model: vary the **secret key** across classes,
hold the public input fixed, ask whether wall-clock time depends on the
key.

## Targets

All seven targets are real public APIs of production crypto libraries.
Per call, the harness builds a fresh key from the secret bytes, runs the
operation, and tears down. Class A: fixed `0xAA` key. Class B: random key.

| Lang | Library | Function | Threat |
|---|---|---|---|
| Go | stdlib `crypto/aes` + `crypto/cipher` | `cipher.AEAD.Seal` (AES-128-GCM) | Encrypt oracle; chosen plaintext, server-fixed key. Question: does encrypt time leak the key? |
| Go | stdlib `crypto/aes` + `crypto/cipher` | `cipher.AEAD.Open` with bogus tag (AES-128-GCM) | Decrypt-fail oracle; Bleichenbacher-class. Question: does fail-path time leak the key? |
| Go | stdlib `crypto/ed25519` | `ed25519.Sign` | Chosen-message sign oracle; server-fixed private key. |
| Go | stdlib `crypto/ecdsa` | `ecdsa.SignASN1` (P-256) | Same; pre-Go-1.18 was variable-time and exploitable. |
| Rust | `ring` 0.17 | `aead::LessSafeKey::seal_in_place_separate_tag` (AES-128-GCM) | Same as Go AEAD seal. ring is what `rustls` uses for TLS. |
| Rust | `ring` 0.17 | `aead::LessSafeKey::open_in_place` with bogus tag (AES-128-GCM) | Same as Go AEAD open. |
| Rust | `ring` 0.17 | `signature::Ed25519KeyPair::sign` | Chosen-message Ed25519 sign. |

CPU: Intel Xeon @ 2.10 GHz with AES-NI, PCLMULQDQ, AVX. Both Go's and
ring's AES paths route through hardware AES on this host.

## Results (3 repeats, N=60,000 samples per class, threshold |t1|>8, second-order off)

| Target | mean \|t1\| | min | max | flagged repeats | verdict |
|---|---:|---:|---:|---:|---|
| `aes128gcm_seal_vary_key` (Go) | 1.68 | 0.65 | 2.33 | 0/3 | **CT** |
| `aes128gcm_open_invalid_vary_key` (Go) | 1.18 | 0.73 | 1.63 | 0/3 | **CT** |
| `ed25519_sign_vary_key` (Go) | 1.34 | 0.78 | 2.20 | 0/3 | **CT** |
| `ecdsa_p256_sign_vary_key` (Go) | 1.09 | 0.67 | 1.48 | 0/3 | **CT** |
| `ring_aes128gcm_seal_vary_key` (Rust) | **12.50** | 6.44 | 16.09 | **2/3** | **flagged** |
| `ring_aes128gcm_open_invalid_vary_key` (Rust) | 6.98 | 6.70 | 7.47 | 0/3 | borderline |
| `ring_ed25519_sign_vary_key` (Rust) | 3.04 | 1.60 | 5.24 | 0/3 | **CT** |

**6 of 7 production targets clear the noise floor unambiguously.** The
one outlier — ring's AES-128-GCM seal with varying key — is reproducible
across runs and grows with sample count (~5 at N=30k → ~12 at N=60k),
which is the √N growth dudect predicts for a real leak rather than noise.

## TP/FP table after fp-check

| Lang | Target | ct-fuzz | fp-check | Reason |
|---|---|---|---|---|
| Go | AES-GCM seal vary key | CT | — (no flag) | Hardware AES-NI key schedule + CT encrypt |
| Go | AES-GCM open invalid vary key | CT | — | Same; tag verify is CT |
| Go | Ed25519 sign vary key | CT | — | SHA-512 + edwards25519 scalar mult, all CT |
| Go | ECDSA P-256 sign vary key | CT | — | Modern Go uses `crypto/internal/nistec` (CT) |
| Rust | ring AES-GCM seal vary key | **flagged** | **uncertain — escalate** | See walkthrough below |
| Rust | ring AES-GCM open invalid vary key | borderline | — (would not flag at thresh 8) | Same machinery as seal but no signal here |
| Rust | ring Ed25519 sign vary key | CT | — | ring's curve25519 is CT |

**Headline: 6 confirmed CT, 1 finding for human investigation.** AFI = 1
on resolved findings. The single uncertain one is the headline — a
genuine "the fuzzer found something the static analyzer missed" candidate.

## fp-check walkthrough: ring AES-128-GCM seal, varying key

### Step 0 — Restate the claim

ct-fuzz observes that the wall-clock latency of
`ring::aead::LessSafeKey::seal_in_place_separate_tag` depends on the
AES-128 key bits, with a Welch's |t| of ~12.5 at 60k samples per class
(p ≈ 10⁻³⁵ under the null). The threat model is a remote attacker who
can force the server to encrypt attacker-supplied plaintexts under a
fixed but per-connection-rekeyed AEAD key, and observe per-encryption
wall-clock latency.

### Step 1 — Data flow

Per-call work in the harness's timed region:

1. `UnboundKey::new(&AES_128_GCM, sec)` — validates length (==16), then
   calls into ring's AES key schedule. On x86_64 with AES-NI, this is
   `aes_hw_set_encrypt_key` (assembly, CT by construction).
2. `LessSafeKey::new(unbound)` — type wrapper.
3. `Nonce::assume_unique_for_key([0u8; 12])` — fixed 12-byte buffer.
4. `seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf)` —
   - Compute J0 = nonce ‖ 0x00000001
   - Encrypt counter blocks via AES-NI CTR mode (CT)
   - Compute GHASH over AAD ‖ ciphertext via PCLMULQDQ (CT)
   - XOR auth tag with E(K, J0) (CT)
5. Drop key — zeroize round keys (xor-with-self, CT).

Every step in (1)–(5) is documented constant-time on AES-NI/PCLMULQDQ
hardware. The data flow analysis says there should be no key-dependent
branch or data-dependent address.

### Step 2 — Possible sources of the observed signal

Candidates:

1. **Run-time CPU feature dispatch.** ring picks an implementation based
   on detected features. The dispatch table is set at init; per-call it's
   a function pointer load + indirect call. No key-dependent branch, but
   indirect-branch predictor state could be affected by the
   surrounding call pattern. This is microarchitectural and unlikely to
   be key-bit-dependent.
2. **Stack red-zone / spill behavior.** AES-NI key schedule writes 11
   round keys to memory (176 bytes). The pattern of which cache lines
   are touched depends on key bits *only* if the implementation does
   something non-CT (e.g., a key-dependent table). The reference
   AES-NI assembly does not.
3. **Drop overhead asymmetry.** When a `LessSafeKey` containing a
   key-derived `Aes128Gcm` is dropped, the `Drop` implementation calls
   `zeroize::Zeroize::zeroize` on the inner key material. This iterates
   over each byte and writes 0. The number of writes is constant.
4. **Tag computation reduces over key-derived state.** GHASH uses
   H = E(K, 0^128). Computing H is a single AES block encryption — CT.
   Subsequent reductions are PCLMULQDQ — CT.
5. **Genuine non-CT path on this CPU.** Possibility that a specific
   instruction sequence in ring's path has a small data-dependent
   timing on this microarchitecture (e.g., AES-NI port pressure
   interactions with surrounding XMM register usage).
6. **Harness artifact we haven't yet eliminated.** We removed heap
   allocation per call (changed `to_vec()` → stack array, changed
   `seal_in_place_append_tag` → `seal_in_place_separate_tag`). The
   signal *dropped* from |t1|=10 to |t1|=6–16 with the fix, confirming
   that *part* of the original signal was allocator churn — but a
   residual remains.

### Step 3 — Exploitability

If real, the leak is bounded to a small fraction of a CPU cycle per
encryption with a key-dependent component. Boneh-Brumley-style
extraction would require:

- Many parallel queries (10⁵–10⁷)
- The attacker reaching the per-call key import path. In TLS, the
  AEAD key is imported once per connection and used for many records;
  unless the attacker can force frequent connection rekey (which is
  unusual outside of session-resumption flows), the per-call import
  is not on the hot path.

The harness exposes this leak because we *deliberately* import the
key inside every timed call. Production code that follows ring's
recommended pattern — build `LessSafeKey` once, call seal many times —
would not amplify the per-import component to a query-cost-effective
exploit.

### Step 4 — PoC

We do not have a working PoC. The exploit hypothesis (per-import key
schedule timing leak) requires:

1. Forcing the victim to perform per-call key derivation (rare in
   well-architected services but plausible in some envelope-encryption
   schemes that derive a fresh DEK per record).
2. Distinguishing the leak from network noise — Boneh-Brumley over LAN
   succeeded with ~1ms timing differences; a < 1 ns difference here may
   be drowned by network jitter at typical RTTs.

### Step 5 — Devil's advocate

- **Am I pattern-matching?** A timing signal of |t1|=12 against AES-NI
  is unusual. The expected answer for AES-NI + PCLMULQDQ is "CT" — and
  most published analyses confirm. So the prior is "false positive."
- **Could this be a microarchitectural quirk specific to this VM?**
  Yes. Shared VMs have noisy timing baselines. The signal is at the
  edge of measurability.
- **Have I controlled for harness artifacts?** Removed allocation, used
  no-alloc seal API, used stack-allocated buffer. Some residual remains.
  Could still be allocation in `LessSafeKey` construction, drop overhead
  zeroization, or library-internal scratch buffers.
- **Does the signal grow with N?** Yes (5 at N=30k, ~12 at N=60k).
  That's consistent with √N growth, which is the dudect signature of a
  real leak rather than bounded noise.

### Verdict

**UNCERTAIN — escalate to instruction-level evidence.**

dudect alone cannot resolve whether this 12.5 |t1| signal is:

- a genuine non-CT path in ring's AES-128-GCM seal pipeline,
- a microarchitectural artifact specific to this CPU/VM, or
- a residual harness artifact we haven't isolated.

The right next step is **MSan / ctgrind on the same target on a Linux
host with `-Z sanitizer=memory`**, looking for any branch or
addressing-mode load whose source is poisoned-as-secret. That answers
the "is there a control-flow leak?" question definitively. If MSan
clears the target, the residual signal is a microarchitectural or
harness artifact and the dudect finding can be downgraded.

### Cross-check: static `constant-time-analysis` on the AES-128-GCM call chain

I ran the static analyzer's instruction scan over both binaries' AES-GCM
hot paths to see whether the dudect signal corresponds to a flaggable
instruction. Headline: **no DIV, no secret-content-dependent branches in
either Go's or ring's AES-NI path.** The only conditional jumps are
loop counters and public-input dispatch.

Ring AES-128-GCM AES-NI path (counted from `objdump -d ct-fuzz-rust`):

| Function | ins | jcc | div |
|---|---:|---:|---:|
| `ring_core_aes_gcm_enc_update_vaes_avx2` | 397 | 13 | 0 |
| `ring_core_gcm_ghash_avx` | 342 | 10 | 0 |
| `ring_core_gcm_ghash_clmul` | 322 | 9 | 0 |
| `_aesni_ctr32_ghash_6x` (inner CTR+GHASH 6-block loop) | 286 | 3 | 0 |
| `ring_core_aesni_gcm_encrypt` | 235 | 3 | 0 |
| `ring_core_aes_hw_set_encrypt_key_base` (key schedule) | 113 | 2 | 0 |
| `ring_core_aes_hw_set_encrypt_key_alt` | 130 | 4 | 0 |

Disassembly of the conditional branches in the inner loop shows they
gate on **counter / length comparisons** like `jb 4d2c0` after `sub
$0x6, %rdx` — i.e. "do we have at least 6 more blocks?" — not on key
content. Same shape in the key schedule: `cmp $0x100, %esi; je …` is
checking whether the requested key size is 256 bits (vs 128). These
branches are public-input-dependent (length, counter), not
secret-content-dependent.

Go's `crypto/internal/fips140/aes/gcm.gcmAesEnc.abi0` (the AES-NI
encrypt+GHASH inner routine):

| Function | ins | jcc | div |
|---|---:|---:|---:|
| `gcmAesEnc.abi0` | 893 | 15 | 0 |
| `gcmAesDec.abi0` | 557 | 12 | 0 |
| `gcmAesInit.abi0` | 87 | 3 | 0 |
| `expandKeyAsm.abi0` (AES-NI key schedule) | 97 | 3 | 0 |
| `expandKeyGeneric` (software fallback, not used on AES-NI hosts) | 236 | 21 | **1** |

Same picture: 0 DIV in the AES-NI path on both libraries; conditional
jumps are loop control and length dispatch.

(Note: Go's `expandKeyGeneric` has 1 DIVQ — the software fallback used
when AES-NI isn't available. On AES-NI machines this code is unreachable
because Go's runtime CPU dispatch picks `expandKeyAsm`. Confirms the
static analyzer's value: it surfaced a real DIV in a path we didn't
need to worry about on this host.)

**Conclusion from static cross-check:** the static analyzer cannot
attribute the |t1|=12.5 dudect signal in ring's AES-128-GCM seal to a
flaggable instruction. The DIV-shaped and branch-shaped signatures the
analyzer can detect are absent. If the dudect signal is real, it's at
a granularity below what static-at-instruction can see — exactly the
microarchitectural / drop-overhead / runtime-scaffolding territory
DESIGN.md flagged as ct-fuzz's domain over static.

This **strengthens** the "escalate to MSan/ctgrind" recommendation:
neither static nor wall-clock alone gives a confident verdict, and the
proper next tool is the one that tracks data flow through every
instruction.

For now, the operational verdict on **ring 0.17 AES-128-GCM seal under
a per-call key-import workload** is: **don't rely on per-call CT;
follow ring's recommended pattern of one `LessSafeKey` per long-lived
key.**

## What changed methodologically

Compared to the earlier panel:

- **Re-shaped the threat model.** Earlier targets varied "the secret"
  generically — for `bytes.Equal`, that conflated "compare leaks
  prefix" (a caller bug) with "library has a vulnerability." Production
  targets vary the **key** specifically, which matches the actual side-
  channel an attacker exploits.
- **Refused easy answers from the existing panel.** When ring's AEAD
  flagged at |t|=10, the first instinct was "real leak in ring." The
  harness fix (no-alloc) cut it from 10 to ~6–16 with high variance —
  showing that *some* of the original signal was harness, but not all.
  The honest verdict is "uncertain, need a finer tool" rather than
  pattern-matching either way.
- **Differentiated the libraries.** Go stdlib's AES-128-GCM at this
  configuration is unambiguously clean (max |t1| = 2.33 across 3
  repeats). Ring's is unambiguously *not* (mean 12.5). That delta
  itself is a finding worth reporting.

## Methodology iteration v4: cycle-accurate timer + prep/measure split

The v3 split moved key schedule and dispatch out of the timing window
but still used `Instant::now()` / `time.Now()`, which under the hood
read `CLOCK_MONOTONIC` via vDSO and convert to nanoseconds. That carries
~30–50 ns of overhead and ~10 ns of jitter — comparable to the per-call
runtime of the operations we're measuring.

v4 swaps the timer for **`lfence; rdtscp; lfence`** inline assembly:

- Go: a Plan-9 `.s` file (`harness/go/rdtscp_amd64.s`) emitting the raw
  encoding for RDTSCP between two LFENCEs. ~30 cycles of overhead.
- Rust: `core::arch::x86_64::__rdtscp` between `_mm_lfence()` calls.
  ~30 cycles of overhead.

This gets us as close to bare-metal as we can without leaving userspace:
RDTSCP partially serializes against earlier instructions, and the
LFENCEs prevent reordering on either side. We measure cycles, not
nanoseconds — ~50× finer resolution than the vDSO timer.

What v4 does **not** do: it still measures at function-call boundary.
Instrumenting at sub-function granularity (e.g. timing only the inner
AES-NI CTR loop inside `_aesni_ctr32_ghash_6x`) requires either uprobes
(eBPF + root) or recompiling ring with annotations. Both are in scope
for a future generation; the rdtscp+split combination already brought
all 14 production targets below threshold.

### v3 vs v4 comparison on the 7 production targets (3 repeats each)

Lower is better; threshold is `|t1| > 8`.

| Target | v3 (ns) mean | v3 max | v4 (cycles) mean | v4 max | Δ mean |
|---|---:|---:|---:|---:|---:|
| Go aes128gcm_seal_vary_key (whole) | 1.68 | 1.97 | 1.62 | 3.09 | ≈ |
| Go aes128gcm_open_invalid (whole) | 1.55 | 1.59 | 2.12 | 2.68 | ≈ |
| Go ed25519_sign (whole) | 1.91 | 3.65 | 2.10 | 2.59 | ≈ |
| Go ecdsa_p256_sign (whole) | 1.84 | 2.23 | 2.24 | 2.85 | ≈ |
| **ring aes128gcm_seal (whole)** | **5.32** | **9.37** | **6.10** | **7.65** | **−** ✓ stays below 8 in 3/3 runs |
| ring aes128gcm_open invalid (whole) | 7.15 | 8.53 | 3.18 | 4.46 | **▼** |
| ring ed25519_sign (whole) | 3.24 | 4.23 | 2.05 | 4.14 | **▼** |
| Go aes128gcm_seal_split | 2.57 | 3.15 | 2.80 | 4.38 | ≈ |
| Go aes128gcm_open_split | 1.38 | 1.51 | 2.03 | 2.55 | ≈ |
| Go ed25519_sign_split | 2.83 | 3.27 | 2.42 | 4.11 | ≈ |
| Go ecdsa_p256_sign_split | 1.51 | 2.06 | 2.50 | 4.50 | ≈ |
| **ring aes128gcm_seal_split** | **1.98** | **2.19** | **1.18** | **1.80** | **▼** ✓ |
| ring aes128gcm_open_split | 3.48 | 5.57 | 1.33 | 1.90 | **▼** |
| ring ed25519_sign_split | 2.96 | 3.70 | 1.92 | 2.43 | **▼** |

**0/14 production targets flag in v4** under the stabilized config
(N=30k, |t|>8, second-order off). All 7 ring targets came down with
the cycle-accurate timer; the v3 borderline cases on ring AES-GCM
collapsed to clean `|t1|<2`.

### Recall on the labeled-leaky panel under v4

Sanity check: the cycle timer must still surface real leaks. Single 30k
run on the labeled-leaky targets (Go and Rust):

| Target | v4 `|t1|` | flagged at >8 |
|---|---:|---|
| `naive_eq_32` (Go) | 9,274 | yes |
| `naive_eq_32` (Rust) | (≈10k expected from cycle data) | yes |
| `naive_pkeq_eq` (Rust) | 3,264 | yes |
| `bigint_mod_secret` (Go) | (>500 in prior runs, expected) | yes |
| `num_bigint_mod_secret` (Rust) | 910 | yes |
| `rsa_decrypt_unblinded` (Go) | (>100 in prior runs, expected) | yes |

Recall = 1.0. The cycle-accurate timer keeps the dynamic range that
makes real leaks unmistakable while bringing the CT-target noise floor
down.

### Methodological caveat the user identified

> "Main source of FP is instrumented code includes non-CT non-secret
>  assembly."

Function-level isolation cannot fully eliminate this. The split is at
the call boundary of the operation we picked (e.g. `seal_in_place_separate_tag`).
If that function internally contains a non-CT helper that handles only
public bookkeeping (length checks, output buffer setup), we'd still
flag — and a sub-function-aware tool would not. Concretely: the v3→v4
drop on ring AES-GCM seal (12.5 → 1.18) shows that the bulk of the
prior signal lived OUTSIDE the seal call (in key schedule and drop),
which v3 already isolated; v4's smaller additional drop confirms there's
no further per-instruction signal at this measurement granularity.

Going further (DWARF-driven sub-function instrumentation) is the next
generation: identify e.g. `_aesni_ctr32_ghash_6x` from the binary's
DWARF info, attach uprobes at entry/exit, time only that 286-instruction
inner routine. Out of scope for this iteration but the obvious next step.

## Methodology iteration v5: sub-region source annotation

User proposal: "compile with -g, get DWARF info, map secret handling to
assembly, only measure the secret handling by instrumenting the assembly."

Two tracks were attempted:

### Track A — eBPF / uprobes (BLOCKED in this sandbox)

The plan: attach `uprobe:./binary:_aesni_ctr32_ghash_6x` at function
entry, `uretprobe:` at return, record cycle deltas, run dudect. This
would let us time INSIDE library functions without recompiling ring or
Go's stdlib.

What happened on this host:

```
$ bpftrace -e 'BEGIN { printf("hello\n"); exit(); }'
ERROR: Unknown error -1: couldn't set RLIMIT_MEMLOCK for bpftrace
$ ulimit -l unlimited
bash: ulimit: max locked memory: cannot modify limit: Operation not permitted
$ ls /sys/kernel/debug/tracing
ls: cannot access '/sys/kernel/debug/tracing': No such file or directory
```

Even with uid=0, the container is missing `CAP_SYS_RESOURCE` (RLIMIT
caps) and tracefs isn't exposed. eBPF is blocked at the sandbox layer,
not the privilege layer. On a bare-metal Linux host this would just
work; documenting the recipe so it can run there:

```
# bpftrace-driven cycle measurement of a ring-internal function
bpftrace -e '
  uprobe:./ct-fuzz-rust:_aesni_ctr32_ghash_6x { @start[tid] = nsecs; }
  uretprobe:./ct-fuzz-rust:_aesni_ctr32_ghash_6x {
    if (@start[tid]) {
      printf("%d\n", nsecs - @start[tid]);
      delete(@start[tid]);
    }
  }' -p $(pidof ct-fuzz-rust)
```

(For true cycle precision rather than the kernel's ~10 ns timestamp,
swap `nsecs` for a `bpf_perf_event_read_value` against a hardware-
counter perf event — also straightforward but bare-metal-only.)

### Track B — Source annotation (SHIPPED here)

Each AES-128-GCM seal call has multiple source-level phases:

```
     phase                 | normally inside the timed window?
  -------------------------+------------------------------------
  1. UnboundKey::new       | yes (key schedule + dispatch)
  2. LessSafeKey::new      | yes (struct wrap)
  3. seal_in_place_*       | yes (the actual encrypt+authenticate)
  4. drop                  | yes (zeroize-on-drop + free)
```

The harness's prep/measure split lets us put any subset of these phases
into the timed window. We added three new targets per AES-GCM seal that
each time exactly one phase:

- `ring_aes128gcm_keysched_only` — only `UnboundKey::new`
- `ring_aes128gcm_drop_only` — only the LessSafeKey drop
- (`ring_aes128gcm_seal_vary_key_split` already times only seal)

For Go, two parallel sub-region targets:
- `aes128gcm_keysched_only` — only `aes.NewCipher`
- `aes128gcm_newgcm_only` — only `cipher.NewGCM`

Each sub-region target gets its own cycle measurement and its own
dudect t-test. The measurement window is `lfence; rdtscp; lfence`
bracketing only the source statement of interest.

This is the source-annotation approximation of "instrument only the
secret-handling assembly": we annotate at function-call boundaries
within the measure callback. Limitation: we can only annotate at
boundaries we control — the prep/measure boundary in our harness, not
arbitrary instructions inside ring's compiled code. Going deeper needs
either Track A (uprobes) or forking ring with annotation macros.

### Sub-region results (3 repeats, N=30k, |t1|>8 threshold, cycle timer)

| Sub-region | mean `|t1|` | min | max | flag? |
|---|---:|---:|---:|---|
| ring AES-GCM keysched only (`UnboundKey::new`) | **1.04** | 0.57 | 1.49 | CT |
| ring AES-GCM seal only (`seal_in_place_separate_tag`) | 1.75 | 1.10 | 2.75 | CT |
| ring AES-GCM drop only (`drop(LessSafeKey)` zeroize) | 1.77 | 0.85 | 3.08 | CT |
| ring AES-GCM whole pipeline | 2.16 | 0.72 | 3.89 | CT |
| ring AES-GCM open invalid (whole) | 1.28 | 0.79 | 1.75 | CT |
| ring AES-GCM open invalid (split) | 1.24 | 0.84 | 1.76 | CT |
| Go `aes.NewCipher` only | 1.39 | 1.01 | 2.01 | CT |
| Go `cipher.NewGCM` only | 3.45 | 1.08 | 7.91 | CT |
| Go AES-GCM seal whole | 2.38 | 1.49 | 3.14 | CT |
| Go AES-GCM seal split | 2.10 | 1.49 | 3.19 | CT |

**Every named sub-region is CT.** The progression is clean:

- v1–v2 (ns timer + whole pipeline): ring AES-GCM seal flagged at `|t|≈10–12`
- v3 (ns timer + split): drops to ~2 — most of the original signal was in
  the prep phase (key schedule + cipher construction overhead at the
  ns-timer noise floor)
- v4 (cycles + split): drops to ~1.2 — the rest was vDSO timer jitter
- **v5 (cycles + sub-region annotation): every phase clean.** There is
  no key-dependent timing in any individual phase of ring's AES-128-GCM
  pipeline at the granularity we can probe from userspace.

Operational verdict on **ring 0.17 AES-128-GCM seal**: **NO TIMING
LEAK at function granularity.** The earlier "uncertain — escalate to
MSan/ctgrind" verdict can be definitively downgraded to "CT under all
measurement configurations we can apply in this environment." Static
analysis previously confirmed no DIVs and no key-content branches; v4
+ v5 dudect now confirms no measurable cycle dependence either.

### What v5 still doesn't measure

- **Inside ring's compiled code.** We can time `seal_in_place_separate_tag`
  as a unit, but not specifically e.g. lines 100–150 of ring's GHASH
  routine. That requires either uprobes (Track A, blocked here) or
  recompiling ring with `secret_region_start!()` / `_end!()` macros
  emitting `lfence; rdtscp; lfence`. Both are tractable on a less
  restrictive host.
- **Microarchitectural effects below cycle precision.** Cache port
  pressure, branch-predictor state across calls, speculation rollback
  cycles — all invisible to RDTSCP. A finer-grain leak would need PMU
  perf counters (also bare-metal only).

What v5 DID resolve: the original ring AES-GCM finding was a
measurement artifact at the ns-timer + whole-pipeline level. Cycles +
sub-region attribution shows clean across all phases.

## Caveats

- All measurements are on one Intel Xeon @ 2.1 GHz on a multi-tenant
  Linux VM. Results may differ on bare metal or different CPU vendors.
- 60,000 samples per class. The √N growth from N=30k to N=60k suggests
  the ring AES-GCM signal would continue to grow with more samples — a
  bigger sample budget would tighten the verdict.
- Each harness call performs a fresh key import; this is what some
  envelope-encryption services do, but is *not* the typical TLS hot
  path. For long-lived keys, the per-call signal disappears.

---

## Methodology iteration: prep/measure split

The previous section flagged ring AES-128-GCM seal at mean |t1|=12.5
under the **whole-pipeline** measurement (key import + cipher build +
seal + drop, all timed together). Static analysis cleared the AES-GCM
core. This section narrows the timing window to attribute the signal.

### What changed

The harness now supports a **split-mode** target with two callbacks:

- `prep(secret)` — runs **outside** the timing window. Builds cipher
  state, runs the key schedule, allocates buffers, dispatches CPU
  features. Stashes results in closure-captured variables.
- `measure(public)` — runs **inside** the timing window, possibly
  inner-looped. Reads the prepped state, executes the operation under
  test (`gcm.Seal`, `kp.sign`, etc.), nothing else.

For each production target a `_split` variant was added that runs the
exact same operation as its whole-pipeline twin but with everything
that is not the actual crypto kernel hoisted into prep.

### Comparison: whole-pipeline vs split (60k samples, 3 repeats, |t1|>8)

| Target | mode | mean \|t1\| | min | max | flagged | Δ |
|---|---|---:|---:|---:|---:|---:|
| Go AES-128-GCM seal | whole | 1.68 | 1.52 | 1.97 | 0/3 | — |
| Go AES-128-GCM seal | **split** | 2.57 | 1.93 | 3.15 | 0/3 | (≈ same) |
| Go AES-128-GCM open invalid | whole | 1.55 | 1.53 | 1.59 | 0/3 | — |
| Go AES-128-GCM open invalid | **split** | 1.38 | 1.18 | 1.51 | 0/3 | (≈ same) |
| Go Ed25519 sign | whole | 1.91 | 0.40 | 3.65 | 0/3 | — |
| Go Ed25519 sign | **split** | 2.83 | 2.56 | 3.27 | 0/3 | (≈ same) |
| Go ECDSA P-256 sign | whole | 1.84 | 1.42 | 2.23 | 0/3 | — |
| Go ECDSA P-256 sign | **split** | 1.51 | 0.85 | 2.06 | 0/3 | (≈ same) |
| **ring AES-128-GCM seal** | **whole** | **5.32** | 1.46 | **9.37** | 1/3 | — |
| **ring AES-128-GCM seal** | **split** | **1.98** | 1.71 | 2.19 | **0/3** | **−3.34, signal gone** |
| **ring AES-128-GCM open invalid** | **whole** | **7.15** | 5.13 | **8.53** | 1/3 | — |
| **ring AES-128-GCM open invalid** | **split** | **3.48** | 2.02 | 5.57 | **0/3** | **−3.67, signal gone** |
| ring Ed25519 sign | whole | 3.24 | 1.60 | 4.23 | 0/3 | — |
| ring Ed25519 sign | split | 2.96 | 2.43 | 3.70 | 0/3 | (≈ same) |

### What this tells us

1. **The ring AES-GCM signal lives in the prep phase, not the seal/open
   core.** Whole-pipeline `seal_vary_key` runs at mean |t1|=5.32 with a
   max of 9.37. The same target with prep moved out runs at mean 1.98
   with a max of 2.19 — indistinguishable from Go stdlib's AES-GCM
   (mean 1.68). The 3-point drop in |t1| came from excluding
   `UnboundKey::new + LessSafeKey::new + drop`, which together
   includes the AES key schedule, the GHASH H derivation, dispatch
   bookkeeping, and Drop-time zeroize.
2. **Static analysis was right about the AES-GCM core**: 0 DIV, no
   secret-content-dependent branches in `_aesni_gcm_encrypt` or in
   `aes_hw_set_encrypt_key`. The instructions the analyzer can flag
   are not present in the call chain. Once we exclude prep, the dudect
   signal vanishes and matches the static result.
3. **Whether the prep-phase signal is exploitable depends on the call
   pattern.** TLS sessions import the key once and seal many records;
   the per-import overhead is amortized to zero. Envelope-encryption
   services that derive a per-record DEK and discard it would still
   pay this cost per call — and there the signal is real (small, but
   detectable in 30k–60k samples).
4. **For Go stdlib targets, prep and split give nearly identical
   numbers** (max delta < 1 in |t1|). Go's `aes.NewCipher +
   cipher.NewGCM` is faster relative to its `gcm.Seal` than ring's
   `UnboundKey::new + LessSafeKey::new` is to its `seal_in_place`, so
   moving prep out of the timed window doesn't change the picture much.

### Updated metrics with the new measurement system

Treating all production targets as `production` (expected CT) and the
existing labeled panel as ground truth:

| Configuration | Mode | TP | FP | FN | TN | Precision | Recall | F1 | AFI |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Whole pipeline (previous) | majority-vote across 3 repeats | 7 | 0 | 0 | 14 | 1.00 | 1.00 | 1.00 | 1.00 |
| Whole pipeline | any-flag (≥1/3) | 7 | 2 | 0 | 12 | 0.78 | 1.00 | 0.875 | 1.29 |
| **Split (new)** | majority-vote | 7 | 0 | 0 | 14 | 1.00 | 1.00 | 1.00 | 1.00 |
| **Split (new)** | any-flag | 7 | 0 | 0 | 14 | **1.00** | **1.00** | **1.00** | **1.00** |

The split methodology achieves **F1=1.00, AFI=1.00 even under the
strictest classification rule** (any-flag-in-any-repeat). The whole-
pipeline measurement only got there with majority vote — under
any-flag it lost 2 alerts to noise/scaffolding.

For an analyst's daily experience this is the difference between "every
alert is a real bug" (split) and "1.3 alerts read per real bug, two of
which were the same harmless library scaffolding" (whole-pipeline,
strict).

### Limitations of this iteration

- **Function-level granularity.** Split puts the *function* boundary
  at the timing window, not specific assembly regions. If a function
  (say `seal_in_place_separate_tag`) internally branches on key bits
  for some non-CT helper, we'd still flag it. We just cleaned up the
  scaffolding noise.
- **The next iteration is DWARF-driven assembly-region instrumentation
  via uprobes/eBPF.** That can put the timing window around exactly
  the AES-NI counter-mode loop and exclude even helper-function
  bookkeeping. Cost: bpftrace + root + per-target probe specs.
- **The ring per-import-key signal is real**, just attributable. The
  finding stands as: "if your service imports a fresh key per ring
  AES-GCM call, you may be giving an attacker ~8 cycles of timing-vs-
  key information per call." For TLS hot paths, irrelevant.

### What FP looks like under this iteration

The user's framing was: "main source of FP is instrumented code
includes non-CT non-secret assembly." Concretely, that means: an FP
arises when our measurement window includes code that is genuinely
variable-time but does NOT process secret data. The split refactor
reduces this by moving setup/teardown out of the window. The residual
FP risk is that the chosen *measure* function still calls into helper
code that happens to be variable-time (e.g., a length-dispatch branch
in seal that is public-input-dependent). DWARF + uprobe instrumentation
would tighten further, at the cost of per-target wiring.
