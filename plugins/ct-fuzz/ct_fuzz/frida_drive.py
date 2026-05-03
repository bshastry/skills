#!/usr/bin/env python3
"""Binary-instrumented dudect via Frida.

Drives the Rust harness, attaches Frida to it, and installs an interceptor
on a chosen ring-internal function (e.g. `ring_core_..._aesni_gcm_encrypt`).
The interceptor's onEnter/onLeave run a CModule-compiled `lfence; rdtscp;
lfence` pair, recording per-call cycle count of ONLY that function's body.

Pairs the inner-function cycles with the class label the harness emits on
stdout, then runs dudect (cropped Welch's t).
"""

import argparse
import json
import statistics
import subprocess
import sys
import threading
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ct_fuzz"))

from ct_fuzz.stats import cropped_welch_t  # noqa: E402

FRIDA_SCRIPT = r"""
// CModule produces the timestamp; subtraction happens in JS via UInt64.
const cm = new CModule(`
  #include <stdint.h>
  uint64_t now(void) {
    uint32_t lo, hi, aux;
    __asm__ __volatile__ (
      "lfence\n\t"
      ".byte 0x0F, 0x01, 0xF9\n\t"  // rdtscp
      "lfence"
      : "=a"(lo), "=d"(hi), "=c"(aux)
    );
    return ((uint64_t)hi << 32) | lo;
  }
`);

const target_name = TARGET_SYMBOL;
const bin = Process.enumerateModules()[0];
let addr = null;
// Match exact name first, else match by Rust-mangled prefix (drop the
// 17h<hash>E suffix that changes per build).
const stripHash = function(n) {
  return n.replace(/17h[0-9a-f]{16}E$/, '');
};
const target_pref = stripHash(target_name);
bin.enumerateSymbols().forEach(function(s){
  if (s.name === target_name) addr = s.address;
});
if (!addr) {
  bin.enumerateSymbols().forEach(function(s){
    if (!addr && stripHash(s.name) === target_pref) addr = s.address;
  });
}
if (!addr) {
  console.log('symbol not found:', target_name);
} else {
  console.log('hooking', target_name, 'at', addr);
  const nowFn = new NativeFunction(cm.now, 'uint64', []);
  Interceptor.attach(addr, {
    onEnter: function(args) {
      this.t0 = nowFn();
    },
    onLeave: function(retval) {
      const t1 = nowFn();
      send({ c: t1.sub(this.t0).toString() });
    }
  });
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="ring_aes128gcm_seal_vary_key_split",
                    help="ct-fuzz harness target name")
    ap.add_argument("--symbol", default="ring_core_0_17_14__aesni_gcm_encrypt",
                    help="ring-internal function to hook")
    ap.add_argument("--samples", type=int, default=10000)
    args = ap.parse_args()

    harness = ROOT / "ct-fuzz-rust"
    proc = subprocess.Popen(
        [str(harness)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        text=True,
    )

    sess = frida.attach(proc.pid)
    script_text = FRIDA_SCRIPT.replace("TARGET_SYMBOL", json.dumps(args.symbol))
    script = sess.create_script(script_text)

    inner_cycles: list[int] = []
    log_lines: list[str] = []

    def on_msg(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload", {})
            if "c" in payload:
                inner_cycles.append(int(payload["c"]))
            elif "cycles" in payload:
                inner_cycles.append(int(payload["cycles"]))
        elif msg.get("type") == "error":
            print("[frida-err]", msg.get("description"))
        elif msg.get("type") == "log":
            log_lines.append(msg.get("payload", ""))

    script.on("message", on_msg)
    script.load()
    print("\n".join(log_lines))

    # Drive the harness.
    proc.stdin.write(f"{args.target} {args.samples}\n")
    proc.stdin.flush()
    proc.stdin.close()

    # Read harness stdout: each line is "<class> <outer_cycles>" or "DONE".
    classes: list[str] = []
    outer_cycles: list[int] = []
    for line in proc.stdout:
        line = line.strip()
        if line == "DONE":
            break
        parts = line.split()
        if len(parts) == 2:
            classes.append(parts[0])
            try:
                outer_cycles.append(int(parts[1]))
            except ValueError:
                pass
    proc.wait(timeout=120)
    sess.detach()

    print(f"\nharness samples: {len(classes)}")
    print(f"frida inner-fn calls: {len(inner_cycles)}")
    if not inner_cycles:
        print("no inner-function calls captured — symbol not invoked or hook broken")
        return

    # Map: each harness sample's measure-callback runs the target operation,
    # which calls the hooked function `inner` times (depends on the inner-loop
    # count baked into the harness target). Average cycles per sample.
    calls_per_sample = len(inner_cycles) // max(len(classes), 1)
    print(f"inner calls per harness sample: {calls_per_sample}")

    # Aggregate inner cycles per harness sample.
    agg_a, agg_b = [], []
    if calls_per_sample >= 1:
        for i, cls in enumerate(classes):
            window = inner_cycles[i * calls_per_sample : (i + 1) * calls_per_sample]
            if not window:
                continue
            total = sum(window)
            (agg_a if cls == "A" else agg_b).append(total)

    if agg_a and agg_b:
        t1, p1 = cropped_welch_t(agg_a, agg_b)
        print(
            f"\ninner-fn dudect: classA n={len(agg_a)} mean={statistics.mean(agg_a):.0f}c, "
            f"classB n={len(agg_b)} mean={statistics.mean(agg_b):.0f}c, "
            f"|t1|={abs(t1):.2f} crop={p1:.2f}"
        )

        # Compare to the outer (harness-level) measurement.
        outer_a = [c for c, t in zip(classes, outer_cycles) if c == "A"]
        outer_b = [t for c, t in zip(classes, outer_cycles) if c == "B"]
        outer_a_t = [t for c, t in zip(classes, outer_cycles) if c == "A"]
        outer_b_t = [t for c, t in zip(classes, outer_cycles) if c == "B"]
        if outer_a_t and outer_b_t:
            t1o, p1o = cropped_welch_t(outer_a_t, outer_b_t)
            print(
                f"outer (harness) dudect: classA n={len(outer_a_t)} mean={statistics.mean(outer_a_t):.0f}c, "
                f"classB n={len(outer_b_t)} mean={statistics.mean(outer_b_t):.0f}c, "
                f"|t1|={abs(t1o):.2f} crop={p1o:.2f}"
            )


if __name__ == "__main__":
    main()
