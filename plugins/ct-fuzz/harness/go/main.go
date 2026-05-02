// ct-fuzz Go harness.
//
// Reads "<target> <samples>" on stdin per run; for each sample it picks
// class A (fixed secret) or class B (random secret) by alternating, runs
// the target, and emits "<class> <cycles>\n" on stdout.
//
// Timing source: monotonic time via time.Now() (ns resolution). On amd64
// this resolves to CLOCK_MONOTONIC and is sub-microsecond — sufficient
// for crypto operations that take >>100ns. We avoid RDTSC to keep the
// harness portable; the dudect t-test is invariant to constant scale.

package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// targetFn runs one operation and returns. The implementation must NOT
// allocate inside the timed region if at all avoidable.
type targetFn func(public, secret []byte)

// targetSpec describes a registered target.
type targetSpec struct {
	fn        targetFn
	publicLen int
	secretLen int
	// inner is the number of inner-loop calls per timed sample. For ns-fast
	// targets we batch many calls so the per-sample time exceeds time.Now()
	// overhead. For slow targets (RSA) inner=1.
	inner int
	// fixedA is the fixed-class secret (typically zeros). nil → all-zeros of secretLen.
	fixedA []byte
}

var targets = map[string]targetSpec{}

func register(name string, secretLen, publicLen, inner int, fn targetFn) {
	targets[name] = targetSpec{fn: fn, publicLen: publicLen, secretLen: secretLen, inner: inner}
}

func main() {
	registerAll()
	runtime.GC()
	// Lock the goroutine to an OS thread to reduce scheduler jitter.
	runtime.LockOSThread()

	if len(os.Args) >= 2 && os.Args[1] == "list" {
		for name, spec := range targets {
			fmt.Printf("%s\tsecret=%d\tpublic=%d\tinner=%d\n", name, spec.secretLen, spec.publicLen, spec.inner)
		}
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<16)
	defer out.Flush()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "ct-fuzz: bad command %q\n", line)
			continue
		}
		name := parts[0]
		n, err := strconv.Atoi(parts[1])
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "ct-fuzz: bad sample count %q\n", parts[1])
			continue
		}
		spec, ok := targets[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "ct-fuzz: unknown target %q\n", name)
			continue
		}
		runOne(out, name, spec, n)
	}
}

func runOne(out *bufio.Writer, name string, spec targetSpec, n int) {
	// fixedA defaults to 0xAA repeats (matching public fill); see comment below.
	fixedA := spec.fixedA
	if fixedA == nil {
		fixedA = make([]byte, spec.secretLen)
		for i := range fixedA {
			fixedA[i] = 0xAA
		}
	}
	publicBuf := make([]byte, spec.publicLen)
	secretBuf := make([]byte, spec.secretLen)
	inner := spec.inner
	if inner < 1 {
		inner = 1
	}

	// Public input: fixed for the entire run. This is the standard dudect
	// setup — we measure timing-vs-secret with the public input held
	// constant. Use 0xAA fill to avoid degenerate cases (zero divisor in
	// modular reduction, all-zero ciphertext in RSA, etc.).
	for i := range publicBuf {
		publicBuf[i] = 0xAA
	}

	// Pre-generate a class-selector byte stream so we don't read /dev/urandom
	// inside the measurement loop.
	classBytes := make([]byte, n)
	_, _ = rand.Read(classBytes)

	// Pre-generate random secrets for class B. This isolates the cost of
	// rand.Read from the measurement window — we just memcpy from the pool.
	randomPool := make([]byte, n*spec.secretLen)
	_, _ = rand.Read(randomPool)

	// Warmup: prime caches, branch predictor.
	const warmup = 2048
	for i := 0; i < warmup; i++ {
		copy(secretBuf, randomPool[(i%n)*spec.secretLen:])
		spec.fn(publicBuf, secretBuf)
	}

	// Disable GC during measurement.
	runtime.GC()
	gcOld := debugSetGCPercent(-1)
	defer debugSetGCPercent(gcOld)

	for i := 0; i < n; i++ {
		var class byte
		if classBytes[i]&1 == 0 {
			class = 'A'
			copy(secretBuf, fixedA)
		} else {
			class = 'B'
			copy(secretBuf, randomPool[i*spec.secretLen:(i+1)*spec.secretLen])
		}
		t0 := time.Now()
		for k := 0; k < inner; k++ {
			spec.fn(publicBuf, secretBuf)
		}
		t1 := time.Now()
		fmt.Fprintf(out, "%c %d\n", class, t1.Sub(t0).Nanoseconds())
	}
	fmt.Fprintln(out, "DONE")
	out.Flush()
}

