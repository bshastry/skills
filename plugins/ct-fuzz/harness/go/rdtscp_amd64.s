// Cycle-accurate timer: lfence; rdtscp; lfence.
//
// rdtscp itself partially serializes — it waits for prior instructions to
// retire — but it does NOT prevent later instructions from executing
// before rdtscp completes. The lfence on either side gives strict
// ordering for the measurement window.
//
// Returns the 64-bit TSC composed from EDX:EAX. Overhead is ~30 cycles
// vs. ~30-50 ns for time.Now() (which under the hood does CLOCK_MONOTONIC
// vDSO read + nanosecond conversion). For ns-fast crypto operations this
// is the difference between "measurable" and "drowned in timer noise."

#include "textflag.h"

// func rdtscp() uint64
TEXT ·rdtscp(SB), NOSPLIT, $0-8
	LFENCE
	BYTE $0x0F; BYTE $0x01; BYTE $0xF9   // RDTSCP
	LFENCE
	SHLQ $32, DX
	ORQ  DX, AX
	MOVQ AX, ret+0(FP)
	RET
