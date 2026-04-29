// Package safe contains crypto patterns that are constant-time and should
// produce zero ERROR-level findings from ct_analyzer. WARN-level branch
// findings may occur because the analyzer does not do data flow analysis;
// what matters is that we do not flag any DIV, REM, or FDIV on secret data.
package safe

import "crypto/subtle"

// EqualSafe is the standard library's constant-time byte comparison. Every
// crypto reviewer in 2026 expects this to be the only acceptable form for
// comparing MACs, signatures, tokens, and capability cookies.
func EqualSafe(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
