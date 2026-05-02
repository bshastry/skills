package main

import "runtime/debug"

func debugSetGCPercent(p int) int { return debug.SetGCPercent(p) }
