package main

// rdtscp returns the current TSC value with lfence-rdtscp-lfence
// serialization. amd64 only; the harness is built for amd64 by default.
func rdtscp() uint64
