package main

import "crypto/rand"

func realRandRead(p []byte) (int, error) { return rand.Read(p) }
