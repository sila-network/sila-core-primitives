// SPDX-License-Identifier: Apache-2.0

package keccak

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// Regression test (review finding F-1): hashing a huge input must remain
// preemptible. Before the assembly path was split into bounded calls with
// a preemption point, one assembly call ran for the whole input: other
// goroutines could not be scheduled on that P and a GC could not suspend
// the goroutine for the whole hash (~1 s for 512 MiB).
//
// The test forces a single P, so the hashing goroutine and a probe
// goroutine compete for it. The probe asks to wake up every millisecond and
// records the longest delay. A preemptible hash is preempted by the runtime
// about every 10 ms, so the delay stays small. A non-preemptible hash
// delays the probe for about the whole hash.
//
// It deliberately does not time runtime.GC(): that wall-clock time also
// includes concurrent marking, which shares the single P with the hash and
// is slow even when hashing is preemptible.
func TestLargeHashIsPreemptible(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 256 MiB")
	}
	data := make([]byte, 256<<20)
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	var stop atomic.Bool
	var worst atomic.Int64
	probeReady := make(chan struct{})
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		close(probeReady)
		for !stop.Load() {
			s := time.Now()
			time.Sleep(time.Millisecond)
			if d := int64(time.Since(s)); d > worst.Load() {
				worst.Store(d)
			}
		}
	}()
	<-probeReady

	s := time.Now()
	Sum256(data)
	hash := time.Since(s)
	stop.Store(true)
	<-probeDone

	delay := time.Duration(worst.Load())
	t.Logf("GOMAXPROCS=1 hash=%v longest probe delay=%v", hash, delay)
	if hash < 200*time.Millisecond {
		t.Skipf("hash finished too quickly (%v) to be meaningful", hash)
	}
	if delay > 100*time.Millisecond && delay > hash/3 {
		t.Fatalf("another goroutine could not run for %v of a %v hash: hashing is not preemptible", delay, hash)
	}
}
