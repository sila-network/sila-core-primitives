// SPDX-License-Identifier: Apache-2.0

package keccak

import (
	"runtime"
	"testing"
	"time"
)

// Regression test: hashing a huge input must not block a stop-the-world
// garbage collection for the duration of the hash. Before the assembly
// path was split into bounded calls, runtime.GC() here waited ~1 s.
func TestLargeHashDoesNotBlockGC(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 256 MiB")
	}
	data := make([]byte, 256<<20)
	start := make(chan struct{})
	done := make(chan time.Duration)
	go func() {
		close(start)
		s := time.Now()
		Sum256(data)
		done <- time.Since(s)
	}()
	<-start
	time.Sleep(20 * time.Millisecond)
	s := time.Now()
	runtime.GC()
	gc := time.Since(s)
	hash := <-done
	t.Logf("hash %v, concurrent runtime.GC() %v", hash, gc)
	// Only meaningful when the hash was still running during the GC.
	if hash > 4*gc && gc > 100*time.Millisecond {
		t.Fatalf("runtime.GC() took %v while hashing (hash took %v): hashing is not preemptible", gc, hash)
	}
	if gc > hash/2 && hash > 200*time.Millisecond {
		t.Fatalf("runtime.GC() took %v of a %v hash: hashing is not preemptible", gc, hash)
	}
}
