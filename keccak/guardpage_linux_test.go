// SPDX-License-Identifier: Apache-2.0

//go:build linux

package keccak

import (
	"syscall"
	"testing"
)

// The input is placed so that it ends exactly at a PROT_NONE page. Any read
// past the end of the caller's slice (e.g. a 16-byte vector load of the last
// 8-byte lane) would crash the test with SIGSEGV.
func TestNoOverreadPastInput(t *testing.T) {
	page := syscall.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, 3*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Skip("mmap unavailable:", err)
	}
	defer syscall.Munmap(mem)
	if err := syscall.Mprotect(mem[2*page:], syscall.PROT_NONE); err != nil {
		t.Skip("mprotect unavailable:", err)
	}
	end := 2 * page
	for n := 0; n <= 2*page && n <= 12*Rate; n++ {
		data := mem[end-n : end : end]
		for i := range data {
			data[i] = byte(i * 7)
		}
		if Sum256(data) != referenceSum(data) {
			t.Fatalf("mismatch len=%d", n)
		}
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
	// Underread: the input starts right after a guard page too.
	if err := syscall.Mprotect(mem[:page], syscall.PROT_NONE); err != nil {
		t.Skip("mprotect unavailable:", err)
	}
	for n := 0; n <= 12*Rate; n++ {
		data := mem[page : page+n : page+n]
		_ = Sum256(data)
	}
}
