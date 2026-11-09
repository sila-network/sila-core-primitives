// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import "math/bits"

// This file implements constant-time arithmetic modulo a 256-bit odd
// modulus m, on values held as four little-endian 64-bit limbs in
// Montgomery form (x·R mod m, R = 2^256). It is shared by the field
// (mod p) and the scalar group (mod n).
//
// Constant-time contract: no branch, loop bound or memory index depends on
// the value of an operand. Branches only depend on public constants (the
// modulus and fixed exponents). math/bits Add64/Sub64/Mul64 compile to
// carry-chain and full-width multiply instructions on amd64 and arm64, and
// their portable fallbacks are branch-free.

type limbs = [4]uint64

type modulus struct {
	m     limbs  // the modulus
	m0inv uint64 // -m^-1 mod 2^64
	r2    limbs  // R^2 mod m, for conversion into Montgomery form
	one   limbs  // R mod m, i.e. 1 in Montgomery form
}

func newModulus(m limbs) *modulus {
	md := &modulus{m: m}
	// Newton iteration for m^-1 mod 2^64; each step doubles the correct
	// low bits (m is odd, so the start value 1 is correct mod 2).
	inv := uint64(1)
	for i := 0; i < 6; i++ {
		inv *= 2 - m[0]*inv
	}
	if inv*m[0] != 1 {
		panic("sila/secp256k1: modulus is not odd")
	}
	md.m0inv = -inv

	// R mod m and R^2 mod m by repeated modular doubling of 1.
	x := limbs{1, 0, 0, 0}
	for i := 0; i < 512; i++ {
		md.add(&x, &x, &x)
		if i == 255 {
			md.one = x
		}
	}
	md.r2 = x
	return md
}

// add sets z = x + y mod m, for x, y < m.
func (md *modulus) add(z, x, y *limbs) {
	var s limbs
	var c uint64
	s[0], c = bits.Add64(x[0], y[0], 0)
	s[1], c = bits.Add64(x[1], y[1], c)
	s[2], c = bits.Add64(x[2], y[2], c)
	s[3], c = bits.Add64(x[3], y[3], c)
	md.reduceOnce(z, &s, c)
}

// reduceOnce sets z = (carry·2^256 + s) - m if that is non-negative,
// else z = s. Requires carry·2^256 + s < 2m.
func (md *modulus) reduceOnce(z, s *limbs, carry uint64) {
	var d limbs
	var b uint64
	d[0], b = bits.Sub64(s[0], md.m[0], 0)
	d[1], b = bits.Sub64(s[1], md.m[1], b)
	d[2], b = bits.Sub64(s[2], md.m[2], b)
	d[3], b = bits.Sub64(s[3], md.m[3], b)
	_, b = bits.Sub64(carry, 0, b)
	// b == 1 exactly when carry·2^256 + s < m: keep s.
	keep := -b
	z[0] = s[0]&keep | d[0]&^keep
	z[1] = s[1]&keep | d[1]&^keep
	z[2] = s[2]&keep | d[2]&^keep
	z[3] = s[3]&keep | d[3]&^keep
}

// sub sets z = x - y mod m, for x, y < m.
func (md *modulus) sub(z, x, y *limbs) {
	var d limbs
	var b uint64
	d[0], b = bits.Sub64(x[0], y[0], 0)
	d[1], b = bits.Sub64(x[1], y[1], b)
	d[2], b = bits.Sub64(x[2], y[2], b)
	d[3], b = bits.Sub64(x[3], y[3], b)
	mask := -b // all ones if x < y: add m back
	var c uint64
	z[0], c = bits.Add64(d[0], md.m[0]&mask, 0)
	z[1], c = bits.Add64(d[1], md.m[1]&mask, c)
	z[2], c = bits.Add64(d[2], md.m[2]&mask, c)
	z[3], _ = bits.Add64(d[3], md.m[3]&mask, c)
}

// neg sets z = -x mod m (0 stays 0), for x < m.
func (md *modulus) neg(z, x *limbs) {
	var zero limbs
	md.sub(z, &zero, x)
}

// mul sets z = x·y·R^-1 mod m (Montgomery product, CIOS method), for
// x, y < m. The result is fully reduced.
func (md *modulus) mul(z, x, y *limbs) {
	var t0, t1, t2, t3, t4 uint64
	for i := 0; i < 4; i++ {
		yi := y[i]
		// t += x·y[i]
		var c, hi, lo, cc uint64
		hi, lo = bits.Mul64(x[0], yi)
		t0, cc = bits.Add64(t0, lo, 0)
		c = hi + cc
		hi, lo = bits.Mul64(x[1], yi)
		lo, cc = bits.Add64(lo, c, 0)
		hi += cc
		t1, cc = bits.Add64(t1, lo, 0)
		c = hi + cc
		hi, lo = bits.Mul64(x[2], yi)
		lo, cc = bits.Add64(lo, c, 0)
		hi += cc
		t2, cc = bits.Add64(t2, lo, 0)
		c = hi + cc
		hi, lo = bits.Mul64(x[3], yi)
		lo, cc = bits.Add64(lo, c, 0)
		hi += cc
		t3, cc = bits.Add64(t3, lo, 0)
		c = hi + cc
		var t5 uint64
		t4, t5 = bits.Add64(t4, c, 0)

		// t = (t + q·m) / 2^64 with q = t0·(-m^-1) mod 2^64.
		q := t0 * md.m0inv
		hi, lo = bits.Mul64(q, md.m[0])
		_, cc = bits.Add64(t0, lo, 0)
		c = hi + cc
		hi, lo = bits.Mul64(q, md.m[1])
		lo, cc = bits.Add64(lo, c, 0)
		hi += cc
		t0, cc = bits.Add64(t1, lo, 0)
		c = hi + cc
		hi, lo = bits.Mul64(q, md.m[2])
		lo, cc = bits.Add64(lo, c, 0)
		hi += cc
		t1, cc = bits.Add64(t2, lo, 0)
		c = hi + cc
		hi, lo = bits.Mul64(q, md.m[3])
		lo, cc = bits.Add64(lo, c, 0)
		hi += cc
		t2, cc = bits.Add64(t3, lo, 0)
		c = hi + cc
		t3, cc = bits.Add64(t4, c, 0)
		t4 = t5 + cc
	}
	s := limbs{t0, t1, t2, t3}
	md.reduceOnce(z, &s, t4)
}

// toMont converts a canonical value x < m into Montgomery form.
func (md *modulus) toMont(z, x *limbs) { md.mul(z, x, &md.r2) }

// fromMont converts out of Montgomery form.
func (md *modulus) fromMont(z, x *limbs) {
	one := limbs{1, 0, 0, 0}
	md.mul(z, x, &one)
}

// expPublic sets z = x^e (Montgomery form) for a PUBLIC exponent e given
// as big-endian bytes. Branches depend only on the bits of e, never on x.
func (md *modulus) expPublic(z, x *limbs, e *[32]byte) {
	acc := md.one
	base := *x
	for _, byt := range e {
		for bit := 7; bit >= 0; bit-- {
			md.mul(&acc, &acc, &acc)
			if byt>>uint(bit)&1 == 1 {
				md.mul(&acc, &acc, &base)
			}
		}
	}
	*z = acc
}

// limbsFromBytes decodes 32 big-endian bytes.
func limbsFromBytes(b *[32]byte) limbs {
	var x limbs
	for i := 0; i < 4; i++ {
		off := 24 - 8*i
		x[i] = uint64(b[off])<<56 | uint64(b[off+1])<<48 | uint64(b[off+2])<<40 | uint64(b[off+3])<<32 |
			uint64(b[off+4])<<24 | uint64(b[off+5])<<16 | uint64(b[off+6])<<8 | uint64(b[off+7])
	}
	return x
}

// limbsToBytes encodes 32 big-endian bytes.
func limbsToBytes(out *[32]byte, x *limbs) {
	for i := 0; i < 4; i++ {
		off := 24 - 8*i
		v := x[i]
		out[off] = byte(v >> 56)
		out[off+1] = byte(v >> 48)
		out[off+2] = byte(v >> 40)
		out[off+3] = byte(v >> 32)
		out[off+4] = byte(v >> 24)
		out[off+5] = byte(v >> 16)
		out[off+6] = byte(v >> 8)
		out[off+7] = byte(v)
	}
}

// lessThan returns 1 if x < y, else 0, in constant time.
func lessThan(x, y *limbs) uint64 {
	var b uint64
	_, b = bits.Sub64(x[0], y[0], 0)
	_, b = bits.Sub64(x[1], y[1], b)
	_, b = bits.Sub64(x[2], y[2], b)
	_, b = bits.Sub64(x[3], y[3], b)
	return b
}

// isZeroLimbs returns 1 if x == 0, else 0, in constant time.
func isZeroLimbs(x *limbs) uint64 {
	v := x[0] | x[1] | x[2] | x[3]
	// (v | -v) has its top bit set exactly when v != 0.
	return 1 ^ ((v | -v) >> 63)
}

// equalLimbs returns 1 if x == y, else 0, in constant time.
func equalLimbs(x, y *limbs) uint64 {
	d := limbs{x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]}
	return isZeroLimbs(&d)
}

// selectLimbs sets z = a if cond == 1, z = b if cond == 0 (cond in {0,1}).
func selectLimbs(z, a, b *limbs, cond uint64) {
	mask := -cond
	z[0] = a[0]&mask | b[0]&^mask
	z[1] = a[1]&mask | b[1]&^mask
	z[2] = a[2]&mask | b[2]&^mask
	z[3] = a[3]&mask | b[3]&^mask
}

// exponentBytes returns (m + delta) >> shift as 32 big-endian bytes, for a
// small delta in [-2, 1]. It is used to derive the public exponents m-2
// and (m+1)/4 from the modulus instead of hard-coding them.
func exponentBytes(m limbs, delta int64, shift uint) [32]byte {
	var x limbs
	var c uint64
	if delta >= 0 {
		x[0], c = bits.Add64(m[0], uint64(delta), 0)
		x[1], c = bits.Add64(m[1], 0, c)
		x[2], c = bits.Add64(m[2], 0, c)
		x[3], c = bits.Add64(m[3], 0, c)
	} else {
		x[0], c = bits.Sub64(m[0], uint64(-delta), 0)
		x[1], c = bits.Sub64(m[1], 0, c)
		x[2], c = bits.Sub64(m[2], 0, c)
		x[3], c = bits.Sub64(m[3], 0, c)
	}
	if c != 0 && delta < 0 {
		panic("sila/secp256k1: exponent underflow")
	}
	// Shift right across limbs; the carry (if any) becomes the top bit.
	for s := uint(0); s < shift; s++ {
		x[0] = x[0]>>1 | x[1]<<63
		x[1] = x[1]>>1 | x[2]<<63
		x[2] = x[2]>>1 | x[3]<<63
		x[3] = x[3]>>1 | c<<63
		c = 0
	}
	if c != 0 {
		panic("sila/secp256k1: exponent overflow")
	}
	var out [32]byte
	limbsToBytes(&out, &x)
	return out
}
