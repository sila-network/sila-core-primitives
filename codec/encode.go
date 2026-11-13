// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

// Package codec implements the SILA canonical encoding: a compact,
// deterministic byte format for nested lists of byte strings.
//
// # Values
//
// A value is either a byte string or a list of values. Each value has
// exactly one valid encoding, so equal values always encode to equal bytes
// and an encoding can be hashed or signed directly.
//
//	value                       encoding
//	single byte 0x00..0x7f      the byte itself
//	string of 0..55 bytes       0x80+len, bytes
//	string of 56+ bytes         0xb7+n, len (n bytes, big-endian), bytes
//	list, content 0..55 bytes   0xc0+len, content
//	list, content 56+ bytes     0xf7+n, len (n bytes, big-endian), content
//
// List content is the concatenation of the encodings of its items. A
// length takes n = 1..8 bytes.
//
// # Canonical rules
//
// The decoder accepts only the unique encoding of each value. It rejects:
//
//   - a one-byte string below 0x80 written with a 0x81 header;
//   - a long form (0xb8..0xbf, 0xf8..0xff) for a length below 56;
//   - a length with a leading zero byte;
//   - a value that extends past the end of its input or of its list;
//   - data after the value, where exactly one value is expected
//     (Validate).
//
// # Integers
//
// An unsigned integer is the byte string of its big-endian representation
// without leading zero bytes; zero is the empty string (0x80). The decoder
// rejects integers with leading zero bytes and integers that do not fit
// the requested width. Signed integers are not defined.
//
// # Scope
//
// The package encodes and decodes the format only. It does not map Go
// types by reflection and does not define the layout of any protocol
// object (transactions, blocks, domain separation); those belong to SILA
// protocol specifications built on this format. The decoder returns
// sub-slices of its input without copying. All functions are safe for
// concurrent use; a Builder is not.
package codec

import (
	"math/bits"
	"slices"
)

const (
	stringOffset = 0x80 // 0x80..0xb7: string of 0..55 bytes
	listOffset   = 0xc0 // 0xc0..0xf7: list with 0..55 content bytes
	maxShort     = 55   // longest string or list content with a one-byte header
)

// lengthBytes returns the number of bytes of v without leading zero bytes.
func lengthBytes(v uint64) int {
	return (bits.Len64(v) + 7) / 8
}

// headerSize returns the size of the header of a string or list whose
// content has size bytes (not used for single bytes below 0x80).
func headerSize(size int) int {
	if size <= maxShort {
		return 1
	}
	return 1 + lengthBytes(uint64(size))
}

func appendBigEndian(dst []byte, v uint64, n int) []byte {
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, byte(v>>(8*uint(i))))
	}
	return dst
}

func appendHeader(dst []byte, offset byte, size int) []byte {
	if size < 0 {
		panic("sila/codec: negative size")
	}
	if size <= maxShort {
		return append(dst, offset+byte(size))
	}
	n := lengthBytes(uint64(size))
	dst = append(dst, offset+maxShort+byte(n))
	return appendBigEndian(dst, uint64(size), n)
}

// AppendString appends the encoding of the byte string s to dst and returns
// the extended slice. s may overlap dst, including the unused capacity of
// dst.
func AppendString(dst, s []byte) []byte {
	if len(s) == 1 && s[0] < stringOffset {
		return append(dst, s[0])
	}
	// The bytes of s are moved into place before the header is written: if
	// s lies in the unused capacity of dst, writing the header first would
	// overwrite them. copy is safe for overlapping slices.
	n, h := len(dst), headerSize(len(s))
	dst = slices.Grow(dst, h+len(s))[:n+h+len(s)]
	copy(dst[n+h:], s)
	return appendHeader(dst[:n], stringOffset, len(s))[:n+h+len(s)]
}

// AppendUint64 appends the encoding of the unsigned integer v to dst.
func AppendUint64(dst []byte, v uint64) []byte {
	switch {
	case v == 0:
		return append(dst, stringOffset)
	case v < stringOffset:
		return append(dst, byte(v))
	}
	n := lengthBytes(v)
	dst = append(dst, stringOffset+byte(n))
	return appendBigEndian(dst, v, n)
}

// AppendUint256 appends the encoding of the unsigned 256-bit integer whose
// big-endian representation is v. v may overlap dst.
func AppendUint256(dst []byte, v *[32]byte) []byte {
	i := 0
	for i < len(v) && v[i] == 0 {
		i++
	}
	return AppendString(dst, v[i:])
}

// AppendListHeader appends the header of a list whose content (the
// concatenated encodings of its items) is contentSize bytes long. The
// caller appends the content. It panics if contentSize is negative.
func AppendListHeader(dst []byte, contentSize int) []byte {
	return appendHeader(dst, listOffset, contentSize)
}

// StringSize returns the size of the encoding of a byte string of n bytes
// whose first byte is first (first is used only when n == 1).
func StringSize(n int, first byte) int {
	if n == 1 && first < stringOffset {
		return 1
	}
	return headerSize(n) + n
}

// ListSize returns the size of the encoding of a list with contentSize
// content bytes.
func ListSize(contentSize int) int {
	return headerSize(contentSize) + contentSize
}
