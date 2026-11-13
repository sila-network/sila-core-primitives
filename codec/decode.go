// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package codec

import "errors"

// Kind is the kind of an encoded value.
type Kind uint8

const (
	// KindString is a byte string (including a single byte below 0x80).
	KindString Kind = iota
	// KindList is a list of values.
	KindList
)

func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindList:
		return "list"
	}
	return "invalid kind"
}

var (
	// ErrUnexpectedEnd: the input ends before the value, or a value extends
	// past the end of its input or of the list that contains it.
	ErrUnexpectedEnd = errors.New("sila/codec: value extends past the end of the input")
	// ErrNonCanonicalSize: a size is not written in its unique shortest form.
	ErrNonCanonicalSize = errors.New("sila/codec: non-canonical size")
	// ErrNonCanonicalInteger: an integer has leading zero bytes.
	ErrNonCanonicalInteger = errors.New("sila/codec: non-canonical integer (leading zero byte)")
	// ErrIntegerTooLarge: an integer does not fit the requested width.
	ErrIntegerTooLarge = errors.New("sila/codec: integer too large")
	// ErrExpectedString: a list was found where a string is required.
	ErrExpectedString = errors.New("sila/codec: expected string, found list")
	// ErrExpectedList: a string was found where a list is required.
	ErrExpectedList = errors.New("sila/codec: expected list, found string")
	// ErrTrailingData: data follows the single value that was expected.
	ErrTrailingData = errors.New("sila/codec: data after the value")
)

// Split reads the first value of b. It returns the kind of the value, its
// content (the bytes of a string, or the concatenated item encodings of a
// list) and the input after the value. content and rest are sub-slices of
// b. Split checks the header of the first value only: list items are
// checked when they are read (Split on the content, or Validate).
func Split(b []byte) (k Kind, content, rest []byte, err error) {
	if len(b) == 0 {
		return 0, nil, b, ErrUnexpectedEnd
	}
	p := b[0]
	var hdr, size int
	switch {
	case p < stringOffset:
		return KindString, b[:1], b[1:], nil
	case p <= stringOffset+maxShort:
		k, hdr, size = KindString, 1, int(p-stringOffset)
		if size == 1 {
			if len(b) < 2 {
				return 0, nil, b, ErrUnexpectedEnd
			}
			if b[1] < stringOffset {
				return 0, nil, b, ErrNonCanonicalSize
			}
		}
	case p < listOffset:
		k = KindString
		hdr, size, err = longSize(b, int(p-stringOffset-maxShort))
	case p <= listOffset+maxShort:
		k, hdr, size = KindList, 1, int(p-listOffset)
	default:
		k = KindList
		hdr, size, err = longSize(b, int(p-listOffset-maxShort))
	}
	if err != nil {
		return 0, nil, b, err
	}
	if size > len(b)-hdr {
		return 0, nil, b, ErrUnexpectedEnd
	}
	return k, b[hdr : hdr+size], b[hdr+size:], nil
}

// longSize reads the n-byte (1..8) big-endian size that follows the first
// byte of b and returns the header and content sizes.
func longSize(b []byte, n int) (hdr, size int, err error) {
	if len(b) < 1+n {
		return 0, 0, ErrUnexpectedEnd
	}
	if b[1] == 0 {
		return 0, 0, ErrNonCanonicalSize
	}
	var v uint64
	for _, c := range b[1 : 1+n] {
		v = v<<8 | uint64(c)
	}
	if v <= maxShort {
		return 0, 0, ErrNonCanonicalSize
	}
	// Compared as uint64 before the conversion, so a size above the
	// maximum int (any platform) cannot wrap.
	if v > uint64(len(b)-1-n) {
		return 0, 0, ErrUnexpectedEnd
	}
	return 1 + n, int(v), nil
}

// SplitString reads a string value at the start of b and returns its bytes
// and the input after it.
func SplitString(b []byte) (s, rest []byte, err error) {
	k, s, rest, err := Split(b)
	if err != nil {
		return nil, b, err
	}
	if k != KindString {
		return nil, b, ErrExpectedString
	}
	return s, rest, nil
}

// SplitList reads a list value at the start of b and returns its content
// (the concatenated item encodings) and the input after it.
func SplitList(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, b, err
	}
	if k != KindList {
		return nil, b, ErrExpectedList
	}
	return content, rest, nil
}

// SplitUint64 reads an unsigned integer of at most 64 bits at the start of
// b.
func SplitUint64(b []byte) (v uint64, rest []byte, err error) {
	s, rest, err := SplitString(b)
	if err != nil {
		return 0, b, err
	}
	switch {
	case len(s) > 8:
		return 0, b, ErrIntegerTooLarge
	case len(s) > 0 && s[0] == 0:
		return 0, b, ErrNonCanonicalInteger
	}
	for _, c := range s {
		v = v<<8 | uint64(c)
	}
	return v, rest, nil
}

// SplitUint256 reads an unsigned integer of at most 256 bits at the start
// of b and returns its 32-byte big-endian representation.
func SplitUint256(b []byte) (v [32]byte, rest []byte, err error) {
	s, rest, err := SplitString(b)
	if err != nil {
		return v, b, err
	}
	switch {
	case len(s) > len(v):
		return v, b, ErrIntegerTooLarge
	case len(s) > 0 && s[0] == 0:
		return v, b, ErrNonCanonicalInteger
	}
	copy(v[len(v)-len(s):], s)
	return v, rest, nil
}

// Count returns the number of values in content, the content of a list. It
// checks the headers of the items but not the inside of nested lists.
func Count(content []byte) (int, error) {
	n := 0
	for len(content) > 0 {
		_, _, rest, err := Split(content)
		if err != nil {
			return 0, err
		}
		content = rest
		n++
	}
	return n, nil
}

// Validate reports whether b is exactly one canonical value, including
// every nested item. It returns nil if it is, and otherwise the first
// error found (ErrTrailingData if a valid value is followed by more
// data). It does not recurse, so deep nesting cannot exhaust the goroutine
// stack; it allocates only for nesting deeper than 32 lists, and then at
// most one int per level.
func Validate(b []byte) error {
	k, content, rest, err := Split(b)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return ErrTrailingData
	}
	if k == KindString {
		return nil
	}
	// Positions in b: the items of the innermost open list are read from
	// pos up to end; ends holds the ends of the enclosing lists.
	var stack [32]int
	ends := stack[:0]
	end := len(b)
	pos := end - len(content)
	for {
		for pos == end {
			if len(ends) == 0 {
				return nil
			}
			end = ends[len(ends)-1]
			ends = ends[:len(ends)-1]
		}
		k, content, rest, err := Split(b[pos:end])
		if err != nil {
			return err
		}
		next := end - len(rest)
		if k == KindList && len(content) > 0 {
			ends = append(ends, end)
			end = next
			pos = next - len(content)
		} else {
			pos = next
		}
	}
}
