// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package codec

import "errors"

// ErrOpenList is returned by Builder.Bytes and Builder.AppendTo when a list
// was started and not ended.
var ErrOpenList = errors.New("sila/codec: list not ended")

// A Builder encodes nested lists whose sizes are not known in advance.
//
//	var b codec.Builder
//	b.StartList()
//	b.Uint64(7)
//	b.String([]byte("SILA"))
//	b.EndList()
//	enc, err := b.Bytes()
//
// The output is the concatenation of the values added at the top level.
// List headers are written once, when the output is produced, so the cost
// is linear in the output size for any nesting depth. The zero value is
// ready to use. A Builder must not be copied after first use and is not
// safe for concurrent use.
type Builder struct {
	buf   []byte     // output without list headers
	heads []listHead // one per list, in start order
	open  []int      // indexes into heads of the lists not yet ended
	hsize int        // total size of the headers of ended lists
}

type listHead struct {
	offset int // position in buf where the content starts
	before int // hsize when the list was started
	size   int // content size, including headers of nested lists
}

// String adds the byte string s.
func (b *Builder) String(s []byte) { b.buf = AppendString(b.buf, s) }

// Uint64 adds the unsigned integer v.
func (b *Builder) Uint64(v uint64) { b.buf = AppendUint64(b.buf, v) }

// Uint256 adds the unsigned 256-bit integer with big-endian representation v.
func (b *Builder) Uint256(v *[32]byte) { b.buf = AppendUint256(b.buf, v) }

// Raw adds enc, which must be exactly one complete canonical value (an
// encoding produced earlier). It returns the error of Validate and adds
// nothing if enc is not.
func (b *Builder) Raw(enc []byte) error {
	if err := Validate(enc); err != nil {
		return err
	}
	b.buf = append(b.buf, enc...)
	return nil
}

// StartList starts a list. The values added until the matching EndList are
// its items.
func (b *Builder) StartList() {
	b.heads = append(b.heads, listHead{offset: len(b.buf), before: b.hsize})
	b.open = append(b.open, len(b.heads)-1)
}

// EndList ends the most recently started list that is still open. It
// panics if no list is open.
func (b *Builder) EndList() {
	if len(b.open) == 0 {
		panic("sila/codec: EndList without StartList")
	}
	h := &b.heads[b.open[len(b.open)-1]]
	b.open = b.open[:len(b.open)-1]
	// Lists ended since this one started are nested in it.
	h.size = len(b.buf) - h.offset + b.hsize - h.before
	b.hsize += headerSize(h.size)
}

// Len returns the size of the output once all open lists are ended
// (headers of open lists are not counted).
func (b *Builder) Len() int { return len(b.buf) + b.hsize }

// AppendTo appends the output to dst. It returns ErrOpenList, and dst
// unchanged, if a list is still open.
func (b *Builder) AppendTo(dst []byte) ([]byte, error) {
	if len(b.open) != 0 {
		return dst, ErrOpenList
	}
	pos := 0
	for _, h := range b.heads {
		dst = append(dst, b.buf[pos:h.offset]...)
		dst = AppendListHeader(dst, h.size)
		pos = h.offset
	}
	return append(dst, b.buf[pos:]...), nil
}

// Bytes returns the output in a new slice. It returns ErrOpenList if a list
// is still open.
func (b *Builder) Bytes() ([]byte, error) {
	if len(b.open) != 0 {
		return nil, ErrOpenList
	}
	return b.AppendTo(make([]byte, 0, b.Len()))
}

// Reset empties the Builder and keeps its allocated memory.
func (b *Builder) Reset() {
	b.buf = b.buf[:0]
	b.heads = b.heads[:0]
	b.open = b.open[:0]
	b.hsize = 0
}
