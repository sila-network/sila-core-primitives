// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"math/rand"
	"slices"
	"sync"
	"testing"
)

// The blinded fixed-base multiplication from canonical shares returns
// exactly k·G for edge and random scalars, including c1 + c2 + b = 0 and
// k = 0, with the process-wide blinding and with the fallback, for any
// projective randomiser; the randomiser changes the projective
// coordinates (finding S-15) but not the point.
func TestBlindedBaseMultMatchesPlain(t *testing.T) {
	rng := rand.New(rand.NewSource(80))
	bl := currentBlinding()
	if bl == nil {
		t.Fatal("no process-wide blinding")
	}
	var negb limbs
	scalarN.neg(&negb, &bl.b)
	ks := []limbs{negb, {}, {1}, {scalarN.m[0] - 1, scalarN.m[1], scalarN.m[2], scalarN.m[3]}}
	for _, k := range interesting(rng, bigN, 300) {
		ks = append(ks, bigToLimbs(k))
	}
	seed := [32]byte{9}
	fbc, fnegB := derivedBaseBlinding(&seed, 'B', nil)
	fallback := func() (limbs, point) { return fbc, fnegB }
	var negfb limbs
	scalarN.neg(&negfb, &fbc)
	for i, k := range append(ks, negfb) {
		var ks scalar
		scalarN.toMont(&ks.v, &k)
		var want point
		want.scalarBaseMult(&ks)
		// Shares c1 (random) and c2 = k - c1.
		c1 := bigToLimbs(new(big.Int).Rand(rng, bigN))
		var c2 limbs
		scalarN.sub(&c2, &k, &c1)
		l1 := projectiveRandomiser(&c1)
		l2 := fieldFromUint(uint64(i) + 2)
		var got1, got2, got3 point
		got1.scalarBaseMultShares(&c1, &c2, &l1, fallback)
		got2.scalarBaseMultShares(&c1, &c2, &l2, fallback)
		// Fallback path: no process-wide blinding.
		blindingState.Store(nil)
		withRandomSource(t, failingReader{}, func() {
			got3.scalarBaseMultShares(&c1, &c2, &l1, fallback)
		})
		blindingState.Store(bl)
		if got1.equal(&want) != 1 || got2.equal(&want) != 1 || got3.equal(&want) != 1 {
			t.Fatalf("blinded k·G differs for case %d", i)
		}
		if want.isIdentity() == 0 && got1.x == got2.x && got1.z == got2.z {
			t.Fatalf("case %d: the projective randomiser did not change the coordinates", i)
		}
	}
}

func TestBlindedInverseMatchesPlain(t *testing.T) {
	rng := rand.New(rand.NewSource(81))
	seed := [32]byte{1}
	for i, k := range interesting(rng, bigN, 300) {
		sk := scalarFromBig(k)
		seed[1] = byte(i)
		rho, _ := derivedBlinding(&seed, 'I', false, nil)
		if rho.isZero() == 1 {
			t.Fatal("zero blinding")
		}
		// Shares k = k1 + k2 with a derived mask, as in signing.
		kc := sk.canonical()
		m := derivedMaskLimbs(&seed, 'K', nil)
		var k2c limbs
		scalarN.sub(&k2c, &kc, &m)
		var k1, k2 scalar
		scalarN.toMont(&k1.v, &m)
		scalarN.toMont(&k2.v, &k2c)
		var want, got scalar
		want.inv(&sk)
		got.invMaskedShares(&k1, &k2, &rho)
		got.mul(&got, &rho) // (k·rho)^-1 · rho = k^-1
		if got != want {
			t.Fatalf("masked inverse differs for %x", k)
		}
	}
}

func TestDerivedBlinding(t *testing.T) {
	seed := [32]byte{3}
	a, pa := derivedBlinding(&seed, 'B', true, nil)
	b, _ := derivedBlinding(&seed, 'B', false, nil)
	c, _ := derivedBlinding(&seed, 'I', false, nil)
	if a != b || a == c || a.isZero() == 1 {
		t.Fatal("derived blinding must be deterministic, label-separated and non-zero")
	}
	var g, sum point
	g.scalarBaseMult(&a)
	sum.add(&g, &pa)
	if sum.isIdentity() != 1 {
		t.Fatal("derived point is not -s·G")
	}
}

// Signatures do not depend on the blinding value: refreshing it (also
// concurrently with signing) never changes Sign's output.
func TestRefreshBlindingKeepsSignaturesAndIsConcurrent(t *testing.T) {
	rng := rand.New(rand.NewSource(82))
	priv := testKey(t, rng)
	pub, _ := priv.PublicKey()
	digest := sha256.Sum256([]byte("blinding"))
	ref, _ := Sign(priv, digest)
	refB, _ := ref.Recoverable()
	if err := RefreshBlinding(failingReader{}); err == nil {
		t.Fatal("entropy failure not reported")
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if g == 0 {
					if err := RefreshBlinding(nil); err != nil {
						errs <- err.Error()
						return
					}
					continue
				}
				s, err := Sign(priv, digest)
				b, _ := s.Recoverable()
				if err != nil || !bytes.Equal(b[:], refB[:]) {
					errs <- "signature changed"
					return
				}
				p, _ := priv.PublicKey()
				if !p.Equal(pub) {
					errs <- "public key changed"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// Masked private keys: the shares are random (they differ between two
// parses of the same key), they always add up to d, and every operation
// returns the same result as before masking.
func TestPrivateKeyShares(t *testing.T) {
	rng := rand.New(rand.NewSource(83))
	for _, d := range interesting(rng, bigN, 200) {
		if d.Sign() == 0 {
			continue
		}
		b := to32(d)
		k1, err := ParsePrivateKey(b[:])
		if err != nil {
			t.Fatal(err)
		}
		k2, _ := ParsePrivateKey(b[:])
		if k1.d1 == k2.d1 {
			t.Fatal("mask is not random")
		}
		got, _ := k1.Bytes()
		if got != *b {
			t.Fatalf("shares do not recombine to %x", d)
		}
		var sum scalar
		sum.add(&k1.d1, &k1.d2)
		if sum != scalarFromBig(d) {
			t.Fatal("d1 + d2 != d")
		}
		p1, _ := k1.PublicKey()
		p2, _ := k2.PublicKey()
		var want point
		ds := scalarFromBig(d)
		want.scalarBaseMult(&ds)
		wp, _ := publicKeyFromPoint(&want)
		if !p1.Equal(wp) || !p2.Equal(wp) {
			t.Fatal("public key differs")
		}
		digest := sha256.Sum256(b[:])
		s1, _ := Sign(k1, digest)
		s2, _ := Sign(k2, digest)
		if s1 != s2 {
			t.Fatal("signature depends on the mask")
		}
	}
	// A derived mask is used when no randomness is available.
	var k PrivateKey
	c := limbs{5, 0, 0, 0}
	k.setShares(&c)
	if got := k.canonicalD(); got != c {
		t.Fatal("shares do not recombine")
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

// withRandomSource runs f with the package random source replaced and the
// process-wide blinding cleared, restoring both afterwards.
func withRandomSource(t *testing.T, r io.Reader, f func()) {
	t.Helper()
	oldSrc, oldBl := randomSource, blindingState.Load()
	randomSource = r
	blindingState.Store(nil)
	defer func() {
		randomSource = oldSrc
		blindingState.Store(oldBl)
	}()
	f()
}

// When randomness fails (an error) or is broken (only zeros, no error),
// nothing runs unblinded or unmasked, nothing hangs, and every result is
// unchanged.
func TestBlindingWithoutRandomness(t *testing.T) {
	rng := rand.New(rand.NewSource(84))
	ref := testKey(t, rng)
	db, _ := ref.Bytes()
	digest := sha256.Sum256([]byte("no randomness"))
	refSig, _ := Sign(ref, digest)
	refPub, _ := ref.PublicKey()

	for _, src := range []struct {
		name string
		r    io.Reader
	}{{"failing", failingReader{}}, {"zeros", zeroReader{}}} {
		withRandomSource(t, src.r, func() {
			// Process-wide blinding cannot be created: callers must use the
			// derived per-call blinding, never b = 0.
			if bl := currentBlinding(); bl != nil {
				t.Fatalf("%s: blinding created from a broken source", src.name)
			}
			if err := RefreshBlinding(nil); err == nil {
				t.Fatalf("%s: RefreshBlinding succeeded", src.name)
			}
			k, err := ParsePrivateKey(db[:])
			if err != nil {
				t.Fatal(err)
			}
			// The key is still masked: d1 is neither 0 nor d.
			var zero scalar
			ds := scalarFromBig(new(big.Int).SetBytes(db[:]))
			if k.d1 == zero || k.d1 == ds || k.d2 == ds {
				t.Fatalf("%s: private key stored unmasked", src.name)
			}
			sig, err := Sign(k, digest)
			if err != nil || sig != refSig {
				t.Fatalf("%s: signature changed", src.name)
			}
			pub, err := k.PublicKey()
			if err != nil || !pub.Equal(refPub) {
				t.Fatalf("%s: public key changed", src.name)
			}
		})
	}
	// A source that recovers: the process-wide blinding is created on the
	// next call (a transient failure does not disable it).
	withRandomSource(t, failingReader{}, func() {
		if currentBlinding() != nil {
			t.Fatal("blinding from failing source")
		}
		randomSource = cryptoRandReader()
		if currentBlinding() == nil {
			t.Fatal("blinding not created after the source recovered")
		}
	})
}

// RefreshBlinding with a broken caller-supplied source returns an error
// after a bounded number of draws instead of looping, and keeps the
// current blinding.
func TestRefreshBlindingBounded(t *testing.T) {
	before := currentBlinding()
	if err := RefreshBlinding(zeroReader{}); err == nil {
		t.Fatal("zero source accepted")
	}
	if currentBlinding() != before {
		t.Fatal("blinding replaced after an error")
	}
}

func cryptoRandReader() io.Reader { return cryptorand.Reader }

// countingReader returns a different byte pattern on every call and
// counts the bytes it delivered.
type countingReader struct{ calls, n int }

func (c *countingReader) Read(b []byte) (int, error) {
	c.calls++
	for i := range b {
		b[i] = byte(c.calls*131 + i)
	}
	c.n += len(b)
	return len(b), nil
}

// TestSignFreshMasks covers findings S-12 and S-13: every signature draws
// fresh random bytes that change the nonce shares, the inversion blinding
// and the re-randomised key shares, while the signature stays the
// deterministic RFC 6979 one; the stored key is not modified.
func TestSignFreshMasks(t *testing.T) {
	key, err := ParsePrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var digest [DigestSize]byte
	digest[0] = 7
	want, err := Sign(key, digest)
	if err != nil {
		t.Fatal(err)
	}
	d1, d2 := key.d1, key.d2
	cr := &countingReader{}
	withRandomSource(t, cr, func() {
		for i := 0; i < 4; i++ {
			before := cr.n
			got, err := Sign(key, digest)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatal("signature changed with the fresh randomness")
			}
			// 32 fresh bytes per signature (the process-wide blinding
			// may draw once more on first use).
			if cr.n-before < 32 {
				t.Fatalf("signature %d drew %d random bytes", i, cr.n-before)
			}
		}
	})
	if key.d1 != d1 || key.d2 != d2 {
		t.Fatal("Sign modified the stored key shares")
	}
	// Failing and all-zero sources: the masks fall back to K-derived
	// values; the signature is unchanged.
	for _, src := range []io.Reader{failingReader{}, zeroReader{}} {
		withRandomSource(t, src, func() {
			got, err := Sign(key, digest)
			if err != nil || got != want {
				t.Fatalf("signature changed with source %T", src)
			}
		})
	}
	// Different fresh bytes give different masks for the same K.
	var k, f1, f2 [32]byte
	k[0], f2[0] = 1, 1
	for _, label := range []byte{'K', 'D', 'Z', 'Y'} {
		a := derivedMaskLimbs(&k, label, &f1)
		b := derivedMaskLimbs(&k, label, &f2)
		c := derivedMaskLimbs(&k, label, nil)
		if a == b || a == c {
			t.Fatalf("mask %c does not depend on the fresh bytes", label)
		}
	}
	r1, _ := derivedBlinding(&k, 'I', false, &f1)
	r2, _ := derivedBlinding(&k, 'I', false, &f2)
	if r1.equal(&r2) == 1 {
		t.Fatal("rho does not depend on the fresh bytes")
	}
}

// TestKeyReconstructionHasNoMultiplication covers finding S-14: rebuilding
// d for RFC 6979 and Bytes must not multiply the fixed stored shares. The
// reconstruction path (canonicalD, dBytes, Bytes) may call no
// multiplication, squaring, inversion or Montgomery conversion, and the
// canonical and Montgomery shares must describe the same d.
func TestKeyReconstructionHasNoMultiplication(t *testing.T) {
	fset := token.NewFileSet()
	forbidden := map[string]bool{
		"mul": true, "square": true, "sqrN": true, "inv": true, "invFermat": true,
		"toMont": true, "fromMont": true, "canonical": true, "scalarMul": true,
		"scalarSqr": true, "mulWords": true, "montReduceN": true,
	}
	// Functions that handle the secret sum itself: the key reconstruction
	// (S-14) and the blinded fixed-base multiplication, whose input c1 +
	// c2 + b is formed and consumed without multiplications (S-15).
	targets := map[string][]string{
		"privatekey.go": {"canonicalD", "dBytes", "Bytes"},
		"blinding.go":   {"scalarBaseMultShares"},
		"point.go":      {"scalarBaseMultCanonical"},
	}
	checked := 0
	for file, names := range targets {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !slices.Contains(names, fn.Name.Name) {
				continue
			}
			checked++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch c := call.Fun.(type) {
				case *ast.Ident:
					name = c.Name
				case *ast.SelectorExpr:
					name = c.Sel.Name
				}
				if forbidden[name] {
					t.Errorf("%s: %s calls %s on a secret-sum path", fset.Position(call.Pos()), fn.Name.Name, name)
				}
				return true
			})
		}
	}
	if checked != 5 {
		t.Fatalf("checked %d of 5 functions", checked)
	}
	// The canonical shares and the Montgomery shares agree with d.
	for i := 0; i < 200; i++ {
		var b [32]byte
		if _, err := cryptorand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		k, err := ParsePrivateKey(b[:])
		if err != nil {
			continue
		}
		var m1, m2 limbs
		scalarN.toMont(&m1, &k.c1)
		scalarN.toMont(&m2, &k.c2)
		if m1 != k.d1.v || m2 != k.d2.v {
			t.Fatal("canonical and Montgomery shares differ")
		}
		if got, _ := k.Bytes(); got != b {
			t.Fatal("Bytes does not return the parsed key")
		}
		k.Zero()
		if k.c1 != (limbs{}) || k.c2 != (limbs{}) {
			t.Fatal("Zero leaves the canonical shares")
		}
	}
}
