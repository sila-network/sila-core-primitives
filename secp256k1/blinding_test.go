// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"math/rand"
	"sync"
	"testing"
)

// The blinded computations return exactly the unblinded results for edge
// and random scalars, including k + b = 0 and k = 0.
func TestBlindedBaseMultMatchesPlain(t *testing.T) {
	rng := rand.New(rand.NewSource(80))
	bl := currentBlinding()
	if bl == nil {
		t.Fatal("no process-wide blinding")
	}
	var negb scalar
	negb.neg(&bl.b)
	ks := []scalar{negb, scalarFromBig(big.NewInt(0)), scalarFromBig(big.NewInt(1)),
		scalarFromBig(new(big.Int).Sub(bigN, big.NewInt(1)))}
	for _, k := range interesting(rng, bigN, 300) {
		ks = append(ks, scalarFromBig(k))
	}
	seed := [32]byte{9}
	fb, fnegB := derivedBlinding(&seed, 'B', true)
	for i := range ks {
		var want, got, got2 point
		want.scalarBaseMult(&ks[i])
		got.scalarBaseMultBlinded(&ks[i], nil)
		got2.scalarBaseMultWith(&ks[i], &fb, &fnegB) // fallback path
		if got.equal(&want) != 1 || got2.equal(&want) != 1 {
			t.Fatalf("blinded k·G differs for case %d", i)
		}
	}
	// Fallback for -b of the derived blinding: (k + b) = 0.
	var negfb scalar
	negfb.neg(&fb)
	var want, got point
	want.scalarBaseMult(&negfb)
	got.scalarBaseMultWith(&negfb, &fb, &fnegB)
	if got.equal(&want) != 1 {
		t.Fatal("k + b = 0 case")
	}
}

func TestBlindedInverseMatchesPlain(t *testing.T) {
	rng := rand.New(rand.NewSource(81))
	seed := [32]byte{1}
	for i, k := range interesting(rng, bigN, 300) {
		sk := scalarFromBig(k)
		seed[1] = byte(i)
		rho, _ := derivedBlinding(&seed, 'I', false)
		if rho.isZero() == 1 {
			t.Fatal("zero blinding")
		}
		// Shares k = k1 + k2 with a derived mask, as in signing.
		kc := sk.canonical()
		m := derivedMaskLimbs(&seed, 'K')
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
	a, pa := derivedBlinding(&seed, 'B', true)
	b, _ := derivedBlinding(&seed, 'B', false)
	c, _ := derivedBlinding(&seed, 'I', false)
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
