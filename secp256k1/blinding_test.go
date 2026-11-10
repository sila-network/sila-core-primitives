// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"bytes"
	"crypto/sha256"
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
		var want, got scalar
		want.inv(&sk)
		got.invBlinded(&sk, &rho)
		if got != want {
			t.Fatalf("blinded inverse differs for %x", k)
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
