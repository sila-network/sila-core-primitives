// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package gethcompare

// Parity tests for the transaction-layer behaviour required by the owner
// (PR #3): account addresses, raw recovery (ecrecover-style), the EIP-2
// strict versus recovery-compatible split, legacy and EIP-155 recovery
// values, and hedged nonces. References (test oracles only):
// go-ethereum v1.17.10 (crypto, core/types; libsecp256k1 via cgo) and
// decred secp256k1 v4.0.1.

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sila-network/sila-core-primitives/account"
	sila "github.com/sila-network/sila-core-primitives/secp256k1"
	"github.com/sila-network/sila-core-primitives/txsig"
)

var halfOrder = new(big.Int).Rsh(orderN, 1)

func fill32(v *big.Int) []byte {
	out := make([]byte, 32)
	if v.Sign() >= 0 && v.BitLen() <= 256 {
		v.FillBytes(out)
	}
	return out
}

// Address: last 20 bytes of Keccak-256(X || Y) == crypto.PubkeyToAddress.
func TestParityAddress(t *testing.T) {
	rng := rand.New(rand.NewSource(100))
	for i := 0; i < 1000; i++ {
		priv, kb, _ := randomKeyAndDigest(t, rng)
		pub, _ := priv.PublicKey()
		got, err := account.FromPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		gk, err := gethcrypto.ToECDSA(kb[:])
		if err != nil {
			t.Fatal(err)
		}
		if want := gethcrypto.PubkeyToAddress(gk.PublicKey); !bytes.Equal(got[:], want[:]) {
			t.Fatalf("case %d: address %x, go-ethereum %x", i, got, want)
		}
	}
}

// ecrecoverCases builds 65-byte inputs for raw recovery: valid low-S and
// high-S signatures with every v, small r (so that v = 2/3 can succeed),
// boundary r and s, and random bytes.
func ecrecoverCases(t *testing.T, rng *rand.Rand, n int) (digests [][32]byte, sigs [][]byte) {
	edges := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), halfOrder,
		new(big.Int).Add(halfOrder, big.NewInt(1)), new(big.Int).Sub(orderN, big.NewInt(1)),
		orderN, new(big.Int).Add(orderN, big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))}
	add := func(d [32]byte, sig []byte) {
		digests = append(digests, d)
		sigs = append(sigs, sig)
	}
	for i := 0; i < n; i++ {
		priv, _, d := randomKeyAndDigest(t, rng)
		sig, _ := sila.Sign(priv, d)
		rb, _ := sig.Recoverable()
		for v := byte(0); v < 6; v++ {
			b := append([]byte(nil), rb[:]...)
			b[64] = v
			add(d, b)
			h := append([]byte(nil), b...)
			s := new(big.Int).SetBytes(h[32:64])
			copy(h[32:64], fill32(new(big.Int).Sub(orderN, s)))
			add(d, h)
		}
		// Small r with every v (v = 2/3 succeeds when r + n < p and r + n
		// is an x-coordinate on the curve).
		small := make([]byte, 65)
		small[31] = byte(rng.Intn(255) + 1)
		rng.Read(small[32:64])
		small[32] &= 0x7f
		for v := byte(0); v < 4; v++ {
			b := append([]byte(nil), small...)
			b[64] = v
			add(d, b)
		}
		// Boundary r and s.
		r := edges[rng.Intn(len(edges))]
		s := edges[rng.Intn(len(edges))]
		b := make([]byte, 65)
		copy(b[:32], fill32(r))
		copy(b[32:64], fill32(s))
		b[64] = byte(rng.Intn(5))
		add(d, b)
		// Random bytes.
		rnd := make([]byte, 65)
		rng.Read(rnd)
		rnd[64] &= 3
		add(d, rnd)
	}
	return
}

// Generic raw recovery (secp256k1.ParseRecoverableSignatureAllowHighS +
// RecoverPublicKey, v in 0..3) == crypto.Ecrecover (libsecp256k1).
func TestParityRawRecovery(t *testing.T) {
	rng := rand.New(rand.NewSource(101))
	digests, sigs := ecrecoverCases(t, rng, 300)
	okCount, v23 := 0, 0
	for i := range sigs {
		want, gerr := gethcrypto.Ecrecover(digests[i][:], sigs[i])
		var got []byte
		sig, serr := sila.ParseRecoverableSignatureAllowHighS(sigs[i])
		if serr == nil {
			var pub sila.PublicKey
			pub, serr = sila.RecoverPublicKey(digests[i], sig)
			if serr == nil {
				u, _ := pub.Uncompressed()
				got = u[:]
			}
		}
		if (gerr == nil) != (serr == nil) {
			t.Fatalf("case %d (%x): go-ethereum err=%v, SILA err=%v", i, sigs[i], gerr, serr)
		}
		if gerr == nil {
			if !bytes.Equal(got, want) {
				t.Fatalf("case %d: recovered keys differ", i)
			}
			okCount++
			if sigs[i][64] >= 2 {
				v23++
			}
		}
	}
	t.Logf("%d inputs, %d recovered identically (%d with v = 2/3), the rest rejected by both", len(sigs), okCount, v23)
	if v23 == 0 {
		t.Fatal("no successful v = 2/3 recovery exercised")
	}
}

// Transaction-layer value checks == crypto.ValidateSignatureValues
// (homestead=true: Strict; homestead=false: RecoveryCompatible).
func TestParityValidateSignatureValues(t *testing.T) {
	rng := rand.New(rand.NewSource(102))
	one := big.NewInt(1)
	vals := []*big.Int{big.NewInt(0), one, halfOrder, new(big.Int).Add(halfOrder, one),
		new(big.Int).Sub(orderN, one), orderN, new(big.Int).Add(orderN, one),
		new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)}
	for i := 0; i < 64; i++ {
		var b [32]byte
		rng.Read(b[:])
		vals = append(vals, new(big.Int).SetBytes(b[:]))
	}
	n := 0
	for _, r := range vals {
		for _, s := range vals {
			for _, v := range []byte{0, 1, 2, 3, 27, 28} {
				var rb, sb [32]byte
				copy(rb[:], fill32(r))
				copy(sb[:], fill32(s))
				for _, c := range []struct {
					rule      txsig.Rule
					homestead bool
				}{{txsig.Strict, true}, {txsig.RecoveryCompatible, false}} {
					_, err := txsig.ParseValues(rb, sb, v, c.rule)
					if (err == nil) != gethcrypto.ValidateSignatureValues(v, r, s, c.homestead) {
						t.Fatalf("r=%x s=%x v=%d homestead=%v: SILA %v", r, s, v, c.homestead, err == nil)
					}
					n++
				}
			}
		}
	}
	t.Logf("%d (r, s, v, rule) combinations agree", n)
}

// Legacy (27/28) and EIP-155 values, end to end through go-ethereum's
// transaction signers: SILA signs the signer's hash, the encoded V matches
// SignatureValues, and go-ethereum recovers the SILA account address.
// High-S transactions are rejected by both.
func TestParityTransactionRecoveryValues(t *testing.T) {
	rng := rand.New(rand.NewSource(103))
	to := common.Address{1}
	for i := 0; i < 200; i++ {
		priv, _, _ := randomKeyAndDigest(t, rng)
		pub, _ := priv.PublicKey()
		addr, _ := account.FromPublicKey(pub)
		chainID := uint64(rng.Int63n(1<<40) + 1)
		if i%4 == 0 {
			chainID = 1
		}
		tx := types.NewTx(&types.LegacyTx{Nonce: uint64(i), To: &to, Value: big.NewInt(int64(i)), Gas: 21000, GasPrice: big.NewInt(1)})
		for _, signer := range []types.Signer{types.HomesteadSigner{}, types.NewEIP155Signer(new(big.Int).SetUint64(chainID))} {
			h := signer.Hash(tx)
			sig, err := sila.Sign(priv, h)
			if err != nil {
				t.Fatal(err)
			}
			v, _ := sig.RecoveryID()
			if v > 1 {
				t.Fatal("v >= 2 from Sign (probability 2^-127)")
			}
			rb, _ := sig.Recoverable()
			_, _, wantV, err := signer.SignatureValues(tx, rb[:])
			if err != nil {
				t.Fatal(err)
			}
			var gotV uint64
			if _, ok := signer.(types.HomesteadSigner); ok {
				lv, _ := txsig.LegacyV(v)
				gotV = uint64(lv)
			} else {
				gotV, _ = txsig.ChainV(v, chainID)
			}
			if !wantV.IsUint64() || wantV.Uint64() != gotV {
				t.Fatalf("V: go-ethereum %v, SILA %d", wantV, gotV)
			}
			signed, err := tx.WithSignature(signer, rb[:])
			if err != nil {
				t.Fatal(err)
			}
			from, err := types.Sender(signer, signed)
			if err != nil || !bytes.Equal(from[:], addr[:]) {
				t.Fatalf("go-ethereum sender %x, SILA address %x (%v)", from, addr, err)
			}
			// Decode go-ethereum's V back with SILA and recover the same key.
			rawV, rawR, rawS := signed.RawSignatureValues()
			var dv byte
			if _, ok := signer.(types.HomesteadSigner); ok {
				dv, err = txsig.FromLegacyV(byte(rawV.Uint64()))
			} else {
				dv, err = txsig.FromChainV(rawV.Uint64(), chainID)
			}
			if err != nil || dv != v {
				t.Fatal("recovery value does not decode")
			}
			var r32, s32 [32]byte
			rawR.FillBytes(r32[:])
			rawS.FillBytes(s32[:])
			rec, err := txsig.Recover(h, r32, s32, dv, txsig.Strict)
			if err != nil || !rec.Equal(pub) {
				t.Fatal("txsig.Recover differs")
			}
			// High-S form: rejected by go-ethereum's Sender (EIP-2) and by
			// txsig Strict; recovered by both in the recovery-compatible
			// context.
			hs := new(big.Int).Sub(orderN, rawS)
			hb := append([]byte(nil), rb[:]...)
			copy(hb[32:64], fill32(hs))
			hb[64] ^= 1
			hsigned, err := tx.WithSignature(signer, hb)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := types.Sender(signer, hsigned); err == nil {
				t.Fatal("go-ethereum accepted a high-S transaction")
			}
			var hs32 [32]byte
			hs.FillBytes(hs32[:])
			if _, err := txsig.Recover(h, r32, hs32, dv^1, txsig.Strict); err == nil {
				t.Fatal("txsig Strict accepted high-S")
			}
			gpub, gerr := gethcrypto.Ecrecover(h[:], hb)
			spub, serr := txsig.Recover(h, r32, hs32, dv^1, txsig.RecoveryCompatible)
			if gerr != nil || serr != nil {
				t.Fatal("recovery-compatible high-S recovery failed")
			}
			u, _ := spub.Uncompressed()
			if !bytes.Equal(gpub, u[:]) {
				t.Fatal("recovery-compatible high-S keys differ")
			}
		}
	}
}

// Hedged signing: the nonce of SignWithExtraEntropy equals decred's
// NonceRFC6979 with the same 32 bytes of extra data (the layout that
// libsecp256k1 also uses for its nonce-function data), checked through r.
// decred uses the unreduced digest, so digests are kept below n.
func TestParityHedgedNonce(t *testing.T) {
	rng := rand.New(rand.NewSource(104))
	for i := 0; i < 300; i++ {
		priv, kb, d := randomKeyAndDigest(t, rng)
		if new(big.Int).SetBytes(d[:]).Cmp(orderN) >= 0 {
			continue
		}
		var extra [32]byte
		rng.Read(extra[:])
		sig, err := sila.SignWithExtraEntropy(priv, d, extra)
		if err != nil {
			t.Fatal(err)
		}
		k := secp256k1.NonceRFC6979(kb[:], d[:], extra[:], nil, 0)
		var R secp256k1.JacobianPoint
		secp256k1.ScalarBaseMultNonConst(k, &R)
		R.ToAffine()
		var x [32]byte
		R.X.PutBytesUnchecked(x[:])
		r := new(big.Int).Mod(new(big.Int).SetBytes(x[:]), orderN)
		sr := sig.R()
		if r.Cmp(new(big.Int).SetBytes(sr[:])) != 0 {
			t.Fatalf("case %d: hedged nonce differs from decred NonceRFC6979", i)
		}
	}
}

// Private-key validation == crypto.ToECDSA (strict 32-byte form, 1 <= d < n).
func TestParityPrivateKeyValidation(t *testing.T) {
	rng := rand.New(rand.NewSource(105))
	one := big.NewInt(1)
	var inputs [][]byte
	for _, v := range []*big.Int{big.NewInt(0), one, big.NewInt(2), halfOrder, new(big.Int).Sub(orderN, one),
		orderN, new(big.Int).Add(orderN, one), new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)} {
		inputs = append(inputs, fill32(v))
	}
	for i := 0; i < 2000; i++ {
		b := make([]byte, 32)
		rng.Read(b)
		if i%4 == 0 {
			for j := 0; j < 16; j++ {
				b[j] = 0xff // near or above n
			}
		}
		inputs = append(inputs, b)
	}
	inputs = append(inputs, nil, make([]byte, 31), append(fill32(one), 0), append([]byte{0}, fill32(one)...))
	for _, in := range inputs {
		_, gerr := gethcrypto.ToECDSA(in)
		_, serr := sila.ParsePrivateKey(in)
		if (gerr == nil) != (serr == nil) {
			t.Fatalf("%x: go-ethereum err=%v, SILA err=%v", in, gerr, serr)
		}
	}
}

// Public-key derivation and encodings == crypto.FromECDSAPub and
// crypto.CompressPubkey; parsing == crypto.UnmarshalPubkey (65 bytes) and
// crypto.DecompressPubkey (33 bytes) on valid, corrupted, off-curve,
// out-of-range and wrong-prefix inputs.
func TestParityPublicKeys(t *testing.T) {
	rng := rand.New(rand.NewSource(106))
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	var inputs [][]byte
	for i := 0; i < 500; i++ {
		priv, kb, _ := randomKeyAndDigest(t, rng)
		pub, _ := priv.PublicKey()
		u, _ := pub.Uncompressed()
		c, _ := pub.Compressed()
		gk, _ := gethcrypto.ToECDSA(kb[:])
		if !bytes.Equal(u[:], gethcrypto.FromECDSAPub(&gk.PublicKey)) || !bytes.Equal(c[:], gethcrypto.CompressPubkey(&gk.PublicKey)) {
			t.Fatalf("public key encodings differ for case %d", i)
		}
		inputs = append(inputs, u[:], c[:])
		// Prefix variants, a flipped bit, coordinates moved out of range.
		for _, pre := range []byte{0, 1, 2, 3, 4, 5, 6, 7} {
			v := append([]byte(nil), u[:]...)
			v[0] = pre
			inputs = append(inputs, v)
			w := append([]byte(nil), c[:]...)
			w[0] = pre
			inputs = append(inputs, w)
		}
		f := append([]byte(nil), u[:]...)
		f[1+rng.Intn(64)] ^= 1 << uint(rng.Intn(8))
		inputs = append(inputs, f)
		x := new(big.Int).SetBytes(u[1:33])
		if xp := new(big.Int).Add(x, p); xp.BitLen() <= 256 {
			o := append([]byte(nil), u[:]...)
			copy(o[1:33], fill32(xp))
			inputs = append(inputs, o)
			oc := append([]byte(nil), c[:]...)
			copy(oc[1:33], fill32(xp))
			inputs = append(inputs, oc)
		}
		y := new(big.Int).SetBytes(u[33:65])
		if yp := new(big.Int).Add(y, p); yp.BitLen() <= 256 {
			o := append([]byte(nil), u[:]...)
			copy(o[33:65], fill32(yp))
			inputs = append(inputs, o)
		}
	}
	for i := 0; i < 500; i++ {
		r := make([]byte, 33)
		rng.Read(r[1:])
		r[0] = 2 + byte(i&1)
		inputs = append(inputs, r) // random x: on the curve about half the time
	}
	inputs = append(inputs, []byte{0}, make([]byte, 65), make([]byte, 33))
	accepted := 0
	for _, in := range inputs {
		var gok bool
		switch len(in) {
		case 65:
			_, err := gethcrypto.UnmarshalPubkey(in)
			gok = err == nil
		case 33:
			_, err := gethcrypto.DecompressPubkey(in)
			gok = err == nil
		}
		k, err := sila.ParsePublicKey(in)
		if gok != (err == nil) {
			t.Fatalf("%x: go-ethereum %v, SILA %v", in, gok, err == nil)
		}
		if gok {
			accepted++
			// Both decode to the same point.
			var gx, gy *big.Int
			if len(in) == 65 {
				gp, _ := gethcrypto.UnmarshalPubkey(in)
				gx, gy = gp.X, gp.Y
			} else {
				gp, _ := gethcrypto.DecompressPubkey(in)
				gx, gy = gp.X, gp.Y
			}
			sx, sy, _ := k.Coordinates()
			if gx.Cmp(new(big.Int).SetBytes(sx[:])) != 0 || gy.Cmp(new(big.Int).SetBytes(sy[:])) != 0 {
				t.Fatalf("%x decodes to different points", in)
			}
		}
	}
	t.Logf("%d inputs, %d accepted by both, the rest rejected by both", len(inputs), accepted)
}
