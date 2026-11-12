// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math"
	"math/big"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Statistical timing check in the style of "dudect" (Reparaz, Balasch,
// Verbauwhede, 2017): measure an operation for two classes of secret
// inputs, interleaved in random order, and compute Welch's t statistic on
// the cropped samples. |t| > 4.5 is the customary "leak detected" bound;
// here it must hold in every one of several repetitions.
//
// This is evidence, not proof: it can only detect leaks that show up in
// wall-clock time on the machine running it. It is opt-in
// (SILA_TIMING_TEST=1) because shared CI machines are too noisy.

func welchT(a, b []float64) float64 {
	mean := func(x []float64) float64 {
		s := 0.0
		for _, v := range x {
			s += v
		}
		return s / float64(len(x))
	}
	variance := func(x []float64, m float64) float64 {
		s := 0.0
		for _, v := range x {
			s += (v - m) * (v - m)
		}
		return s / float64(len(x)-1)
	}
	ma, mb := mean(a), mean(b)
	va, vb := variance(a, ma), variance(b, mb)
	return (ma - mb) / math.Sqrt(va/float64(len(a))+vb/float64(len(b)))
}

// crop removes the slowest samples (interrupts, preemption), as dudect does.
// keep >= 1 returns all samples.
func crop(x []float64, keep float64) []float64 {
	if keep >= 1 {
		return append([]float64(nil), x...)
	}
	s := append([]float64(nil), x...)
	sort.Float64s(s)
	limit := s[int(float64(len(s))*keep)]
	out := x[:0:0]
	for _, v := range x {
		if v <= limit {
			out = append(out, v)
		}
	}
	return out
}

// measureClassesSigned returns the Welch t statistic with the largest
// magnitude over the cropping levels, keeping its sign (a's mean minus b's).
func measureClassesSigned(samples int, load func(class, i int), run func()) float64 {
	a, b := sampleClasses(samples, load, run)
	return maxAbsWelch(a, b)
}

// maxAbsWelch returns the Welch t statistic with the largest magnitude
// over the cropping levels, including the uncropped samples (a leak that
// only affects the slowest observations of one class is removed by every
// crop; TestTimingDetectorTailLeak is the negative control).
func maxAbsWelch(a, b []float64) float64 {
	best := 0.0
	for _, keep := range []float64{0.5, 0.75, 0.9, 1} {
		tv := welchT(crop(a, keep), crop(b, keep))
		if math.Abs(tv) > math.Abs(best) {
			best = tv
		}
	}
	return best
}

func minAbs(ts []float64) float64 {
	m := math.Inf(1)
	for _, v := range ts {
		m = math.Min(m, math.Abs(v))
	}
	return m
}

// countAbove returns how many values exceed bound in magnitude.
func countAbove(ts []float64, bound float64) int {
	n := 0
	for _, v := range ts {
		if math.Abs(v) > bound {
			n++
		}
	}
	return n
}

func sameSigns(ts []float64) bool {
	for _, v := range ts {
		if (v > 0) != (ts[0] > 0) {
			return false
		}
	}
	return true
}

func fmtTs(ts []float64) string {
	out := "["
	for i, v := range ts {
		if i > 0 {
			out += " "
		}
		out += strconv.FormatFloat(v, 'f', 2, 64)
	}
	return out + "]"
}

// sampleClasses interleaves the two classes at random. For each sample,
// load (not timed) copies the class's secret into the fixed input
// variable, then run (timed) executes the operation on it. Keeping the
// copy out of the timed region removes any effect of where each class's
// values are stored in memory.
func sampleClasses(samples int, load func(class, i int), run func()) (a, b []float64) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < samples; i++ {
		class := rng.Intn(2)
		load(class, i)
		start := time.Now()
		run()
		d := float64(time.Since(start).Nanoseconds())
		if class == 0 {
			a = append(a, d)
		} else {
			b = append(b, d)
		}
	}
	return a, b
}

func TestConstantTimeStatistical(t *testing.T) {
	if os.Getenv("SILA_TIMING_TEST") != "1" {
		t.Skip("set SILA_TIMING_TEST=1 to run (needs a quiet machine)")
	}
	samples := 20000
	if v, err := strconv.Atoi(os.Getenv("SILA_TIMING_SAMPLES")); err == nil && v > 0 {
		samples = v
	}
	reps := 3
	if v, err := strconv.Atoi(os.Getenv("SILA_TIMING_REPS")); err == nil && v > 0 {
		reps = v
	}

	// Every call reads its secret from the same fixed variable (in, key),
	// so all classes use the same memory addresses: only the secret value
	// differs. Fresh secret sets are drawn for every repetition.
	//
	// Diagnostics measure the raw building blocks (to locate a root cause)
	// and are only reported. The production paths (blinded inversion,
	// blinded k·G, Sign, PublicKey) must not show a consistent difference.
	var in scalar
	key := &PrivateKey{valid: true}
	var sink point
	var sinkS scalar
	var sinkF fieldElement
	var sinkP PublicKey
	digest := [32]byte{7}
	brng := rand.New(rand.NewSource(99))
	var ys [64]fieldElement
	var ysc [64]scalar
	var rhos [256]scalar
	for i := range ys {
		ys[i] = fieldFromRand(brng)
		ysc[i] = scalarFromBig(new(big.Int).SetBytes(randBytes(brng)))
	}
	for i := range rhos {
		rhos[i] = scalarFromBig(new(big.Int).Add(big.NewInt(1), new(big.Int).Mod(new(big.Int).SetBytes(randBytes(brng)), new(big.Int).Sub(bigN, big.NewInt(1)))))
	}
	idx := 0
	// load copies the secret into the fixed inputs (untimed); run is timed.
	var in1, in2 scalar  // shares of in (k = in1 + in2), as in signing
	var in1c, in2c limbs // the same shares in canonical form (k·G)
	var lam fieldElement // projective randomiser of k·G
	// Keys are parsed once per secret set (setShares, as ParsePrivateKey)
	// and then reused for every sample of that secret, as a long-lived key
	// is in production: the timed Sign re-randomises its shares itself.
	// The selected key is copied (untimed) into the one fixed PrivateKey
	// the timed code reads, so both classes use the same address.
	loadScalar := func(k *scalar, kp *PrivateKey) {
		in = *k
		in1 = rhos[(idx+128)&255]
		in2.sub(k, &in1)
		in1c, in2c = in1.canonical(), in2.canonical()
		lam = ys[(idx*7)&63]
		*key = *kp
		idx++
	}
	mkKeys := func(x []scalar) []PrivateKey {
		ks := make([]PrivateKey, len(x))
		for i := range x {
			c := x[i].canonical()
			ks[i].valid = true
			ks[i].setShares(&c)
		}
		return ks
	}
	ops := []struct {
		name       string
		diagnostic bool
		run        func()
	}{
		{"diag: timer only", true, func() {}},
		{"diag: field mul x64", true, func() {
			x := fieldElement{v: in.v} // Montgomery limbs of the secret
			for i := range ys {
				sinkF.mul(&x, &ys[i])
			}
		}},
		{"diag: scalar mul x64", true, func() {
			for i := range ysc {
				sinkS.mul(&in, &ysc[i])
			}
		}},
		{"diag: raw inverse", true, func() { sinkS.inv(&in) }},
		{"diag: raw k·G", true, func() { sink.scalarBaseMult(&in) }},
		{"masked inverse", false, func() { sinkS.invMaskedShares(&in1, &in2, &rhos[idx&255]) }},
		{"masked k·G", false, func() { sink.scalarBaseMultShares(&in1c, &in2c, &lam, nil) }},
		{"Sign", false, func() { Sign(key, digest) }},
		{"PublicKey", false, func() { sinkP, _ = key.PublicKey() }},
	}
	only := os.Getenv("SILA_TIMING_ONLY") // optional substring filter
	seed := time.Now().UnixNano()
	for _, op := range ops {
		if only != "" && !strings.Contains(op.name, only) {
			continue
		}
		if op.diagnostic && os.Getenv("SILA_TIMING_PRODUCTION_ONLY") == "1" {
			continue
		}
		var ts, cs []float64
		for r := 0; r < reps; r++ {
			rng := rand.New(rand.NewSource(seed + int64(r)))
			// a: tiny secrets (1..255); b, c: uniformly random secrets.
			a, b, c := make([]scalar, 256), make([]scalar, 256), make([]scalar, 256)
			for i := range a {
				a[i] = scalarFromBig(big.NewInt(int64(rng.Intn(255) + 1)))
				b[i] = scalarFromBig(new(big.Int).Mod(new(big.Int).SetBytes(randBytes(rng)), bigN))
				c[i] = scalarFromBig(new(big.Int).Mod(new(big.Int).SetBytes(randBytes(rng)), bigN))
			}
			ka, kb, kc := mkKeys(a), mkKeys(b), mkKeys(c)
			keysOf := map[*scalar][]PrivateKey{&a[0]: ka, &b[0]: kb, &c[0]: kc}
			pair := func(x, y []scalar) func(class, i int) {
				kx, ky := keysOf[&x[0]], keysOf[&y[0]]
				return func(class, i int) {
					if class == 0 {
						loadScalar(&x[i%256], &kx[i%256])
					} else {
						loadScalar(&y[i%256], &ky[i%256])
					}
				}
			}
			// Counterbalanced: each comparison is measured in both class
			// orders. A positional bias of the harness (the first class of a
			// pair consistently slower or faster, seen on some runners in
			// both the tests and the random-vs-random controls) has the same
			// sign in both orders and cancels in the half-difference; a real
			// value-dependent difference changes sign and is kept.
			ts = append(ts, (measureClassesSigned(samples, pair(a, b), op.run)-
				measureClassesSigned(samples, pair(b, a), op.run))/2)
			cs = append(cs, (measureClassesSigned(samples, pair(c, b), op.run)-
				measureClassesSigned(samples, pair(b, c), op.run))/2)
		}
		minT, sameSign := minAbs(ts), sameSigns(ts)
		kind := "production"
		if op.diagnostic {
			kind = "diagnostic"
		}
		t.Logf("%-22s [%s] t %s; control t %s (bound 4.5, %d runs)", op.name, kind, fmtTs(ts), fmtTs(cs), reps)
		if op.diagnostic {
			continue
		}
		// Verdict per production path (docs/SECP256K1-DEDICATED-TIMING.md
		// §4): the control must stay within the bound in all but at most
		// one run in ten; otherwise the machine is too noisy and the
		// result does not count.
		leak := minT > 4.5 && sameSign
		noisy := countAbove(cs, 4.5) > reps/10
		verdict := "pass"
		switch {
		case leak && noisy:
			verdict = "INCONCLUSIVE (test and control both beyond the bound; repeat after preparation)"
		case leak:
			verdict = "FAIL (secret-dependent timing difference)"
		case noisy:
			verdict = "NOISY (control beyond the bound; the result does not count)"
		case os.Getenv("SILA_TIMING_REQUIRE_QUIET") == "1" && (samples < 1000000 || reps < 10):
			verdict = "TRIAL (below the required 1,000,000 samples x 10 runs; does not count)"
		}
		t.Logf("%-22s verdict: %s", op.name, verdict)
		if leak {
			t.Errorf("%s: consistent timing difference between secret classes, min |t| = %.2f (control %s)", op.name, minT, fmtTs(cs))
		}
		if noisy && os.Getenv("SILA_TIMING_REQUIRE_QUIET") == "1" {
			// Dedicated-hardware mode: a noisy machine must not produce a
			// passing run.
			t.Errorf("%s: machine too noisy, control t %s; the result does not count", op.name, fmtTs(cs))
		}
	}
	_ = sink
	_ = sinkS
	_ = sinkF
	_ = sinkP
}

func randBytes(rng *rand.Rand) []byte {
	b := make([]byte, 32)
	rng.Read(b)
	return b
}

func fieldFromRand(rng *rand.Rand) fieldElement {
	for {
		var b [32]byte
		rng.Read(b[:])
		var f fieldElement
		if f.setBytes(&b) == 1 {
			return f
		}
	}
}

// TestTimingDetectorTailLeak is a negative control for the detector: two
// classes with the same baseline distribution, where 5 % of one class's
// observations are slow. Every crop removes the slow tail; the uncropped
// comparison must still report the difference.
func TestTimingDetectorTailLeak(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	const n = 10000
	a, b := make([]float64, n), make([]float64, n)
	for i := 0; i < n; i++ {
		a[i] = 1000 + rng.NormFloat64()*10
		b[i] = 1000 + rng.NormFloat64()*10
		if i%20 == 0 {
			a[i] += 300 // the leaking minority
		}
	}
	for _, keep := range []float64{0.5, 0.75, 0.9} {
		if v := math.Abs(welchT(crop(a, keep), crop(b, keep))); v > 4.5 {
			t.Logf("crop %.2f alone detects it (t = %.2f)", keep, v)
		}
	}
	if v := math.Abs(maxAbsWelch(a, b)); v <= 4.5 {
		t.Fatalf("tail-only leak not detected: |t| = %.2f", v)
	}
	// Identical distributions stay below the bound.
	c := make([]float64, n)
	for i := range c {
		c[i] = 1000 + rng.NormFloat64()*10
	}
	if v := math.Abs(maxAbsWelch(c, b)); v > 4.5 {
		t.Fatalf("false positive on identical distributions: |t| = %.2f", v)
	}
}
