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
func crop(x []float64, keep float64) []float64 {
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
	best := 0.0
	for _, keep := range []float64{0.5, 0.75, 0.9} {
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
	loadScalar := func(k *scalar) {
		in = *k
		c := k.canonical()
		key.setShares(&c) // fresh random shares, as ParsePrivateKey does
		idx++
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
		{"blinded inverse", false, func() { sinkS.invBlinded(&in, &rhos[idx&255]) }},
		{"blinded k·G", false, func() { sink.scalarBaseMultBlinded(&in, nil) }},
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
			pair := func(x, y []scalar) func(class, i int) {
				return func(class, i int) {
					if class == 0 {
						loadScalar(&x[i%256])
					} else {
						loadScalar(&y[i%256])
					}
				}
			}
			ts = append(ts, measureClassesSigned(samples, pair(a, b), op.run))
			cs = append(cs, measureClassesSigned(samples, pair(c, b), op.run))
		}
		minT, sameSign := minAbs(ts), sameSigns(ts)
		kind := "production"
		if op.diagnostic {
			kind = "diagnostic"
		}
		t.Logf("%-22s [%s] t %s; control t %s (bound 4.5, %d runs)", op.name, kind, fmtTs(ts), fmtTs(cs), reps)
		if !op.diagnostic && minT > 4.5 && sameSign {
			t.Errorf("%s: consistent timing difference between secret classes, min |t| = %.2f (control %s)", op.name, minT, fmtTs(cs))
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
