// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math"
	"math/big"
	"math/rand"
	"os"
	"sort"
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

func measureClasses(t *testing.T, samples int, classA, classB func(i int) func()) float64 {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var a, b []float64
	for i := 0; i < samples; i++ {
		useA := rng.Intn(2) == 0
		var f func()
		if useA {
			f = classA(i)
		} else {
			f = classB(i)
		}
		start := time.Now()
		f()
		d := float64(time.Since(start).Nanoseconds())
		if useA {
			a = append(a, d)
		} else {
			b = append(b, d)
		}
	}
	worst := 0.0
	for _, keep := range []float64{0.5, 0.75, 0.9} {
		tv := math.Abs(welchT(crop(a, keep), crop(b, keep)))
		if tv > worst {
			worst = tv
		}
	}
	return worst
}

func TestConstantTimeStatistical(t *testing.T) {
	if os.Getenv("SILA_TIMING_TEST") != "1" {
		t.Skip("set SILA_TIMING_TEST=1 to run (needs a quiet machine)")
	}
	const samples = 20000
	rng := rand.New(rand.NewSource(17))

	// Class A: tiny secrets (1..255, mostly zero bits and windows).
	// Class B: uniformly random full-size secrets.
	small := make([]scalar, 256)
	random := make([]scalar, 256)
	keysSmall := make([]*PrivateKey, 256)
	keysRandom := make([]*PrivateKey, 256)
	for i := range small {
		small[i] = scalarFromBig(big.NewInt(int64(i%255 + 1)))
		var buf [32]byte
		rng.Read(buf[:])
		random[i] = scalarFromBig(new(big.Int).SetBytes(buf[:]))
		keysSmall[i] = &PrivateKey{d: small[i], valid: true}
		keysRandom[i] = &PrivateKey{d: random[i], valid: true}
	}
	var sink point
	var sinkS scalar
	digest := [32]byte{7}
	checks := []struct {
		name string
		a, b func(i int) func()
	}{
		{"scalarBaseMult",
			func(i int) func() { return func() { sink.scalarBaseMult(&small[i%256]) } },
			func(i int) func() { return func() { sink.scalarBaseMult(&random[i%256]) } }},
		{"scalarMult",
			func(i int) func() { return func() { sink.scalarMult(&small[i%256], &generator) } },
			func(i int) func() { return func() { sink.scalarMult(&random[i%256], &generator) } }},
		{"scalar inverse",
			func(i int) func() { return func() { sinkS.inv(&small[i%256]) } },
			func(i int) func() { return func() { sinkS.inv(&random[i%256]) } }},
		{"Sign",
			func(i int) func() { return func() { Sign(keysSmall[i%256], digest) } },
			func(i int) func() { return func() { Sign(keysRandom[i%256], digest) } }},
	}
	// A real data-dependent timing difference shows up in every
	// repetition; scheduler and frequency noise on a shared machine does
	// not (a random-vs-random control reached |t| = 3.6 here). So a leak
	// is reported only if all repetitions exceed the bound.
	const reps = 3
	for _, c := range checks {
		minT, maxT := math.Inf(1), 0.0
		for r := 0; r < reps; r++ {
			tv := measureClasses(t, samples, c.a, c.b)
			minT, maxT = math.Min(minT, tv), math.Max(maxT, tv)
		}
		t.Logf("%-15s |t| min %.2f max %.2f over %d runs (bound 4.5)", c.name, minT, maxT, reps)
		if minT > 4.5 {
			t.Errorf("%s: consistent timing difference between secret classes, min |t| = %.2f", c.name, minT)
		}
	}
	_ = sink
	_ = sinkS
}
