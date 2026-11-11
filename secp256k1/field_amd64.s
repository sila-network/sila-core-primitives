// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build amd64 && !purego

#include "textflag.h"

// Field multiplication and squaring modulo p = 2^256 - 2^32 - 977 for
// amd64. Same algorithm as the portable Go code (field_mul.go,
// reduceWords and fieldCorrect in field.go): the 512-bit product is formed
// row by row, folded twice with 2^256 ≡ 0x1000003D1, and conditionally
// corrected below p.
//
// Two implementations:
//   - fieldMulADX / fieldSqrADX use MULX (BMI2) and the two independent
//     carry chains of ADCX/ADOX (ADX), on CPUs that have both (Intel
//     since Broadwell, AMD since Zen);
//   - fieldMulMULQ / fieldSqrMULQ run on every x86-64 CPU (MOVQ, MULQ,
//     ADDQ, ADCQ, SBBQ, ANDQ, CMOVQCS only; the square is the product
//     with y = x).
// fieldMul and fieldSqr select one with a single comparison of useADX, a
// constant set once at start-up from CPUID (never from data).
//
// Constant time: straight-line code, no conditional branch (checked on the
// compiled binary by TestCompiledConstantTimeFunctions), no memory access
// at a data-dependent address; the final selection uses CMOVQCS. MULQ,
// ADDQ/ADCQ and CMOVQ have data-independent timing on x86 processors with
// DOIT (and in practice on the others; see docs/SECP256K1-SECURITY-REVIEW.md).
//
// Registers: R8..R15 hold the eight product words t0..t7; AX/DX are the
// MULQ operands; BX carries; CX holds a word of x (and later the
// constant c = 0x1000003D1); SI = x, DI = y. Every output word is written
// only after all input words have been read, so z may alias x or y.

#define t0 R8
#define t1 R9
#define t2 R10
#define t3 R11
#define t4 R12
#define t5 R13
#define t6 R14
#define t7 R15


// REDUCE_ADX reduces the product t0..t7 modulo p and stores it at z.
#define REDUCE_ADX \
MOVQ $0x1000003D1, DX \
XORQ CX, CX \
MULXQ t4, AX, BX; ADCXQ AX, t0; ADOXQ BX, t1 \
MULXQ t5, AX, BX; ADCXQ AX, t1; ADOXQ BX, t2 \
MULXQ t6, AX, BX; ADCXQ AX, t2; ADOXQ BX, t3 \
MULXQ t7, AX, t4; ADCXQ AX, t3; ADOXQ CX, t4; ADCXQ CX, t4 \
MULXQ t4, AX, BX \
ADDQ AX, t0; ADCQ BX, t1; ADCQ $0, t2; ADCQ $0, t3 \
SBBQ BX, BX; ANDQ DX, BX \
ADDQ BX, t0; ADCQ $0, t1; ADCQ $0, t2; ADCQ $0, t3 \
MOVQ t0, t4; MOVQ t1, t5; MOVQ t2, t6; MOVQ t3, t7 \
ADDQ DX, t4; ADCQ $0, t5; ADCQ $0, t6; ADCQ $0, t7 \
CMOVQCS t4, t0; CMOVQCS t5, t1; CMOVQCS t6, t2; CMOVQCS t7, t3 \
MOVQ z+0(FP), DI \
MOVQ t0, 0(DI); MOVQ t1, 8(DI); MOVQ t2, 16(DI); MOVQ t3, 24(DI) \
	RET

// func fieldMulMULQ(z, x, y *limbs)
TEXT ·fieldMulMULQ(SB), NOSPLIT, $0-24
	MOVQ x+8(FP), SI
	MOVQ y+16(FP), DI
	// row 0: t0..t4 = x0·y
	MOVQ 0(SI), CX
	MOVQ CX, AX; MULQ 0(DI); MOVQ AX, t0; MOVQ DX, t1
	MOVQ CX, AX; MULQ 8(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, t2
	MOVQ CX, AX; MULQ 16(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, t3
	MOVQ CX, AX; MULQ 24(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, t4
	// row 1: t1..t5 += x1·y
	MOVQ 8(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, t5
	// row 2: t2..t6 += x2·y
	MOVQ 16(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, t6
	// row 3: t3..t7 += x3·y
	MOVQ 24(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t6; ADCQ $0, DX; MOVQ DX, t7
	// First fold: (t0..t3) += (t4..t7)·c; the top word r4 < 2^34 ends in DX.
	MOVQ $0x1000003D1, CX
	MOVQ t4, AX; MULQ CX; ADDQ AX, t0; ADCQ $0, DX; MOVQ DX, BX
	MOVQ t5, AX; MULQ CX; ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, BX
	MOVQ t6, AX; MULQ CX; ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ t7, AX; MULQ CX; ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX

	// Second fold: (t0..t3) += r4·c (< 2^68).
	MOVQ DX, AX; MULQ CX
	ADDQ AX, t0; ADCQ DX, t1; ADCQ $0, t2; ADCQ $0, t3

	// A carry out is worth 2^256 ≡ c; the sum is then small and cannot
	// carry again. BX = c if carry else 0 (SBBQ/ANDQ, no branch).
	SBBQ BX, BX; ANDQ CX, BX
	ADDQ BX, t0; ADCQ $0, t1; ADCQ $0, t2; ADCQ $0, t3

	// Final correction (value < 2p): t - p = t + c mod 2^256, taken
	// exactly when t + c carries.
	MOVQ t0, t4; MOVQ t1, t5; MOVQ t2, t6; MOVQ t3, t7
	ADDQ CX, t4; ADCQ $0, t5; ADCQ $0, t6; ADCQ $0, t7
	CMOVQCS t4, t0; CMOVQCS t5, t1; CMOVQCS t6, t2; CMOVQCS t7, t3

	MOVQ z+0(FP), DI
	MOVQ t0, 0(DI); MOVQ t1, 8(DI); MOVQ t2, 16(DI); MOVQ t3, 24(DI)
	RET

// func fieldSqrMULQ(z, x *limbs): fieldMulMULQ with y = x.
TEXT ·fieldSqrMULQ(SB), NOSPLIT, $0-16
	MOVQ x+8(FP), SI
	MOVQ SI, DI
	// row 0: t0..t4 = x0·y
	MOVQ 0(SI), CX
	MOVQ CX, AX; MULQ 0(DI); MOVQ AX, t0; MOVQ DX, t1
	MOVQ CX, AX; MULQ 8(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, t2
	MOVQ CX, AX; MULQ 16(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, t3
	MOVQ CX, AX; MULQ 24(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, t4
	// row 1: t1..t5 += x1·y
	MOVQ 8(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, t5
	// row 2: t2..t6 += x2·y
	MOVQ 16(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, t6
	// row 3: t3..t7 += x3·y
	MOVQ 24(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t6; ADCQ $0, DX; MOVQ DX, t7
	// First fold: (t0..t3) += (t4..t7)·c; the top word r4 < 2^34 ends in DX.
	MOVQ $0x1000003D1, CX
	MOVQ t4, AX; MULQ CX; ADDQ AX, t0; ADCQ $0, DX; MOVQ DX, BX
	MOVQ t5, AX; MULQ CX; ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, BX
	MOVQ t6, AX; MULQ CX; ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ t7, AX; MULQ CX; ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX

	// Second fold: (t0..t3) += r4·c (< 2^68).
	MOVQ DX, AX; MULQ CX
	ADDQ AX, t0; ADCQ DX, t1; ADCQ $0, t2; ADCQ $0, t3

	// A carry out is worth 2^256 ≡ c; the sum is then small and cannot
	// carry again. BX = c if carry else 0 (SBBQ/ANDQ, no branch).
	SBBQ BX, BX; ANDQ CX, BX
	ADDQ BX, t0; ADCQ $0, t1; ADCQ $0, t2; ADCQ $0, t3

	// Final correction (value < 2p): t - p = t + c mod 2^256, taken
	// exactly when t + c carries.
	MOVQ t0, t4; MOVQ t1, t5; MOVQ t2, t6; MOVQ t3, t7
	ADDQ CX, t4; ADCQ $0, t5; ADCQ $0, t6; ADCQ $0, t7
	CMOVQCS t4, t0; CMOVQCS t5, t1; CMOVQCS t6, t2; CMOVQCS t7, t3

	MOVQ z+0(FP), DI
	MOVQ t0, 0(DI); MOVQ t1, 8(DI); MOVQ t2, 16(DI); MOVQ t3, 24(DI)
	RET


// func fieldMulADX(z, x, y *limbs)
TEXT ·fieldMulADX(SB), NOSPLIT, $0-24
	MOVQ x+8(FP), SI
	MOVQ y+16(FP), DI
	MOVQ 0(SI), DX
	MULXQ 0(DI), t0, t1
	MULXQ 8(DI), AX, t2; ADDQ AX, t1
	MULXQ 16(DI), AX, t3; ADCQ AX, t2
	MULXQ 24(DI), AX, t4; ADCQ AX, t3; ADCQ $0, t4
	// row 1
	XORQ BX, BX
	MOVQ 8(SI), DX
	MULXQ 0(DI), AX, CX; ADCXQ AX, t1; ADOXQ CX, t2
	MULXQ 8(DI), AX, CX; ADCXQ AX, t2; ADOXQ CX, t3
	MULXQ 16(DI), AX, CX; ADCXQ AX, t3; ADOXQ CX, t4
	MULXQ 24(DI), AX, t5; ADCXQ AX, t4; ADOXQ BX, t5; ADCXQ BX, t5
	// row 2
	XORQ BX, BX
	MOVQ 16(SI), DX
	MULXQ 0(DI), AX, CX; ADCXQ AX, t2; ADOXQ CX, t3
	MULXQ 8(DI), AX, CX; ADCXQ AX, t3; ADOXQ CX, t4
	MULXQ 16(DI), AX, CX; ADCXQ AX, t4; ADOXQ CX, t5
	MULXQ 24(DI), AX, t6; ADCXQ AX, t5; ADOXQ BX, t6; ADCXQ BX, t6
	// row 3
	XORQ BX, BX
	MOVQ 24(SI), DX
	MULXQ 0(DI), AX, CX; ADCXQ AX, t3; ADOXQ CX, t4
	MULXQ 8(DI), AX, CX; ADCXQ AX, t4; ADOXQ CX, t5
	MULXQ 16(DI), AX, CX; ADCXQ AX, t5; ADOXQ CX, t6
	MULXQ 24(DI), AX, t7; ADCXQ AX, t6; ADOXQ BX, t7; ADCXQ BX, t7
	REDUCE_ADX

// func fieldSqrADX(z, x *limbs)
TEXT ·fieldSqrADX(SB), NOSPLIT, $0-16
	MOVQ x+8(FP), SI
	// Cross products x_i·x_j (i < j) into t1..t6.
	MOVQ 0(SI), DX
	MULXQ 8(SI), t1, t2
	MULXQ 16(SI), AX, t3; ADDQ AX, t2
	MULXQ 24(SI), AX, t4; ADCQ AX, t3
	MOVQ 8(SI), DX
	MULXQ 24(SI), AX, t5; ADCQ AX, t4; ADCQ $0, t5
	MULXQ 16(SI), AX, BX
	MOVQ 16(SI), DX
	MULXQ 24(SI), CX, t6
	ADDQ AX, t3; ADCQ BX, t4; ADCQ CX, t5; ADCQ $0, t6
	// Double them (t7 receives the top bit).
	MOVQ $0, t7
	ADDQ t1, t1; ADCQ t2, t2; ADCQ t3, t3; ADCQ t4, t4; ADCQ t5, t5; ADCQ t6, t6; ADCQ $0, t7
	// Add the squares x_i^2 at words 2i, 2i+1.
	MOVQ 0(SI), DX; MULXQ DX, t0, AX; ADDQ AX, t1
	MOVQ 8(SI), DX; MULXQ DX, AX, BX; ADCQ AX, t2; ADCQ BX, t3
	MOVQ 16(SI), DX; MULXQ DX, AX, BX; ADCQ AX, t4; ADCQ BX, t5
	MOVQ 24(SI), DX; MULXQ DX, AX, BX; ADCQ AX, t6; ADCQ BX, t7
	REDUCE_ADX

// func fieldMul(z, x, y *limbs)
TEXT ·fieldMul(SB), NOSPLIT, $0-24
	CMPB ·useADX(SB), $0
	JEQ  portable
	JMP  ·fieldMulADX(SB)
portable:
	JMP  ·fieldMulMULQ(SB)

// func fieldSqr(z, x *limbs)
TEXT ·fieldSqr(SB), NOSPLIT, $0-16
	CMPB ·useADX(SB), $0
	JEQ  portable
	JMP  ·fieldSqrADX(SB)
portable:
	JMP  ·fieldSqrMULQ(SB)


// Scalar Montgomery multiplication and squaring modulo the group order n
// (z = x·y·2^-256 mod n for x, y < n; the result is < n). Same product
// code as the field functions, then a four-row Montgomery reduction (as
// montReduceN in scalar.go) and one conditional subtraction of n. n is
// passed as a pointer (its words are memory operands of MULX/MULQ/SBBQ).

// func scalarMulADX(z, x, y, n *limbs)
TEXT ·scalarMulADX(SB), NOSPLIT, $0-32
	MOVQ x+8(FP), SI
	MOVQ y+16(FP), DI
	MOVQ 0(SI), DX
	MULXQ 0(DI), t0, t1
	MULXQ 8(DI), AX, t2; ADDQ AX, t1
	MULXQ 16(DI), AX, t3; ADCQ AX, t2
	MULXQ 24(DI), AX, t4; ADCQ AX, t3; ADCQ $0, t4
	// row 1
	XORQ BX, BX
	MOVQ 8(SI), DX
	MULXQ 0(DI), AX, CX; ADCXQ AX, t1; ADOXQ CX, t2
	MULXQ 8(DI), AX, CX; ADCXQ AX, t2; ADOXQ CX, t3
	MULXQ 16(DI), AX, CX; ADCXQ AX, t3; ADOXQ CX, t4
	MULXQ 24(DI), AX, t5; ADCXQ AX, t4; ADOXQ BX, t5; ADCXQ BX, t5
	// row 2
	XORQ BX, BX
	MOVQ 16(SI), DX
	MULXQ 0(DI), AX, CX; ADCXQ AX, t2; ADOXQ CX, t3
	MULXQ 8(DI), AX, CX; ADCXQ AX, t3; ADOXQ CX, t4
	MULXQ 16(DI), AX, CX; ADCXQ AX, t4; ADOXQ CX, t5
	MULXQ 24(DI), AX, t6; ADCXQ AX, t5; ADOXQ BX, t6; ADCXQ BX, t6
	// row 3
	XORQ BX, BX
	MOVQ 24(SI), DX
	MULXQ 0(DI), AX, CX; ADCXQ AX, t3; ADOXQ CX, t4
	MULXQ 8(DI), AX, CX; ADCXQ AX, t4; ADOXQ CX, t5
	MULXQ 16(DI), AX, CX; ADCXQ AX, t5; ADOXQ CX, t6
	MULXQ 24(DI), AX, t7; ADCXQ AX, t6; ADOXQ BX, t7; ADCXQ BX, t7
	MOVQ n+24(FP), SI
	// Montgomery reduction modulo n (four rows, m = t_i·(-n^-1) mod 2^64),
	// t8 (DI) collects the top carries.
	XORQ DI, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t0, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t0; ADOXQ BX, t1
	MULXQ 8(SI), AX, BX; ADCXQ AX, t1; ADOXQ BX, t2
	MULXQ 16(SI), AX, BX; ADCXQ AX, t2; ADOXQ BX, t3
	MULXQ 24(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	ADCXQ CX, t4
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, t5; ADCXQ CX, t6; ADCXQ CX, t7; ADCXQ CX, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t1, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t1; ADOXQ BX, t2
	MULXQ 8(SI), AX, BX; ADCXQ AX, t2; ADOXQ BX, t3
	MULXQ 16(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	MULXQ 24(SI), AX, BX; ADCXQ AX, t4; ADOXQ BX, t5
	ADCXQ CX, t5
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, t6; ADCXQ CX, t7; ADCXQ CX, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t2, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t2; ADOXQ BX, t3
	MULXQ 8(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	MULXQ 16(SI), AX, BX; ADCXQ AX, t4; ADOXQ BX, t5
	MULXQ 24(SI), AX, BX; ADCXQ AX, t5; ADOXQ BX, t6
	ADCXQ CX, t6
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, t7; ADCXQ CX, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t3, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	MULXQ 8(SI), AX, BX; ADCXQ AX, t4; ADOXQ BX, t5
	MULXQ 16(SI), AX, BX; ADCXQ AX, t5; ADOXQ BX, t6
	MULXQ 24(SI), AX, BX; ADCXQ AX, t6; ADOXQ BX, t7
	ADCXQ CX, t7
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, DI
	// The result t8·2^256 + t4..t7 is below 2n: subtract n when no borrow.
	MOVQ t4, AX; SUBQ 0(SI), AX
	MOVQ t5, BX; SBBQ 8(SI), BX
	MOVQ t6, CX; SBBQ 16(SI), CX
	MOVQ t7, DX; SBBQ 24(SI), DX
	SBBQ $0, DI
	CMOVQCC AX, t4; CMOVQCC BX, t5; CMOVQCC CX, t6; CMOVQCC DX, t7
	MOVQ z+0(FP), DI
	MOVQ t4, 0(DI); MOVQ t5, 8(DI); MOVQ t6, 16(DI); MOVQ t7, 24(DI)
	RET

// func scalarSqrADX(z, x, n *limbs)
TEXT ·scalarSqrADX(SB), NOSPLIT, $0-24
	MOVQ x+8(FP), SI
	// Cross products x_i·x_j (i < j) into t1..t6.
	MOVQ 0(SI), DX
	MULXQ 8(SI), t1, t2
	MULXQ 16(SI), AX, t3; ADDQ AX, t2
	MULXQ 24(SI), AX, t4; ADCQ AX, t3
	MOVQ 8(SI), DX
	MULXQ 24(SI), AX, t5; ADCQ AX, t4; ADCQ $0, t5
	MULXQ 16(SI), AX, BX
	MOVQ 16(SI), DX
	MULXQ 24(SI), CX, t6
	ADDQ AX, t3; ADCQ BX, t4; ADCQ CX, t5; ADCQ $0, t6
	// Double them (t7 receives the top bit).
	MOVQ $0, t7
	ADDQ t1, t1; ADCQ t2, t2; ADCQ t3, t3; ADCQ t4, t4; ADCQ t5, t5; ADCQ t6, t6; ADCQ $0, t7
	// Add the squares x_i^2 at words 2i, 2i+1.
	MOVQ 0(SI), DX; MULXQ DX, t0, AX; ADDQ AX, t1
	MOVQ 8(SI), DX; MULXQ DX, AX, BX; ADCQ AX, t2; ADCQ BX, t3
	MOVQ 16(SI), DX; MULXQ DX, AX, BX; ADCQ AX, t4; ADCQ BX, t5
	MOVQ 24(SI), DX; MULXQ DX, AX, BX; ADCQ AX, t6; ADCQ BX, t7
	MOVQ n+16(FP), SI
	// Montgomery reduction modulo n (four rows, m = t_i·(-n^-1) mod 2^64),
	// t8 (DI) collects the top carries.
	XORQ DI, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t0, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t0; ADOXQ BX, t1
	MULXQ 8(SI), AX, BX; ADCXQ AX, t1; ADOXQ BX, t2
	MULXQ 16(SI), AX, BX; ADCXQ AX, t2; ADOXQ BX, t3
	MULXQ 24(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	ADCXQ CX, t4
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, t5; ADCXQ CX, t6; ADCXQ CX, t7; ADCXQ CX, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t1, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t1; ADOXQ BX, t2
	MULXQ 8(SI), AX, BX; ADCXQ AX, t2; ADOXQ BX, t3
	MULXQ 16(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	MULXQ 24(SI), AX, BX; ADCXQ AX, t4; ADOXQ BX, t5
	ADCXQ CX, t5
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, t6; ADCXQ CX, t7; ADCXQ CX, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t2, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t2; ADOXQ BX, t3
	MULXQ 8(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	MULXQ 16(SI), AX, BX; ADCXQ AX, t4; ADOXQ BX, t5
	MULXQ 24(SI), AX, BX; ADCXQ AX, t5; ADOXQ BX, t6
	ADCXQ CX, t6
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, t7; ADCXQ CX, DI
	MOVQ $0x4B0DFF665588B13F, DX; IMULQ t3, DX
	XORQ CX, CX
	MULXQ 0(SI), AX, BX; ADCXQ AX, t3; ADOXQ BX, t4
	MULXQ 8(SI), AX, BX; ADCXQ AX, t4; ADOXQ BX, t5
	MULXQ 16(SI), AX, BX; ADCXQ AX, t5; ADOXQ BX, t6
	MULXQ 24(SI), AX, BX; ADCXQ AX, t6; ADOXQ BX, t7
	ADCXQ CX, t7
	MOVQ $0, BX; ADOXQ CX, BX
	ADCXQ BX, DI
	// The result t8·2^256 + t4..t7 is below 2n: subtract n when no borrow.
	MOVQ t4, AX; SUBQ 0(SI), AX
	MOVQ t5, BX; SBBQ 8(SI), BX
	MOVQ t6, CX; SBBQ 16(SI), CX
	MOVQ t7, DX; SBBQ 24(SI), DX
	SBBQ $0, DI
	CMOVQCC AX, t4; CMOVQCC BX, t5; CMOVQCC CX, t6; CMOVQCC DX, t7
	MOVQ z+0(FP), DI
	MOVQ t4, 0(DI); MOVQ t5, 8(DI); MOVQ t6, 16(DI); MOVQ t7, 24(DI)
	RET

// func scalarMulMULQ(z, x, y, n *limbs)
TEXT ·scalarMulMULQ(SB), NOSPLIT, $0-32
	MOVQ x+8(FP), SI
	MOVQ y+16(FP), DI
	// row 0: t0..t4 = x0·y
	MOVQ 0(SI), CX
	MOVQ CX, AX; MULQ 0(DI); MOVQ AX, t0; MOVQ DX, t1
	MOVQ CX, AX; MULQ 8(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, t2
	MOVQ CX, AX; MULQ 16(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, t3
	MOVQ CX, AX; MULQ 24(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, t4
	// row 1: t1..t5 += x1·y
	MOVQ 8(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, t5
	// row 2: t2..t6 += x2·y
	MOVQ 16(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, t6
	// row 3: t3..t7 += x3·y
	MOVQ 24(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t6; ADCQ $0, DX; MOVQ DX, t7
	MOVQ n+24(FP), SI
	// Montgomery reduction modulo n (four rows, m = t_i·(-n^-1) mod 2^64),
	// t8 (DI) collects the top carries.
	XORQ DI, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t0, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t0; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX
	ADDQ DX, t4; ADCQ $0, t5; ADCQ $0, t6; ADCQ $0, t7; ADCQ $0, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t1, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX
	ADDQ DX, t5; ADCQ $0, t6; ADCQ $0, t7; ADCQ $0, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t2, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX
	ADDQ DX, t6; ADCQ $0, t7; ADCQ $0, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t3, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t6; ADCQ $0, DX
	ADDQ DX, t7; ADCQ $0, DI
	// The result t8·2^256 + t4..t7 is below 2n: subtract n when no borrow.
	MOVQ t4, AX; SUBQ 0(SI), AX
	MOVQ t5, BX; SBBQ 8(SI), BX
	MOVQ t6, CX; SBBQ 16(SI), CX
	MOVQ t7, DX; SBBQ 24(SI), DX
	SBBQ $0, DI
	CMOVQCC AX, t4; CMOVQCC BX, t5; CMOVQCC CX, t6; CMOVQCC DX, t7
	MOVQ z+0(FP), DI
	MOVQ t4, 0(DI); MOVQ t5, 8(DI); MOVQ t6, 16(DI); MOVQ t7, 24(DI)
	RET

// func scalarSqrMULQ(z, x, n *limbs)
TEXT ·scalarSqrMULQ(SB), NOSPLIT, $0-24
	MOVQ x+8(FP), SI
	MOVQ SI, DI
	// row 0: t0..t4 = x0·y
	MOVQ 0(SI), CX
	MOVQ CX, AX; MULQ 0(DI); MOVQ AX, t0; MOVQ DX, t1
	MOVQ CX, AX; MULQ 8(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, t2
	MOVQ CX, AX; MULQ 16(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, t3
	MOVQ CX, AX; MULQ 24(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, t4
	// row 1: t1..t5 += x1·y
	MOVQ 8(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, t5
	// row 2: t2..t6 += x2·y
	MOVQ 16(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, t6
	// row 3: t3..t7 += x3·y
	MOVQ 24(SI), CX
	MOVQ CX, AX; MULQ 0(DI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 8(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 16(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, BX
	MOVQ CX, AX; MULQ 24(DI); ADDQ BX, AX; ADCQ $0, DX; ADDQ AX, t6; ADCQ $0, DX; MOVQ DX, t7
	MOVQ n+16(FP), SI
	// Montgomery reduction modulo n (four rows, m = t_i·(-n^-1) mod 2^64),
	// t8 (DI) collects the top carries.
	XORQ DI, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t0, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t0; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX
	ADDQ DX, t4; ADCQ $0, t5; ADCQ $0, t6; ADCQ $0, t7; ADCQ $0, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t1, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t1; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX
	ADDQ DX, t5; ADCQ $0, t6; ADCQ $0, t7; ADCQ $0, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t2, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t2; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX
	ADDQ DX, t6; ADCQ $0, t7; ADCQ $0, DI
	MOVQ $0x4B0DFF665588B13F, AX; IMULQ t3, AX; MOVQ AX, BX
	MULQ 0(SI); ADDQ AX, t3; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 8(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t4; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 16(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t5; ADCQ $0, DX; MOVQ DX, CX
	MOVQ BX, AX; MULQ 24(SI); ADDQ CX, AX; ADCQ $0, DX; ADDQ AX, t6; ADCQ $0, DX
	ADDQ DX, t7; ADCQ $0, DI
	// The result t8·2^256 + t4..t7 is below 2n: subtract n when no borrow.
	MOVQ t4, AX; SUBQ 0(SI), AX
	MOVQ t5, BX; SBBQ 8(SI), BX
	MOVQ t6, CX; SBBQ 16(SI), CX
	MOVQ t7, DX; SBBQ 24(SI), DX
	SBBQ $0, DI
	CMOVQCC AX, t4; CMOVQCC BX, t5; CMOVQCC CX, t6; CMOVQCC DX, t7
	MOVQ z+0(FP), DI
	MOVQ t4, 0(DI); MOVQ t5, 8(DI); MOVQ t6, 16(DI); MOVQ t7, 24(DI)
	RET

// func scalarMul(z, x, y, n *limbs)
TEXT ·scalarMul(SB), NOSPLIT, $0-32
	CMPB ·useADX(SB), $0
	JEQ  portable
	JMP  ·scalarMulADX(SB)
portable:
	JMP  ·scalarMulMULQ(SB)

// func scalarSqr(z, x, n *limbs)
TEXT ·scalarSqr(SB), NOSPLIT, $0-24
	CMPB ·useADX(SB), $0
	JEQ  portable
	JMP  ·scalarSqrADX(SB)
portable:
	JMP  ·scalarSqrMULQ(SB)

// func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuid(SB), NOSPLIT, $0-24
	MOVL leaf+0(FP), AX
	MOVL subleaf+4(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET
