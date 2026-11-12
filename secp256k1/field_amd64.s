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

// func lookupAffineSSE2(r *affinePoint, table *[baseEntries]affinePoint, idx uint64)
//
// r = table[idx-1] for 1 <= idx <= 16, scanning all 16 entries of 64
// bytes (x then y): every entry is loaded, masked with an equality mask
// (PCMPEQL of the broadcast index with the entry number) and OR-ed into
// the result. Fully unrolled, no branch, every address independent of
// idx. SSE2 only (part of the amd64 baseline). Uses X0..X13 (X14 and X15
// are left alone).
TEXT ·lookupAffineSSE2(SB), NOSPLIT, $0-24
	MOVQ table+8(FP), SI
	MOVQ idx+16(FP), AX
	MOVQ AX, X13
	PSHUFD $0, X13, X13
	PXOR X0, X0; PXOR X1, X1; PXOR X2, X2; PXOR X3, X3
	// entry 0 (magnitude 1)
	MOVL $1, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 0(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 16(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 32(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 48(SI), X7; PAND X12, X7; POR X7, X3
	// entry 1 (magnitude 2)
	MOVL $2, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 64(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 80(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 96(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 112(SI), X7; PAND X12, X7; POR X7, X3
	// entry 2 (magnitude 3)
	MOVL $3, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 128(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 144(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 160(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 176(SI), X7; PAND X12, X7; POR X7, X3
	// entry 3 (magnitude 4)
	MOVL $4, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 192(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 208(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 224(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 240(SI), X7; PAND X12, X7; POR X7, X3
	// entry 4 (magnitude 5)
	MOVL $5, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 256(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 272(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 288(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 304(SI), X7; PAND X12, X7; POR X7, X3
	// entry 5 (magnitude 6)
	MOVL $6, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 320(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 336(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 352(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 368(SI), X7; PAND X12, X7; POR X7, X3
	// entry 6 (magnitude 7)
	MOVL $7, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 384(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 400(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 416(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 432(SI), X7; PAND X12, X7; POR X7, X3
	// entry 7 (magnitude 8)
	MOVL $8, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 448(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 464(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 480(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 496(SI), X7; PAND X12, X7; POR X7, X3
	// entry 8 (magnitude 9)
	MOVL $9, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 512(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 528(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 544(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 560(SI), X7; PAND X12, X7; POR X7, X3
	// entry 9 (magnitude 10)
	MOVL $10, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 576(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 592(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 608(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 624(SI), X7; PAND X12, X7; POR X7, X3
	// entry 10 (magnitude 11)
	MOVL $11, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 640(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 656(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 672(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 688(SI), X7; PAND X12, X7; POR X7, X3
	// entry 11 (magnitude 12)
	MOVL $12, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 704(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 720(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 736(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 752(SI), X7; PAND X12, X7; POR X7, X3
	// entry 12 (magnitude 13)
	MOVL $13, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 768(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 784(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 800(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 816(SI), X7; PAND X12, X7; POR X7, X3
	// entry 13 (magnitude 14)
	MOVL $14, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 832(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 848(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 864(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 880(SI), X7; PAND X12, X7; POR X7, X3
	// entry 14 (magnitude 15)
	MOVL $15, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 896(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 912(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 928(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 944(SI), X7; PAND X12, X7; POR X7, X3
	// entry 15 (magnitude 16)
	MOVL $16, AX; MOVQ AX, X12; PSHUFD $0, X12, X12; PCMPEQL X13, X12
	MOVOU 960(SI), X4; PAND X12, X4; POR X4, X0
	MOVOU 976(SI), X5; PAND X12, X5; POR X5, X1
	MOVOU 992(SI), X6; PAND X12, X6; POR X6, X2
	MOVOU 1008(SI), X7; PAND X12, X7; POR X7, X3
	MOVQ r+0(FP), DI
	MOVOU X0, 0(DI); MOVOU X1, 16(DI); MOVOU X2, 32(DI); MOVOU X3, 48(DI)
	RET

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
