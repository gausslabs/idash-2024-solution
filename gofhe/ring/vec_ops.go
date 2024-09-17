package ring

import (
	"unsafe"
)

// AddVec evaluates p3 = p1 + p2 - modulus if p3 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func AddVec(p1, p2, p3 []uint64, modulus uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = CRed(x[0]+y[0], modulus)
		z[1] = CRed(x[1]+y[1], modulus)
		z[2] = CRed(x[2]+y[2], modulus)
		z[3] = CRed(x[3]+y[3], modulus)
		z[4] = CRed(x[4]+y[4], modulus)
		z[5] = CRed(x[5]+y[5], modulus)
		z[6] = CRed(x[6]+y[6], modulus)
		z[7] = CRed(x[7]+y[7], modulus)
	}
}

// AddLazyVec evaluates p3 = p1 + p2
//
// Loops are iterated with respect to len(p1)
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func AddLazyVec(p1, p2, p3 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = x[0] + y[0]
		z[1] = x[1] + y[1]
		z[2] = x[2] + y[2]
		z[3] = x[3] + y[3]
		z[4] = x[4] + y[4]
		z[5] = x[5] + y[5]
		z[6] = x[6] + y[6]
		z[7] = x[7] + y[7]
	}
}

// SubVec evaluates p3 = p1 + modulus - p2 - modulus if (p1 + modulus - p2) >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func SubVec(p1, p2, p3 []uint64, modulus uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = CRed((x[0]+modulus)-y[0], modulus)
		z[1] = CRed((x[1]+modulus)-y[1], modulus)
		z[2] = CRed((x[2]+modulus)-y[2], modulus)
		z[3] = CRed((x[3]+modulus)-y[3], modulus)
		z[4] = CRed((x[4]+modulus)-y[4], modulus)
		z[5] = CRed((x[5]+modulus)-y[5], modulus)
		z[6] = CRed((x[6]+modulus)-y[6], modulus)
		z[7] = CRed((x[7]+modulus)-y[7], modulus)
	}
}

// SubLazyVec evaluates p3 = p1 + modulus - p2
//
// Loops are iterated with respect to len(p1)
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func SubLazyVec(p1, p2, p3 []uint64, modulus uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = x[0] + modulus - y[0]
		z[1] = x[1] + modulus - y[1]
		z[2] = x[2] + modulus - y[2]
		z[3] = x[3] + modulus - y[3]
		z[4] = x[4] + modulus - y[4]
		z[5] = x[5] + modulus - y[5]
		z[6] = x[6] + modulus - y[6]
		z[7] = x[7] + modulus - y[7]
	}
}

// NegVec evaluates p2 = modulus - p1
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func NegVec(p1, p2 []uint64, modulus uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = modulus - x[0]
		z[1] = modulus - x[1]
		z[2] = modulus - x[2]
		z[3] = modulus - x[3]
		z[4] = modulus - x[4]
		z[5] = modulus - x[5]
		z[6] = modulus - x[6]
		z[7] = modulus - x[7]
	}
}

// BarrettReduceVec evaluates p2 = p1 % modulus with Barret reduction
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensured to be in the range [0, modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func BarrettReduceVec(p1, p2 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = BRedAdd(x[0], modulus, bredconstant)
		z[1] = BRedAdd(x[1], modulus, bredconstant)
		z[2] = BRedAdd(x[2], modulus, bredconstant)
		z[3] = BRedAdd(x[3], modulus, bredconstant)
		z[4] = BRedAdd(x[4], modulus, bredconstant)
		z[5] = BRedAdd(x[5], modulus, bredconstant)
		z[6] = BRedAdd(x[6], modulus, bredconstant)
		z[7] = BRedAdd(x[7], modulus, bredconstant)
	}
}

// BarrettReduceLazyVec evaluates p2 = p1 % modulus with Barrett reduction
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func BarrettReduceLazyVec(p1, p2 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = BRedAddLazy(x[0], modulus, bredconstant)
		z[1] = BRedAddLazy(x[1], modulus, bredconstant)
		z[2] = BRedAddLazy(x[2], modulus, bredconstant)
		z[3] = BRedAddLazy(x[3], modulus, bredconstant)
		z[4] = BRedAddLazy(x[4], modulus, bredconstant)
		z[5] = BRedAddLazy(x[5], modulus, bredconstant)
		z[6] = BRedAddLazy(x[6], modulus, bredconstant)
		z[7] = BRedAddLazy(x[7], modulus, bredconstant)
	}
}

// MulVec evaluates p3 = p1 * p2
//
// Loops are iterated with respect to len(p1)
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func MulVec(p1, p2, p3 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = x[0] * y[0]
		z[1] = x[1] * y[1]
		z[2] = x[2] * y[2]
		z[3] = x[3] * y[3]
		z[4] = x[4] * y[4]
		z[5] = x[5] * y[5]
		z[6] = x[6] * y[6]
		z[7] = x[7] * y[7]
	}
}

// MulThenAddLazyVec evaluates p3 += p1 * p2
//
// Loops are iterated with respect to len(p1)
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func MulThenAddLazyVec(p1, p2, p3 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] += x[0] * y[0]
		z[1] += x[1] * y[1]
		z[2] += x[2] * y[2]
		z[3] += x[3] * y[3]
		z[4] += x[4] * y[4]
		z[5] += x[5] * y[5]
		z[6] += x[6] * y[6]
		z[7] += x[7] * y[7]
	}
}

// MulBarrettReduceVec evaluates p3 = p1 * p2 % modulus with Barrett reduction
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulBarrettReduceVec(p1, p2, p3 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = BRed(x[0], y[0], modulus, bredconstant)
		z[1] = BRed(x[1], y[1], modulus, bredconstant)
		z[2] = BRed(x[2], y[2], modulus, bredconstant)
		z[3] = BRed(x[3], y[3], modulus, bredconstant)
		z[4] = BRed(x[4], y[4], modulus, bredconstant)
		z[5] = BRed(x[5], y[5], modulus, bredconstant)
		z[6] = BRed(x[6], y[6], modulus, bredconstant)
		z[7] = BRed(x[7], y[7], modulus, bredconstant)
	}
}

// MulBarrettReduceLazyVec evaluates p3 = p1 * p2 % modulus
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func MulBarrettReduceLazyVec(p1, p2, p3 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = BRedLazy(x[0], y[0], modulus, bredconstant)
		z[1] = BRedLazy(x[1], y[1], modulus, bredconstant)
		z[2] = BRedLazy(x[2], y[2], modulus, bredconstant)
		z[3] = BRedLazy(x[3], y[3], modulus, bredconstant)
		z[4] = BRedLazy(x[4], y[4], modulus, bredconstant)
		z[5] = BRedLazy(x[5], y[5], modulus, bredconstant)
		z[6] = BRedLazy(x[6], y[6], modulus, bredconstant)
		z[7] = BRedLazy(x[7], y[7], modulus, bredconstant)
	}
}

// MulBarrettReduceThenAddVec evaluates p3 += p1 * p2 % modulus (Barrett reduction) - modulus if p3 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulBarrettReduceThenAddVec(p1, p2, p3 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = CRed(z[0]+BRed(x[0], y[0], modulus, bredconstant), modulus)
		z[1] = CRed(z[1]+BRed(x[1], y[1], modulus, bredconstant), modulus)
		z[2] = CRed(z[2]+BRed(x[2], y[2], modulus, bredconstant), modulus)
		z[3] = CRed(z[3]+BRed(x[3], y[3], modulus, bredconstant), modulus)
		z[4] = CRed(z[4]+BRed(x[4], y[4], modulus, bredconstant), modulus)
		z[5] = CRed(z[5]+BRed(x[5], y[5], modulus, bredconstant), modulus)
		z[6] = CRed(z[6]+BRed(x[6], y[6], modulus, bredconstant), modulus)
		z[7] = CRed(z[7]+BRed(x[7], y[7], modulus, bredconstant), modulus)
	}
}

// MulBarrettReduceThenAddLazyVec evaluates p3 += p1 * p2 % modulus (with Barrett reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 2*modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This funcion is constant time.
func MulBarrettReduceThenAddLazyVec(p1, p2, p3 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] += BRed(x[0], y[0], modulus, bredconstant)
		z[1] += BRed(x[1], y[1], modulus, bredconstant)
		z[2] += BRed(x[2], y[2], modulus, bredconstant)
		z[3] += BRed(x[3], y[3], modulus, bredconstant)
		z[4] += BRed(x[4], y[4], modulus, bredconstant)
		z[5] += BRed(x[5], y[5], modulus, bredconstant)
		z[6] += BRed(x[6], y[6], modulus, bredconstant)
		z[7] += BRed(x[7], y[7], modulus, bredconstant)
	}
}

// MulMontgomeryReduceVec evaluates p3 = p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulMontgomeryReduceVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = MRed(x[0], y[0], modulus, mredconstant)
		z[1] = MRed(x[1], y[1], modulus, mredconstant)
		z[2] = MRed(x[2], y[2], modulus, mredconstant)
		z[3] = MRed(x[3], y[3], modulus, mredconstant)
		z[4] = MRed(x[4], y[4], modulus, mredconstant)
		z[5] = MRed(x[5], y[5], modulus, mredconstant)
		z[6] = MRed(x[6], y[6], modulus, mredconstant)
		z[7] = MRed(x[7], y[7], modulus, mredconstant)
	}
}

// MulMontgomeryReduceLazyVec evaluates p3 = p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MulMontgomeryReduceLazyVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = MRedLazy(x[0], y[0], modulus, mredconstant)
		z[1] = MRedLazy(x[1], y[1], modulus, mredconstant)
		z[2] = MRedLazy(x[2], y[2], modulus, mredconstant)
		z[3] = MRedLazy(x[3], y[3], modulus, mredconstant)
		z[4] = MRedLazy(x[4], y[4], modulus, mredconstant)
		z[5] = MRedLazy(x[5], y[5], modulus, mredconstant)
		z[6] = MRedLazy(x[6], y[6], modulus, mredconstant)
		z[7] = MRedLazy(x[7], y[7], modulus, mredconstant)
	}
}

// MulMontgomeryReduceThenAddVec evaluates p3 += p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction) - modulus if p3 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulMontgomeryReduceThenAddVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = CRed(z[0]+MRed(x[0], y[0], modulus, mredconstant), modulus)
		z[1] = CRed(z[1]+MRed(x[1], y[1], modulus, mredconstant), modulus)
		z[2] = CRed(z[2]+MRed(x[2], y[2], modulus, mredconstant), modulus)
		z[3] = CRed(z[3]+MRed(x[3], y[3], modulus, mredconstant), modulus)
		z[4] = CRed(z[4]+MRed(x[4], y[4], modulus, mredconstant), modulus)
		z[5] = CRed(z[5]+MRed(x[5], y[5], modulus, mredconstant), modulus)
		z[6] = CRed(z[6]+MRed(x[6], y[6], modulus, mredconstant), modulus)
		z[7] = CRed(z[7]+MRed(x[7], y[7], modulus, mredconstant), modulus)
	}
}

// MulMontgomeryReduceThenAddLazyVec evaluates p3 += p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 2*modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulMontgomeryReduceThenAddLazyVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] += MRed(x[0], y[0], modulus, mredconstant)
		z[1] += MRed(x[1], y[1], modulus, mredconstant)
		z[2] += MRed(x[2], y[2], modulus, mredconstant)
		z[3] += MRed(x[3], y[3], modulus, mredconstant)
		z[4] += MRed(x[4], y[4], modulus, mredconstant)
		z[5] += MRed(x[5], y[5], modulus, mredconstant)
		z[6] += MRed(x[6], y[6], modulus, mredconstant)
		z[7] += MRed(x[7], y[7], modulus, mredconstant)
	}
}

// MulMontgomeryReduceLazyThenAddLazyVec evaluates p3 += p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 3*modulus-2] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MulMontgomeryReduceLazyThenAddLazyVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] += MRedLazy(x[0], y[0], modulus, mredconstant)
		z[1] += MRedLazy(x[1], y[1], modulus, mredconstant)
		z[2] += MRedLazy(x[2], y[2], modulus, mredconstant)
		z[3] += MRedLazy(x[3], y[3], modulus, mredconstant)
		z[4] += MRedLazy(x[4], y[4], modulus, mredconstant)
		z[5] += MRedLazy(x[5], y[5], modulus, mredconstant)
		z[6] += MRedLazy(x[6], y[6], modulus, mredconstant)
		z[7] += MRedLazy(x[7], y[7], modulus, mredconstant)
	}
}

// MulMontgomeryReduceThenSubVec evaluates p3 = p3 + modulus - p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction) - modulus if p3 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulMontgomeryReduceThenSubVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = CRed(z[0]+(modulus-MRed(x[0], y[0], modulus, mredconstant)), modulus)
		z[1] = CRed(z[1]+(modulus-MRed(x[1], y[1], modulus, mredconstant)), modulus)
		z[2] = CRed(z[2]+(modulus-MRed(x[2], y[2], modulus, mredconstant)), modulus)
		z[3] = CRed(z[3]+(modulus-MRed(x[3], y[3], modulus, mredconstant)), modulus)
		z[4] = CRed(z[4]+(modulus-MRed(x[4], y[4], modulus, mredconstant)), modulus)
		z[5] = CRed(z[5]+(modulus-MRed(x[5], y[5], modulus, mredconstant)), modulus)
		z[6] = CRed(z[6]+(modulus-MRed(x[6], y[6], modulus, mredconstant)), modulus)
		z[7] = CRed(z[7]+(modulus-MRed(x[7], y[7], modulus, mredconstant)), modulus)
	}
}

// MulMontgomeryReduceThenSubLazyVec evaluates p3 += modulus - p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 2*modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func MulMontgomeryReduceThenSubLazyVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] += (modulus - MRed(x[0], y[0], modulus, mredconstant))
		z[1] += (modulus - MRed(x[1], y[1], modulus, mredconstant))
		z[2] += (modulus - MRed(x[2], y[2], modulus, mredconstant))
		z[3] += (modulus - MRed(x[3], y[3], modulus, mredconstant))
		z[4] += (modulus - MRed(x[4], y[4], modulus, mredconstant))
		z[5] += (modulus - MRed(x[5], y[5], modulus, mredconstant))
		z[6] += (modulus - MRed(x[6], y[6], modulus, mredconstant))
		z[7] += (modulus - MRed(x[7], y[7], modulus, mredconstant))
	}
}

// MulMontgomeryReduceLazyThenSubLazyVec evaluates p3 += modulus - p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 3*modulus-1] if p3 was already in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MulMontgomeryReduceLazyThenSubLazyVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)
	twomodulus := modulus << 1

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] += twomodulus - MRedLazy(x[0], y[0], modulus, mredconstant)
		z[1] += twomodulus - MRedLazy(x[1], y[1], modulus, mredconstant)
		z[2] += twomodulus - MRedLazy(x[2], y[2], modulus, mredconstant)
		z[3] += twomodulus - MRedLazy(x[3], y[3], modulus, mredconstant)
		z[4] += twomodulus - MRedLazy(x[4], y[4], modulus, mredconstant)
		z[5] += twomodulus - MRedLazy(x[5], y[5], modulus, mredconstant)
		z[6] += twomodulus - MRedLazy(x[6], y[6], modulus, mredconstant)
		z[7] += twomodulus - MRedLazy(x[7], y[7], modulus, mredconstant)
	}
}

// MulMontgomeryReduceLazyThenNegLazyVec evaluates p3 = 2*modulus - p1 * p2 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MulMontgomeryReduceLazyThenNegLazyVec(p1, p2, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)
	twomodulus := modulus << 1

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = twomodulus - MRedLazy(x[0], y[0], modulus, mredconstant)
		z[1] = twomodulus - MRedLazy(x[1], y[1], modulus, mredconstant)
		z[2] = twomodulus - MRedLazy(x[2], y[2], modulus, mredconstant)
		z[3] = twomodulus - MRedLazy(x[3], y[3], modulus, mredconstant)
		z[4] = twomodulus - MRedLazy(x[4], y[4], modulus, mredconstant)
		z[5] = twomodulus - MRedLazy(x[5], y[5], modulus, mredconstant)
		z[6] = twomodulus - MRedLazy(x[6], y[6], modulus, mredconstant)
		z[7] = twomodulus - MRedLazy(x[7], y[7], modulus, mredconstant)
	}
}

// AddThenMulScalarMontgomeryReduce evaluates p3 = (p1 + p2) * scalar * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func AddThenMulScalarMontgomeryReduce(p1, p2 []uint64, scalarMont uint64, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = MRed(x[0]+y[0], scalarMont, modulus, mredconstant)
		z[1] = MRed(x[1]+y[1], scalarMont, modulus, mredconstant)
		z[2] = MRed(x[2]+y[2], scalarMont, modulus, mredconstant)
		z[3] = MRed(x[3]+y[3], scalarMont, modulus, mredconstant)
		z[4] = MRed(x[4]+y[4], scalarMont, modulus, mredconstant)
		z[5] = MRed(x[5]+y[5], scalarMont, modulus, mredconstant)
		z[6] = MRed(x[6]+y[6], scalarMont, modulus, mredconstant)
		z[7] = MRed(x[7]+y[7], scalarMont, modulus, mredconstant)
	}
}

// AddScalarThenMulScalarMontgomeryReduceVec evaluates p3 = (p1+scalar0) * scalarMont1 * 2^{64}^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func AddScalarThenMulScalarMontgomeryReduceVec(p1 []uint64, scalar0, scalarMont1 uint64, p2 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = MRed(x[0]+scalar0, scalarMont1, modulus, mredconstant)
		z[1] = MRed(x[1]+scalar0, scalarMont1, modulus, mredconstant)
		z[2] = MRed(x[2]+scalar0, scalarMont1, modulus, mredconstant)
		z[3] = MRed(x[3]+scalar0, scalarMont1, modulus, mredconstant)
		z[4] = MRed(x[4]+scalar0, scalarMont1, modulus, mredconstant)
		z[5] = MRed(x[5]+scalar0, scalarMont1, modulus, mredconstant)
		z[6] = MRed(x[6]+scalar0, scalarMont1, modulus, mredconstant)
		z[7] = MRed(x[7]+scalar0, scalarMont1, modulus, mredconstant)
	}
}

// AddScalarVec evaluates p2 = p1 + scalar - modulus if p2 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func AddScalarVec(p1 []uint64, scalar uint64, p2 []uint64, modulus uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = CRed(x[0]+scalar, modulus)
		z[1] = CRed(x[1]+scalar, modulus)
		z[2] = CRed(x[2]+scalar, modulus)
		z[3] = CRed(x[3]+scalar, modulus)
		z[4] = CRed(x[4]+scalar, modulus)
		z[5] = CRed(x[5]+scalar, modulus)
		z[6] = CRed(x[6]+scalar, modulus)
		z[7] = CRed(x[7]+scalar, modulus)
	}
}

// AddScalarLazyVec evaluates p2 = p1 + scalar
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func AddScalarLazyVec(p1 []uint64, scalar uint64, p2 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = x[0] + scalar
		z[1] = x[1] + scalar
		z[2] = x[2] + scalar
		z[3] = x[3] + scalar
		z[4] = x[4] + scalar
		z[5] = x[5] + scalar
		z[6] = x[6] + scalar
		z[7] = x[7] + scalar
	}
}

// AddScalarLazyThenNegateTwoModulusLazyVec evaluates p2 = scalar + 2*modulus - p1
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func AddScalarLazyThenNegateTwoModulusLazyVec(p1 []uint64, scalar uint64, p2 []uint64, modulus uint64) {

	N := len(p1)
	twomodulus := modulus << 1

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = scalar + twomodulus - x[0]
		z[1] = scalar + twomodulus - x[1]
		z[2] = scalar + twomodulus - x[2]
		z[3] = scalar + twomodulus - x[3]
		z[4] = scalar + twomodulus - x[4]
		z[5] = scalar + twomodulus - x[5]
		z[6] = scalar + twomodulus - x[6]
		z[7] = scalar + twomodulus - x[7]
	}
}

// SubScalarVec evaluates p2 = p1 + modulus - scalar
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func SubScalarVec(p1 []uint64, scalar uint64, p2 []uint64, modulus uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = CRed(x[0]+modulus-scalar, modulus)
		z[1] = CRed(x[1]+modulus-scalar, modulus)
		z[2] = CRed(x[2]+modulus-scalar, modulus)
		z[3] = CRed(x[3]+modulus-scalar, modulus)
		z[4] = CRed(x[4]+modulus-scalar, modulus)
		z[5] = CRed(x[5]+modulus-scalar, modulus)
		z[6] = CRed(x[6]+modulus-scalar, modulus)
		z[7] = CRed(x[7]+modulus-scalar, modulus)
	}
}

// MulScalarMontgomeryReduceVec evaluates p2 = p1 * scalarMont (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensure to be in the range [0, modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func MulScalarMontgomeryReduceVec(p1 []uint64, scalarMont uint64, p2 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = MRed(x[0], scalarMont, modulus, mredconstant)
		z[1] = MRed(x[1], scalarMont, modulus, mredconstant)
		z[2] = MRed(x[2], scalarMont, modulus, mredconstant)
		z[3] = MRed(x[3], scalarMont, modulus, mredconstant)
		z[4] = MRed(x[4], scalarMont, modulus, mredconstant)
		z[5] = MRed(x[5], scalarMont, modulus, mredconstant)
		z[6] = MRed(x[6], scalarMont, modulus, mredconstant)
		z[7] = MRed(x[7], scalarMont, modulus, mredconstant)
	}
}

// MulScalarMontgomeryReduceLazyVec evaluates p2 = p1 * scalarMont (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensure to be in the range [0, 2*modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MulScalarMontgomeryReduceLazyVec(p1 []uint64, scalarMont uint64, p2 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = MRedLazy(x[0], scalarMont, modulus, mredconstant)
		z[1] = MRedLazy(x[1], scalarMont, modulus, mredconstant)
		z[2] = MRedLazy(x[2], scalarMont, modulus, mredconstant)
		z[3] = MRedLazy(x[3], scalarMont, modulus, mredconstant)
		z[4] = MRedLazy(x[4], scalarMont, modulus, mredconstant)
		z[5] = MRedLazy(x[5], scalarMont, modulus, mredconstant)
		z[6] = MRedLazy(x[6], scalarMont, modulus, mredconstant)
		z[7] = MRedLazy(x[7], scalarMont, modulus, mredconstant)
	}
}

// MulScalarMontgomeryReduceThenAddVec evaluates p2 += p1 * scalarMont (with Montgomery reduction) - modulus if p2 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensure to be in the range [0, modulus-1] if p2 was already in the range [0, modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func MulScalarMontgomeryReduceThenAddVec(p1 []uint64, scalarMont uint64, p2 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = CRed(z[0]+MRed(x[0], scalarMont, modulus, mredconstant), modulus)
		z[1] = CRed(z[1]+MRed(x[1], scalarMont, modulus, mredconstant), modulus)
		z[2] = CRed(z[2]+MRed(x[2], scalarMont, modulus, mredconstant), modulus)
		z[3] = CRed(z[3]+MRed(x[3], scalarMont, modulus, mredconstant), modulus)
		z[4] = CRed(z[4]+MRed(x[4], scalarMont, modulus, mredconstant), modulus)
		z[5] = CRed(z[5]+MRed(x[5], scalarMont, modulus, mredconstant), modulus)
		z[6] = CRed(z[6]+MRed(x[6], scalarMont, modulus, mredconstant), modulus)
		z[7] = CRed(z[7]+MRed(x[7], scalarMont, modulus, mredconstant), modulus)
	}
}

// MulScalarMontgomeryReduceThenAddScalarVec evaluates p2 = p1 * scalarMont * 2^{64}^{-1} + scalar0 (with Montgomery reduction) - modulus if p2 >= modulus
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensure to be in the range [0, modulus-1] if p2 was already in the range [0, modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func MulScalarMontgomeryReduceThenAddScalarVec(p1 []uint64, scalar0, scalarMont1 uint64, p2 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = CRed(MRed(x[0], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[1] = CRed(MRed(x[1], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[2] = CRed(MRed(x[2], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[3] = CRed(MRed(x[3], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[4] = CRed(MRed(x[4], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[5] = CRed(MRed(x[5], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[6] = CRed(MRed(x[6], scalarMont1, modulus, mredconstant)+scalar0, modulus)
		z[7] = CRed(MRed(x[7], scalarMont1, modulus, mredconstant)+scalar0, modulus)
	}
}

// SubToModulusThenMulScalarMontgomeryReduceVec evaluates p3 = (2*modulus - p2 + p1) * scalarMont * (2^{64})^{-1} (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p3 is ensured to be in the range [0, modulus-1]
//
// p1, p2, p3 must:
// - be of the same size
// - be of size of a multiple of 8
func SubToModulusThenMulScalarMontgomeryReduceVec(p1, p2 []uint64, scalarMont uint64, p3 []uint64, modulus, mredconstant uint64) {

	N := len(p1)
	twomodulus := modulus << 1

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p2[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p3)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p3[j]))

		z[0] = MRed(twomodulus-y[0]+x[0], scalarMont, modulus, mredconstant)
		z[1] = MRed(twomodulus-y[1]+x[1], scalarMont, modulus, mredconstant)
		z[2] = MRed(twomodulus-y[2]+x[2], scalarMont, modulus, mredconstant)
		z[3] = MRed(twomodulus-y[3]+x[3], scalarMont, modulus, mredconstant)
		z[4] = MRed(twomodulus-y[4]+x[4], scalarMont, modulus, mredconstant)
		z[5] = MRed(twomodulus-y[5]+x[5], scalarMont, modulus, mredconstant)
		z[6] = MRed(twomodulus-y[6]+x[6], scalarMont, modulus, mredconstant)
		z[7] = MRed(twomodulus-y[7]+x[7], scalarMont, modulus, mredconstant)

	}
}

// MFormVec evaluates p2 = p1 * 2^{64} % modulus (with Barrett reduction)
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensured to be in the range [0, modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func MFormVec(p1, p2 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = MForm(x[0], modulus, bredconstant)
		z[1] = MForm(x[1], modulus, bredconstant)
		z[2] = MForm(x[2], modulus, bredconstant)
		z[3] = MForm(x[3], modulus, bredconstant)
		z[4] = MForm(x[4], modulus, bredconstant)
		z[5] = MForm(x[5], modulus, bredconstant)
		z[6] = MForm(x[6], modulus, bredconstant)
		z[7] = MForm(x[7], modulus, bredconstant)
	}
}

// MFormLazyVec evaluates p2 = p1 * 2^{64} % modulus (with Barrett reduction)
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MFormLazyVec(p1, p2 []uint64, modulus uint64, bredconstant [2]uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = MFormLazy(x[0], modulus, bredconstant)
		z[1] = MFormLazy(x[1], modulus, bredconstant)
		z[2] = MFormLazy(x[2], modulus, bredconstant)
		z[3] = MFormLazy(x[3], modulus, bredconstant)
		z[4] = MFormLazy(x[4], modulus, bredconstant)
		z[5] = MFormLazy(x[5], modulus, bredconstant)
		z[6] = MFormLazy(x[6], modulus, bredconstant)
		z[7] = MFormLazy(x[7], modulus, bredconstant)
	}
}

// IMFormVec evaluates p2 = p1 * (2^{64})^{-1} % modulus (with Montgomery reduction)
//
// Loops are iterated with respect to len(p1)
//
// p2 is ensured to be in the range [0, 2*modulus-1]
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func IMFormVec(p1, p2 []uint64, modulus, mredconstant uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = IMForm(x[0], modulus, mredconstant)
		z[1] = IMForm(x[1], modulus, mredconstant)
		z[2] = IMForm(x[2], modulus, mredconstant)
		z[3] = IMForm(x[3], modulus, mredconstant)
		z[4] = IMForm(x[4], modulus, mredconstant)
		z[5] = IMForm(x[5], modulus, mredconstant)
		z[6] = IMForm(x[6], modulus, mredconstant)
		z[7] = IMForm(x[7], modulus, mredconstant)
	}
}

// ZeroVec evaluates p1 = 0
//
// Loops are iterated with respect to len(p1)
//
// p1 must:
// - be of size of a multiple of 8
//
// This function is constant time.
func ZeroVec(p1 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p1[j]))

		z[0] = 0
		z[1] = 0
		z[2] = 0
		z[3] = 0
		z[4] = 0
		z[5] = 0
		z[6] = 0
		z[7] = 0
	}
}

// MaskVec evaluates p2 = (p1>>w) & mask
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MaskVec(p1 []uint64, w int, mask uint64, p2 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = (x[0] >> w) & mask
		z[1] = (x[1] >> w) & mask
		z[2] = (x[2] >> w) & mask
		z[3] = (x[3] >> w) & mask
		z[4] = (x[4] >> w) & mask
		z[5] = (x[5] >> w) & mask
		z[6] = (x[6] >> w) & mask
		z[7] = (x[7] >> w) & mask
	}
}

// MaskThenAddVec evaluates p2 += (p1>>w) & mask
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func MaskThenAddVec(p1 []uint64, w int, mask uint64, p2 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] += (x[0] >> w) & mask
		z[1] += (x[1] >> w) & mask
		z[2] += (x[2] >> w) & mask
		z[3] += (x[3] >> w) & mask
		z[4] += (x[4] >> w) & mask
		z[5] += (x[5] >> w) & mask
		z[6] += (x[6] >> w) & mask
		z[7] += (x[7] >> w) & mask
	}
}

// RShiftVec evaluates p2 = p1>>w
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func RShiftVec(p1 []uint64, w int, p2 []uint64) {

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		z[0] = x[0] >> w
		z[1] = x[1] >> w
		z[2] = x[2] >> w
		z[3] = x[3] >> w
		z[4] = x[4] >> w
		z[5] = x[5] >> w
		z[6] = x[6] >> w
		z[7] = x[7] >> w
	}
}

// DecomposeUnsigned returns the i-th unsigned digit base 2^{w} of p1 on p2.
//
// p2 is ensured to be in the range [0, 2^{w}-1[, with E[p2] = 2^{w}-1
// and Var[p2] = 2^{w}/12
//
// Loops are iterated with respect to len(p1)
//
// p1, carry, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time.
func DecomposeUnsigned(i int, p1, p2 []uint64, w, modulus uint64) {
	MaskVec(p1, i*int(w), uint64(1<<w)-1, p2)
}

// DecomposeSigned returns the i-th signed digit base 2^{w} of p1 on p2.
//
// The method will read the carry of the i-1-th iteration and write the
// carry on the i-th iteration on the operand "carry"
//
// p2 is ensured to be in the range [-2^{w-1}, 2^{w-1}[, with E[p2] = -0.5
// and Var[p2] = 2^{w}/12
//
// Loops are iterated with respect to len(p1)
//
// p1, carry, p2 must:
// - be of the same size
// - be of size of a multiple of 8
//
// This function is constant time except for a single condition on i.
func DecomposeSigned(i int, p1, carry, p2 []uint64, w, modulus uint64) {

	base := uint64(1 << w)
	N := len(p1)
	mask := uint64(1<<w) - 1

	if i == 0 {
		MaskVec(p1, i*int(w), mask, carry)
	} else {
		MaskThenAddVec(p1, i*int(w), mask, carry)
	}

	var b uint64

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(carry)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&carry[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		b = ((x[0] | (x[0] << 1)) >> w) & 1
		z[0] = x[0] + (modulus-base)*b
		x[0] = b

		b = ((x[1] | (x[1] << 1)) >> w) & 1
		z[1] = x[1] + (modulus-base)*b
		x[1] = b

		b := ((x[2] | (x[2] << 1)) >> w) & 1
		z[2] = x[2] + (modulus-base)*b
		x[2] = b

		b = ((x[3] | (x[3] << 1)) >> w) & 1
		z[3] = x[3] + (modulus-base)*b
		x[3] = b

		b = ((x[4] | (x[4] << 1)) >> w) & 1
		z[4] = x[4] + (modulus-base)*b
		x[4] = b

		b = ((x[5] | (x[5] << 1)) >> w) & 1
		z[5] = x[5] + (modulus-base)*b
		x[5] = b

		b = ((x[6] | (x[6] << 1)) >> w) & 1
		z[6] = x[6] + (modulus-base)*b
		x[6] = b

		b = ((x[7] | (x[7] << 1)) >> w) & 1
		z[7] = x[7] + (modulus-base)*b
		x[7] = b
	}
}

// DecomposeSignedBalanced returns the i-th signed digit base 2^{w} of p1 on p2
//
// The method will read the carry of the i-1-th iteration and write the
// carry on the i-th iteration on the operand "carry"
//
// p2 is ensured to be in the range [-2^{w-1}, 2^{w-1}], with E[p2] = 0
// and Var[p2] = 2^{w}/12
//
// Loops are iterated with respect to len(p1)
//
// p1, carry, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func DecomposeSignedBalanced(i int, p1, carry, p2 []uint64, w, modulus uint64) {

	base := uint64(1 << w)
	N := len(p1)
	mask := uint64(1<<w) - 1

	if i == 0 {
		MaskVec(p1, i*int(w), mask, carry)
	} else {
		MaskThenAddVec(p1, i*int(w), mask, carry)
	}

	var b uint64

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		y := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(carry)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&carry[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		if x[0] == base>>1 {
			b = p1[0] & 1
		} else {
			b = ((x[0] | (x[0] << 1)) >> w) & 1
		}

		z[0] = x[0] + (modulus-base)*b
		x[0] = b

		if x[1] == base>>1 {
			b = y[1] & 1
		} else {
			b = ((x[1] | (x[1] << 1)) >> w) & 1
		}

		z[1] = x[1] + (modulus-base)*b
		x[1] = b

		if x[2] == base>>1 {
			b = y[2] & 1
		} else {
			b = ((x[2] | (x[2] << 1)) >> w) & 1
		}

		z[2] = x[2] + (modulus-base)*b
		x[2] = b

		if x[3] == base>>1 {
			b = y[3] & 1
		} else {
			b = ((x[3] | (x[3] << 1)) >> w) & 1
		}

		z[3] = x[3] + (modulus-base)*b
		x[3] = b

		if x[4] == base>>1 {
			b = y[4] & 1
		} else {
			b = ((x[4] | (x[4] << 1)) >> w) & 1
		}

		z[4] = x[4] + (modulus-base)*b
		x[4] = b

		if x[5] == base>>1 {
			b = y[5] & 1
		} else {
			b = ((x[5] | (x[5] << 1)) >> w) & 1
		}

		z[5] = x[5] + (modulus-base)*b
		x[5] = b

		if x[6] == base>>1 {
			b = y[6] & 1
		} else {
			b = ((x[6] | (x[6] << 1)) >> w) & 1
		}

		z[6] = x[6] + (modulus-base)*b
		x[6] = b

		if x[7] == base>>1 {
			b = y[7] & 1
		} else {
			b = ((x[7] | (x[7] << 1)) >> w) & 1
		}

		z[7] = x[7] + (modulus-base)*b
		x[7] = b
	}
}

// CenterModU64Vec evaluates p2 = p1 - w if p1 >= (w>>1) % 2^{64}
//
// Loops are iterated with respect to len(p1)
//
// p1, p2 must:
// - be of the same size
// - be of size of a multiple of 8
func CenterModU64Vec(p1 []uint64, w uint64, p2 []uint64) {

	qhalf := w >> 1

	N := len(p1)

	for j := 0; j < N; j = j + 8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 */
		x := (*[8]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 */
		z := (*[8]uint64)(unsafe.Pointer(&p2[j]))

		if x[0] >= qhalf {
			z[0] = x[0] - w
		} else {
			z[0] = x[0]
		}

		if x[1] >= qhalf {
			z[1] = x[1] - w
		} else {
			z[1] = x[1]
		}

		if x[2] >= qhalf {
			z[2] = x[2] - w
		} else {
			z[2] = x[2]
		}

		if x[3] >= qhalf {
			z[3] = x[3] - w
		} else {
			z[3] = x[3]
		}

		if x[4] >= qhalf {
			z[4] = x[4] - w
		} else {
			z[4] = x[4]
		}

		if x[5] >= qhalf {
			z[5] = x[5] - w
		} else {
			z[5] = x[5]
		}

		if x[6] >= qhalf {
			z[6] = x[6] - w
		} else {
			z[6] = x[6]
		}

		if x[7] >= qhalf {
			z[7] = x[7] - w
		} else {
			z[7] = x[7]
		}
	}
}
