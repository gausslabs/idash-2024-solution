package ring

import (
	"math/big"

	"app/gofhe/utils/bignum"
)

// Add evaluates p3 = p1 + p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) Add(p1, p2, p3 []uint64) {
	AddVec(p1, p2, p3, s.Modulus)
}

// AddLazy evaluates p3 = p1 + p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) AddLazy(p1, p2, p3 []uint64) {
	AddLazyVec(p1, p2, p3)
}

// Sub evaluates p3 = p1 - p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) Sub(p1, p2, p3 []uint64) {
	SubVec(p1, p2, p3, s.Modulus)
}

// SubLazy evaluates p3 = p1 - p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) SubLazy(p1, p2, p3 []uint64) {
	SubLazyVec(p1, p2, p3, s.Modulus)
}

// Neg evaluates p2 = -p1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) Neg(p1, p2 []uint64) {
	NegVec(p1, p2, s.Modulus)
}

// Reduce evaluates p2 = p1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) Reduce(p1, p2 []uint64) {
	BarrettReduceVec(p1, p2, s.Modulus, s.BRedConstant)
}

// ReduceLazy evaluates p2 = p1 (mod modulus) with p2 in range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) ReduceLazy(p1, p2 []uint64) {
	BarrettReduceLazyVec(p1, p2, s.Modulus, s.BRedConstant)
}

// MulCoeffsLazy evaluates p3 = p1*p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsLazy(p1, p2, p3 []uint64) {
	MulVec(p1, p2, p3)
}

// MulCoeffsLazyThenAddLazy evaluates p3 = p3 + p1*p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsLazyThenAddLazy(p1, p2, p3 []uint64) {
	MulThenAddLazyVec(p1, p2, p3)
}

// MulCoeffsBarrett evaluates p3 = p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsBarrett(p1, p2, p3 []uint64) {
	MulBarrettReduceVec(p1, p2, p3, s.Modulus, s.BRedConstant)
}

// MulCoeffsBarrettLazy evaluates p3 = p1*p2 (mod modulus) with p3 in [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsBarrettLazy(p1, p2, p3 []uint64) {
	MulBarrettReduceLazyVec(p1, p2, p3, s.Modulus, s.BRedConstant)
}

// MulCoeffsBarrettThenAdd evaluates p3 = p3 + (p1*p2) (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsBarrettThenAdd(p1, p2, p3 []uint64) {
	MulBarrettReduceThenAddVec(p1, p2, p3, s.Modulus, s.BRedConstant)
}

// MulCoeffsBarrettThenAddLazy evaluates p3 = p3 + p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsBarrettThenAddLazy(p1, p2, p3 []uint64) {
	MulBarrettReduceThenAddLazyVec(p1, p2, p3, s.Modulus, s.BRedConstant)
}

// MulCoeffsMontgomery evaluates p3 = p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomery(p1, p2, p3 []uint64) {
	MulMontgomeryReduceVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryLazy evaluates p3 = p1*p2 (mod modulus) with p3 in range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryThenAdd evaluates p3 = p3 + (p1*p2) (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryThenAdd(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenAddVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryThenAddLazy evaluates p3 = p3 + (p1*p2 (mod modulus)).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryThenAddLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenAddLazyVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryLazyThenAddLazy evaluates p3 = p3 + p1*p2 (mod modulus) with p3 in range [0, 3modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryLazyThenAddLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyThenAddLazyVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryThenSub evaluates p3 = p3 - p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryThenSub(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenSubVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryThenSubLazy evaluates p3 = p3 - p1*p2 (mod modulus) with p3 in range [0, 2*modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryThenSubLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenSubLazyVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryLazyThenSubLazy evaluates p3 = p3 - p1*p2 (mod modulus) with p3 in range [0, 3*modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryLazyThenSubLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyThenSubLazyVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// MulCoeffsMontgomeryLazyThenNeg evaluates p3 = - p1*p2 (mod modulus) with p3 in range [0, 2*modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulCoeffsMontgomeryLazyThenNeg(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyThenNegLazyVec(p1, p2, p3, s.Modulus, s.MRedConstant)
}

// AddLazyThenMulScalarMontgomery evaluates p3 = (p1+p2)*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) AddLazyThenMulScalarMontgomery(p1, p2 []uint64, scalarMont uint64, p3 []uint64) {
	AddThenMulScalarMontgomeryReduce(p1, p2, scalarMont, p3, s.Modulus, s.MRedConstant)
}

// AddScalarLazyThenMulScalarMontgomery evaluates p3 = (scalarMont0+p2)*scalarMont1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) AddScalarLazyThenMulScalarMontgomery(p1 []uint64, scalar0, scalarMont1 uint64, p2 []uint64) {
	AddScalarThenMulScalarMontgomeryReduceVec(p1, scalar0, scalarMont1, p2, s.Modulus, s.MRedConstant)
}

// AddScalar evaluates p2 = p1 + scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) AddScalar(p1 []uint64, scalar uint64, p2 []uint64) {
	AddScalarVec(p1, scalar, p2, s.Modulus)
}

// AddScalarLazy evaluates p2 = p1 + scalar.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) AddScalarLazy(p1 []uint64, scalar uint64, p2 []uint64) {
	AddScalarLazyVec(p1, scalar, p2)
}

// AddScalarLazyThenNegTwoModulusLazy evaluates p2 = 2*modulus - p1 + scalar.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) AddScalarLazyThenNegTwoModulusLazy(p1 []uint64, scalar uint64, p2 []uint64) {
	AddScalarLazyThenNegateTwoModulusLazyVec(p1, scalar, p2, s.Modulus)
}

// SubScalar evaluates p2 = p1 - scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) SubScalar(p1 []uint64, scalar uint64, p2 []uint64) {
	SubScalarVec(p1, scalar, p2, s.Modulus)
}

// SubScalarBigint evaluates p2 = p1 - scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) SubScalarBigint(p1 []uint64, scalar *big.Int, p2 []uint64) {
	SubScalarVec(p1, new(big.Int).Mod(scalar, bignum.NewInt(s.Modulus)).Uint64(), p2, s.Modulus)
}

// MulScalar evaluates p2 = p1*scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulScalar(p1 []uint64, scalar uint64, p2 []uint64) {
	MulScalarMontgomeryReduceVec(p1, MForm(scalar, s.Modulus, s.BRedConstant), p2, s.Modulus, s.MRedConstant)
}

// MulScalarMontgomery evaluates p2 = p1*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulScalarMontgomery(p1 []uint64, scalarMont uint64, p2 []uint64) {
	MulScalarMontgomeryReduceVec(p1, scalarMont, p2, s.Modulus, s.MRedConstant)
}

// MulScalarMontgomeryLazy evaluates p2 = p1*scalarMont (mod modulus) with p2 in range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulScalarMontgomeryLazy(p1 []uint64, scalarMont uint64, p2 []uint64) {
	MulScalarMontgomeryReduceLazyVec(p1, scalarMont, p2, s.Modulus, s.MRedConstant)
}

// MulScalarMontgomeryThenAdd evaluates p2 = p2 + p1*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulScalarMontgomeryThenAdd(p1 []uint64, scalarMont uint64, p2 []uint64) {
	MulScalarMontgomeryReduceThenAddVec(p1, scalarMont, p2, s.Modulus, s.MRedConstant)
}

// MulScalarMontgomeryThenAddScalar evaluates p2 = scalar + p1*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MulScalarMontgomeryThenAddScalar(p1 []uint64, scalar0, scalarMont1 uint64, p2 []uint64) {
	MulScalarMontgomeryReduceThenAddScalarVec(p1, scalar0, scalarMont1, p2, s.Modulus, s.MRedConstant)
}

// SubThenMulScalarMontgomeryTwoModulus evaluates p3 = (p1 + twomodulus - p2) * scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) SubThenMulScalarMontgomeryTwoModulus(p1, p2 []uint64, scalarMont uint64, p3 []uint64) {
	SubToModulusThenMulScalarMontgomeryReduceVec(p1, p2, scalarMont, p3, s.Modulus, s.MRedConstant)
}

// NTT evaluates p2 = NTT(p1).
func (s *SubRing) NTT(p1, p2 []uint64) {
	s.ntt.Forward(p1, p2)
}

// NTTLazy evaluates p2 = NTT(p1) with p2 in [0, 2*modulus-1].
func (s *SubRing) NTTLazy(p1, p2 []uint64) {
	s.ntt.ForwardLazy(p1, p2)
}

// INTT evaluates p2 = INTT(p1).
func (s *SubRing) INTT(p1, p2 []uint64) {
	s.ntt.Backward(p1, p2)
}

// INTTLazy evaluates p2 = INTT(p1) with p2 in [0, 2*modulus-1].
func (s *SubRing) INTTLazy(p1, p2 []uint64) {
	s.ntt.BackwardLazy(p1, p2)
}

// MForm evaluates p2 = p1 * 2^64 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MForm(p1, p2 []uint64) {
	MFormVec(p1, p2, s.Modulus, s.BRedConstant)
}

// MFormLazy evaluates p2 = p1 * 2^64 (mod modulus) with p2 in the range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) MFormLazy(p1, p2 []uint64) {
	MFormLazyVec(p1, p2, s.Modulus, s.BRedConstant)
}

// IMForm evaluates p2 = p1 * (2^64)^-1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) IMForm(p1, p2 []uint64) {
	IMFormVec(p1, p2, s.Modulus, s.MRedConstant)
}

// CenterModU64 evaluates p2 = center(p1, w) % 2^{64}
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (s *SubRing) CenterModU64(p1 []uint64, p2 []uint64) {
	CenterModU64Vec(p1, s.Modulus, p2)
}

func (s *SubRing) DecomposeUnsigned(j int, pw2 uint64, in, out []uint64) {
	DecomposeUnsigned(j, in, out, pw2, s.Modulus)
}

func (s *SubRing) DecomposeSigned(j int, pw2 uint64, in, carry, out []uint64) {
	DecomposeSigned(j, in, carry, out, pw2, s.Modulus)
}

func (s *SubRing) DecomposeSignedBalanced(j int, pw2 uint64, in, carry, out []uint64) {
	DecomposeSignedBalanced(j, in, carry, out, pw2, s.Modulus)
}
