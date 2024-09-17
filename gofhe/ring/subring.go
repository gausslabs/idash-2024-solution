package ring

import (
	"fmt"
	"math/big"
	"math/bits"

	"app/gofhe/utils"
	"app/gofhe/utils/factorization"
)

// SubRing is a struct storing precomputation
// for fast modular reduction and NTT for
// a given modulus.
type SubRing struct {
	ntt NumberTheoreticTransformer

	// Polynomial nb.Coefficients
	N int

	BaseModulus uint64

	BaseModulusPower int

	// BaseModulus^BaseModulusPower
	Modulus uint64

	// Unique factors of Modulus-1
	Factors []uint64

	// 2^bit_length(Modulus) - 1
	Mask uint64

	// Fast reduction constants
	BRedConstant [2]uint64 // Barrett Reduction
	MRedConstant uint64    // Montgomery Reduction

	*NTTTable // NTT related constants
}

// NewSubRing creates a new SubRing with the standard NTT.
// NTT constants still need to be generated using .GenNTTConstants(NthRoot uint64).
func NewSubRing(N int, Modulus uint64, ModulusPower int) (s *SubRing, err error) {
	return NewSubRingWithCustomNTT(N, Modulus, ModulusPower, NewNumberTheoreticTransformerStandard, 2*N)
}

// NewSubRingWithCustomNTT creates a new SubRing with degree N and modulus Modulus with user-defined NTT transform and primitive Nth root of unity.
// Modulus should be equal to 1 modulo the root of unity.
// N must be a power of two larger than 8. An error is returned with a nil *SubRing in the case of non NTT-enabling parameters.
func NewSubRingWithCustomNTT(N int, Modulus uint64, ModulusPower int, ntt func(*SubRing, int) NumberTheoreticTransformer, NthRoot int) (s *SubRing, err error) {

	// Checks if N is a power of 2
	if N < MinimumRingDegreeForLoopUnrolledOperations || (N&(N-1)) != 0 && N != 0 {
		return nil, fmt.Errorf("invalid ring degree: must be a power of 2 greater than %d", MinimumRingDegreeForLoopUnrolledOperations)
	}

	if bits.Len64(Modulus)*ModulusPower > 62 {
		return nil, fmt.Errorf("invalid Modulus: Modulus^ModulusPower > 2^61")
	}

	s = &SubRing{}

	s.N = N

	s.BaseModulus = Modulus

	s.Modulus = Modulus
	for i := 1; i < ModulusPower; i++ {
		s.Modulus *= Modulus
	}

	s.BaseModulusPower = ModulusPower

	s.Mask = (1 << uint64(bits.Len64(s.Modulus-1))) - 1

	// Computes the fast modular reduction constants for the Ring
	s.BRedConstant = GetBRedConstant(s.Modulus)

	// If qi is not a power of 2, we can compute the MRed (otherwise, it
	// would return an error as there is no valid Montgomery form mod a power of 2)
	if (s.Modulus&(s.Modulus-1)) != 0 && s.Modulus != 0 {
		s.MRedConstant = GetMRedConstant(s.Modulus)
	}

	s.NTTTable = new(NTTTable)
	s.NthRoot = uint64(NthRoot)

	s.ntt = ntt(s, N)

	return
}

func (s SubRing) LogN() int {
	return bits.Len64(uint64(s.N) - 1)
}

// Phi returns Phi(BaseModulus^BaseModulusPower)
func (s SubRing) Phi() (phi uint64) {
	phi = s.BaseModulus - 1
	for i := 1; i < s.BaseModulusPower; i++ {
		phi *= s.BaseModulus
	}
	return
}

// Type returns the Type of subring which might be either `Standard` or `ConjugateInvariant`.
func (s SubRing) Type() Type {
	switch s.ntt.(type) {
	case NumberTheoreticTransformerStandard:
		return Standard
	case NumberTheoreticTransformerConjugateInvariant:
		return ConjugateInvariant
	default:
		// Sanity check
		panic(fmt.Errorf("invalid NumberTheoreticTransformer type: %T", s.ntt))
	}
}

// GenerateNTTConstants generates the NTT constant for the target SubRing.
// The fields `PrimitiveRoot` and `Factors` can be set manually to
// bypass the search for the primitive root (which requires to
// factor Modulus-1) and speedup the generation of the constants.
func (s *SubRing) GenerateNTTConstants() (err error) {

	if s.N == 0 || s.Modulus == 0 {
		return fmt.Errorf("invalid t parameters (missing)")
	}

	Modulus := s.Modulus
	NthRoot := s.NthRoot

	// Checks if each qi is prime and equal to 1 mod NthRoot
	if !IsPrime(s.BaseModulus) {
		return fmt.Errorf("invalid modulus: %d is not prime)", Modulus)
	}

	if Modulus&(NthRoot-1) != 1 {
		return fmt.Errorf("invalid modulus: %d != 1 mod NthRoot=%d)", Modulus, NthRoot)
	}

	// It is possible to manually set the primitive root along with the factors of q-1.
	// This is notably useful when marshalling the SubRing, to avoid re-factoring q-1.
	// If both are set, then checks that that the root is indeed primitive.
	// Else, factorize q-1 and finds a primitive root.
	if s.PrimitiveRoot != 0 && s.Factors != nil {
		if err = CheckPrimitiveRoot(s.PrimitiveRoot, Modulus, s.Factors); err != nil {
			return
		}
	} else {

		if s.PrimitiveRoot, s.Factors, err = PrimitiveRoot(s.BaseModulus, s.Factors); err != nil {
			return
		}
	}

	logNthRoot := int(bits.Len64(NthRoot>>1) - 1)

	// BaseModulus^{k-1} * (BaseModulus - 1) - 1

	phi := s.Phi()

	// 1.1 Computes N^(-1) mod Q in Montgomery form
	s.NInv = MForm(ModExp(NthRoot>>1, phi-1, Modulus), Modulus, s.BRedConstant)

	// 1.2 Computes Psi and PsiInv in Montgomery form

	// Computes Psi and PsiInv in Montgomery form for BaseModulus
	Psi := ModExp(s.PrimitiveRoot, (s.BaseModulus-1)/NthRoot, s.BaseModulus)

	// Updates the primitive root mod P to mod P^k using Hensel lifting
	Psi = HenselLift(Psi, NthRoot, s.BaseModulus, s.BaseModulusPower)

	PsiMont := MForm(Psi, Modulus, s.BRedConstant)

	// Checks that Psi^{2N} = 1 mod BaseModulus^BaseModulusPower
	if IMForm(ModexpMontgomery(PsiMont, NthRoot, s.Modulus, s.MRedConstant, s.BRedConstant), s.Modulus, s.MRedConstant) != 1 {
		return fmt.Errorf("invalid 2Nth primtive root: psi^{2N} != 1 mod Modulus, something went wrong")
	}

	// Checks that Psi^{N} = -1 mod BaseModulus^BaseModulusPower
	if IMForm(ModexpMontgomery(PsiMont, NthRoot>>1, s.Modulus, s.MRedConstant, s.BRedConstant), s.Modulus, s.MRedConstant) != s.Modulus-1 {
		return fmt.Errorf("invalid 2Nth primtive root: psi^{2N} != 1 mod Modulus, something went wrong")
	}

	PsiInvMont := ModexpMontgomery(PsiMont, phi-1, Modulus, s.MRedConstant, s.BRedConstant)

	s.RootsForward = make([]uint64, NthRoot>>1)
	s.RootsBackward = make([]uint64, NthRoot>>1)

	s.RootsForward[0] = MForm(1, Modulus, s.BRedConstant)
	s.RootsBackward[0] = MForm(1, Modulus, s.BRedConstant)

	// Computes nttPsi[j] = nttPsi[j-1]*Psi and RootsBackward[j] = RootsBackward[j-1]*PsiInv
	for j := uint64(1); j < NthRoot>>1; j++ {

		indexReversePrev := utils.BitReverse64(j-1, logNthRoot)
		indexReverseNext := utils.BitReverse64(j, logNthRoot)

		s.RootsForward[indexReverseNext] = MRed(s.RootsForward[indexReversePrev], PsiMont, Modulus, s.MRedConstant)
		s.RootsBackward[indexReverseNext] = MRed(s.RootsBackward[indexReversePrev], PsiInvMont, Modulus, s.MRedConstant)
	}

	return
}

// PrimitiveRoot computes the smallest primitive root of the given prime q
// The unique factors of q-1 can be given to speed up the search for the root.
func PrimitiveRoot(q uint64, factors []uint64) (uint64, []uint64, error) {

	if factors != nil {
		if err := CheckFactors(q-1, factors); err != nil {
			return 0, factors, err
		}
	} else {

		factorsBig := factorization.GetFactors(new(big.Int).SetUint64(q - 1)) //Factor q-1, might be slow

		factors = make([]uint64, len(factorsBig))
		for i := range factors {
			factors[i] = factorsBig[i].Uint64()
		}
	}

	notFoundPrimitiveRoot := true

	var g uint64 = 2

	for notFoundPrimitiveRoot {
		g++
		for _, factor := range factors {
			// if for any factor of q-1, g^(q-1)/factor = 1 mod q, g is not a primitive root
			if ModExp(g, (q-1)/factor, q) == 1 {
				notFoundPrimitiveRoot = true
				break
			}
			notFoundPrimitiveRoot = false
		}
	}

	return g, factors, nil
}

// CheckFactors checks that the given list of factors contains
// all the unique primes of m.
func CheckFactors(m uint64, factors []uint64) (err error) {

	for _, factor := range factors {

		if !IsPrime(factor) {
			return fmt.Errorf("composite factor")
		}

		for m%factor == 0 {
			m /= factor
		}
	}

	if m != 1 {
		return fmt.Errorf("incomplete factor list")
	}

	return
}

// CheckPrimitiveRoot checks that g is a valid primitive root mod q,
// given the factors of q-1.
func CheckPrimitiveRoot(g, q uint64, factors []uint64) (err error) {

	if err = CheckFactors(q-1, factors); err != nil {
		return
	}

	for _, factor := range factors {
		if ModExp(g, (q-1)/factor, q) == 1 {
			return fmt.Errorf("invalid primitive root")
		}
	}

	return
}

// subRingParametersLiteral is a struct to store the minimum information
// to uniquely identify a SubRing and be able to reconstruct it efficiently.
// This struct's purpose is to faciliate marshalling of SubRings.
type subRingParametersLiteral struct {
	Type             uint8  // Standard or ConjugateInvariant
	LogN             uint8  // Log2 of the ring degree
	NthRoot          uint8  // N/NthRoot
	Modulus          uint64 // Modulus
	BaseModulus      uint64
	BaseModulusPower int
	Factors          []uint64 // Factors of Modulus-1
	PrimitiveRoot    uint64   // Primitive root used
}

// ParametersLiteral returns the SubRingParametersLiteral of the SubRing.
func (s *SubRing) parametersLiteral() subRingParametersLiteral {
	Factors := make([]uint64, len(s.Factors))
	copy(Factors, s.Factors)
	return subRingParametersLiteral{
		Type:             uint8(s.Type()),
		LogN:             uint8(bits.Len64(uint64(s.N - 1))),
		NthRoot:          uint8(int(s.NthRoot) / s.N),
		Modulus:          s.Modulus,
		BaseModulus:      s.BaseModulus,
		BaseModulusPower: s.BaseModulusPower,
		Factors:          Factors,
		PrimitiveRoot:    s.PrimitiveRoot,
	}
}

// newSubRingFromParametersLiteral creates a new SubRing from the provided subRingParametersLiteral.
func newSubRingFromParametersLiteral(p subRingParametersLiteral) (s *SubRing, err error) {

	s = new(SubRing)

	s.N = 1 << int(p.LogN)

	s.NTTTable = new(NTTTable)
	s.NthRoot = uint64(s.N) * uint64(p.NthRoot)

	s.Modulus = p.Modulus
	s.BaseModulus = p.BaseModulus
	s.BaseModulusPower = p.BaseModulusPower

	s.Factors = make([]uint64, len(p.Factors))
	copy(s.Factors, p.Factors)

	s.PrimitiveRoot = p.PrimitiveRoot

	s.Mask = (1 << uint64(bits.Len64(s.Modulus-1))) - 1

	// Computes the fast modular reduction parameters for the Ring
	s.BRedConstant = GetBRedConstant(s.Modulus)

	// If qi is not a power of 2, we can compute the MRed (otherwise, it
	// would return an error as there is no valid Montgomery form mod a power of 2)
	if (s.Modulus&(s.Modulus-1)) != 0 && s.Modulus != 0 {
		s.MRedConstant = GetMRedConstant(s.Modulus)
	}

	switch Type(p.Type) {
	case Standard:

		s.ntt = NewNumberTheoreticTransformerStandard(s, s.N)

		if int(s.NthRoot) < s.N<<1 {
			return nil, fmt.Errorf("invalid ring type: NthRoot must be at least 2N but is %dN", int(s.NthRoot)/s.N)
		}

	case ConjugateInvariant:

		s.ntt = NewNumberTheoreticTransformerConjugateInvariant(s, s.N)

		if int(s.NthRoot) < s.N<<2 {
			return nil, fmt.Errorf("invalid ring type: NthRoot must be at least 4N but is %dN", int(s.NthRoot)/s.N)
		}

	default:
		return nil, fmt.Errorf("invalid ring type")
	}

	return s, s.GenerateNTTConstants()
}

// SetCoefficientsBigint sets the coefficients of p1 from an array of Int variables.
func (s SubRing) SetCoefficientsBigint(coeffs []big.Int, p1 []uint64) {
	QiBigint := new(big.Int)
	coeffTmp := new(big.Int)
	QiBigint.SetUint64(s.Modulus)
	for j := range coeffs {
		p1[j] = coeffTmp.Mod(&coeffs[j], QiBigint).Uint64()
	}
}
