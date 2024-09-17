// Package ring implements RNS-accelerated modular arithmetic operations for polynomials, including:
// RNS basis extension; RNS rescaling; number theoretic transform (NTT); uniform, Gaussian and ternary sampling.
package ring

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"app/gofhe/utils"
	"app/gofhe/utils/bignum"
)

const (
	// GaloisGen is an integer of order N/2 modulo M that spans Z_M with the integer -1.
	// The j-th ring automorphism takes the root zeta to zeta^(5j).
	GaloisGen uint64 = 5

	// MinimumRingDegreeForLoopUnrolledOperations is the minimum ring degree required to
	// safely perform loop-unrolled operations
	MinimumRingDegreeForLoopUnrolledOperations = 8
)

// Type is the type of ring used by the cryptographic scheme
type Type int

// RingStandard and RingConjugateInvariant are two types of Rings.
const (
	Standard           = Type(0) // Z[X]/(X^N + 1) (Default)
	ConjugateInvariant = Type(1) // Z[X+X^-1]/(X^2N + 1)
)

// Ring is a structure that keeps all the variables required to operate on a polynomial represented in this ring.
type Ring struct {
	SubRings []*SubRing
	level    int
}

// NewRing creates a new RNS Ring with degree N and coefficient moduli Moduli with Standard NTT. N must be a power of two larger than 8. Moduli should be
// a non-empty []uint64 with distinct prime elements. All moduli must also be equal to 1 modulo 2*N.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRing(N int, Moduli []uint64) (r *Ring, err error) {
	return NewRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerStandard, 2*N)
}

// NewRingConjugateInvariant creates a new RNS Ring with degree N and coefficient moduli Moduli with Conjugate Invariant NTT. N must be a power of two larger than 8. Moduli should be
// a non-empty []uint64 with distinct prime elements. All moduli must also be equal to 1 modulo 4*N.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRingConjugateInvariant(N int, Moduli []uint64) (r *Ring, err error) {
	return NewRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerConjugateInvariant, 4*N)
}

// NewRingFromType creates a new RNS Ring with degree N and coefficient moduli Moduli for which the type of NTT is determined by the ringType argument.
// If ringType==Standard, the ring is instantiated with standard NTT with the Nth root of unity 2*N. If ringType==ConjugateInvariant, the ring
// is instantiated with a ConjugateInvariant NTT with Nth root of unity 4*N. N must be a power of two larger than 8.
// Moduli should be a non-empty []uint64 with distinct prime elements. All moduli must also be equal to 1 modulo the root of unity.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRingFromType(N int, Moduli []uint64, ringType Type) (r *Ring, err error) {
	switch ringType {
	case Standard:
		return NewRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerStandard, 2*N)
	case ConjugateInvariant:
		return NewRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerConjugateInvariant, 4*N)
	default:
		return nil, fmt.Errorf("invalid ring type")
	}
}

// NewRingWithCustomNTT creates a new RNS Ring with degree N and coefficient moduli Moduli with user-defined NTT transform and primitive Nth root of unity.
// ModuliChain should be a non-empty []uint64 with distinct prime elements.
// All moduli must also be equal to 1 modulo the root of unity.
// N must be a power of two larger than 8. An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRingWithCustomNTT(N int, ModuliChain []uint64, ntt func(*SubRing, int) NumberTheoreticTransformer, NthRoot int) (r *Ring, err error) {
	r = new(Ring)

	// Checks if N is a power of 2
	if N < MinimumRingDegreeForLoopUnrolledOperations || (N&(N-1)) != 0 && N != 0 {
		return nil, fmt.Errorf("invalid ring degree: must be a power of 2 greater than %d", MinimumRingDegreeForLoopUnrolledOperations)
	}

	if len(ModuliChain) == 0 {
		return nil, fmt.Errorf("invalid ModuliChain (must be a non-empty []uint64)")
	}

	if !utils.AllDistinct(ModuliChain) {
		return nil, fmt.Errorf("invalid ModuliChain (moduli are not distinct)")
	}

	r.SubRings = make([]*SubRing, len(ModuliChain))

	for i := range r.SubRings {
		if r.SubRings[i], err = NewSubRingWithCustomNTT(N, ModuliChain[i], 1, ntt, NthRoot); err != nil {
			return nil, err
		}
	}

	r.level = len(ModuliChain) - 1

	return r, r.GenerateNTTConstants(nil, nil)
}

// N returns the ring degree.
func (r *Ring) N() int {
	return r.SubRings[0].N
}

// LogN returns log2(ring degree).
func (r *Ring) LogN() int {
	return bits.Len64(uint64(r.N() - 1))
}

// LogModuli returns the size of the extended modulus P in bits
func (r *Ring) LogModuli() (logmod float64) {
	for _, qi := range r.ModuliChain() {
		logmod += math.Log2(float64(qi))
	}
	return
}

// NthRoot returns the multiplicative order of the primitive root.
func (r *Ring) NthRoot() uint64 {
	return r.SubRings[0].NthRoot
}

// ModuliChainLength returns the number of primes in the RNS basis of the ring.
func (r *Ring) ModuliChainLength() int {
	return len(r.SubRings)
}

// Level returns the level of the current ring.
func (r *Ring) Level() int {
	return r.level
}

// AtLevel returns an instance of the target ring that operates at the target level.
// This instance is thread safe and can be use concurrently with the base ring.
func (r *Ring) AtLevel(level int) *Ring {

	// Sanity check
	if level < 0 {
		panic("level cannot be negative")
	}

	// Sanity check
	if level > r.MaxLevel() {
		panic("level cannot be larger than max level")
	}

	return &Ring{
		SubRings: r.SubRings,
		level:    level,
	}
}

// MaxLevel returns the maximum level allowed by the ring (#NbModuli -1).
func (r *Ring) MaxLevel() int {
	return r.ModuliChainLength() - 1
}

// ModuliChain returns the list of primes in the modulus chain.
func (r *Ring) ModuliChain() (moduli []uint64) {
	moduli = make([]uint64, len(r.SubRings))
	for i := range r.SubRings {
		moduli[i] = r.SubRings[i].Modulus
	}

	return
}

// MRedConstants returns the concatenation of the Montgomery constants
// of the target ring.
func (r *Ring) MRedConstants() (MRC []uint64) {
	MRC = make([]uint64, len(r.SubRings))
	for i := range r.SubRings {
		MRC[i] = r.SubRings[i].MRedConstant
	}

	return
}

// BRedConstants returns the concatenation of the Barrett constants
// of the target ring.
func (r *Ring) BRedConstants() (BRC [][2]uint64) {
	BRC = make([][2]uint64, len(r.SubRings))
	for i := range r.SubRings {
		BRC[i] = r.SubRings[i].BRedConstant
	}

	return
}

// NewPoly creates a new polynomial with all coefficients set to 0.
func (r *Ring) NewPoly() Poly {
	return NewPoly(r.N(), r.level)
}

// NewMonomialXi returns a polynomial X^{i}.
func (r *Ring) NewMonomialXi(i int) (p Poly) {

	p = r.NewPoly()

	N := r.N()

	i &= (N << 1) - 1

	if i >= N {
		i -= N << 1
	}

	for k, s := range r.SubRings[:r.level+1] {

		if i < 0 {
			p.At(k)[N+i] = s.Modulus - 1
		} else {
			p.At(k)[i] = 1
		}
	}

	return
}

// SetCoefficientsBigint sets the coefficients of p1 from an array of Int variables.
func (r *Ring) SetCoefficientsBigint(coeffs []big.Int, p1 Poly) {

	QiBigint := new(big.Int)
	coeffTmp := new(big.Int)
	for i, table := range r.SubRings[:r.level+1] {

		QiBigint.SetUint64(table.Modulus)

		p1Coeffs := p1.At(i)

		for j := range coeffs {
			p1Coeffs[j] = coeffTmp.Mod(&coeffs[j], QiBigint).Uint64()
		}
	}
}

// PolyToString reconstructs p1 and returns the result in an array of string.
func (r *Ring) PolyToString(p1 Poly) []string {

	coeffsBigint := make([]big.Int, r.N())
	r.PolyToBigint(p1, 1, coeffsBigint)
	coeffsString := make([]string, len(coeffsBigint))

	for i := range coeffsBigint {
		coeffsString[i] = coeffsBigint[i].String()
	}

	return coeffsString
}

// PolyToBigint reconstructs p1 and returns the result in an array of Int.
// gap defines coefficients X^{i*gap} that will be reconstructed.
// For example, if gap = 1, then all coefficients are reconstructed, while
// if gap = 2 then only coefficients X^{2*i} are reconstructed.
func (r *Ring) PolyToBigint(p1 Poly, gap int, coeffsBigint []big.Int) {

	crtReconstruction := make([]*big.Int, r.level+1)

	QiB := new(big.Int)
	tmp := new(big.Int)
	modulusBigint := r.Modulus()

	for i, table := range r.SubRings[:r.level+1] {
		QiB.SetUint64(table.Modulus)
		crtReconstruction[i] = new(big.Int).Quo(modulusBigint, QiB)
		tmp.ModInverse(crtReconstruction[i], QiB)
		tmp.Mod(tmp, QiB)
		crtReconstruction[i].Mul(crtReconstruction[i], tmp)
	}

	N := r.N()

	for i, j := 0, 0; j < N; i, j = i+1, j+gap {
		tmp.SetUint64(0)
		for k := 0; k < r.level+1; k++ {
			coeffsBigint[i].Add(&coeffsBigint[i], tmp.Mul(bignum.NewInt(p1.At(k)[j]), crtReconstruction[k]))
		}
		coeffsBigint[i].Mod(&coeffsBigint[i], modulusBigint)
	}
}

// PolyToBigintCentered reconstructs p1 and returns the result in an array of Int.
// Coefficients are centered around Q/2
// gap defines coefficients X^{i*gap} that will be reconstructed.
// For example, if gap = 1, then all coefficients are reconstructed, while
// if gap = 2 then only coefficients X^{2*i} are reconstructed.
func (r *Ring) PolyToBigintCentered(p1 Poly, gap int, values []big.Int) {
	PolyToBigintCentered(r, nil, p1, nil, gap, values)
}

// Equal checks if p1 = p2 in the given Ring.
func (r *Ring) Equal(p1, p2 Poly) bool {

	for i := 0; i < r.level+1; i++ {
		if len(p1.At(i)) != len(p2.At(i)) {
			return false
		}
	}

	r.Reduce(p1, p1)
	r.Reduce(p2, p2)

	return p1.Equal(&p2)
}

// Stats returns base 2 logarithm of the standard deviation
// and the mean of the coefficients of the polynomial.
func (r *Ring) Stats(poly Poly) [2]float64 {
	N := r.N()
	values := make([]big.Int, N)
	r.PolyToBigintCentered(poly, 1, values)
	return bignum.Stats(values, 128)
}

// String returns the string representation of the ring Type
func (rt Type) String() string {
	switch rt {
	case Standard:
		return "Standard"
	case ConjugateInvariant:
		return "ConjugateInvariant"
	default:
		return "Invalid"
	}
}

// UnmarshalJSON reads a JSON byte slice into the receiver Type
func (rt *Type) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	default:
		return fmt.Errorf("invalid ring type: %s", s)
	case "Standard":
		*rt = Standard
	case "ConjugateInvariant":
		*rt = ConjugateInvariant
	}

	return nil
}

// Type returns the Type of the first subring which might be either `Standard` or `ConjugateInvariant`.
func (r *Ring) Type() Type {
	return r.SubRings[0].Type()
}

// MarshalJSON marshals the receiver Type into a JSON []byte
func (rt *Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(rt.String())
}

// ConjugateInvariantRing returns the conjugate invariant ring of the receiver ring.
// If `r.Type()==ConjugateInvariant`, then the method returns the receiver.
// if `r.Type()==Standard`, then the method returns a ring with ring degree N/2.
// The returned Ring is a shallow copy of the receiver.
func (r *Ring) ConjugateInvariantRing() (cr *Ring, err error) {

	if r.Type() == ConjugateInvariant {
		return r, nil
	}

	cr = new(Ring)

	cr.SubRings = make([]*SubRing, len(r.SubRings))

	factors := make([][]uint64, len(r.SubRings))

	for i, s := range r.SubRings {

		if cr.SubRings[i], err = NewSubRingWithCustomNTT(s.N>>1, s.Modulus, 1, NewNumberTheoreticTransformerConjugateInvariant, int(s.NthRoot)); err != nil {
			return nil, err
		}

		factors[i] = s.Factors // Allocates factor for faster generation
	}

	return cr, cr.GenerateNTTConstants(nil, factors)
}

// StandardRing returns the standard ring of the receiver ring.
// If `r.Type()==Standard`, then the method returns the receiver.
// if `r.Type()==ConjugateInvariant`, then the method returns a ring with ring degree 2N.
// The returned Ring is a shallow copy of the receiver.
func (r *Ring) StandardRing() (sr *Ring, err error) {

	if r.Type() == Standard {
		return r, nil
	}

	sr = new(Ring)

	sr.SubRings = make([]*SubRing, len(r.SubRings))

	factors := make([][]uint64, len(r.SubRings))

	for i, s := range r.SubRings {

		if sr.SubRings[i], err = NewSubRingWithCustomNTT(s.N<<1, s.Modulus, 1, NewNumberTheoreticTransformerStandard, int(s.NthRoot)); err != nil {
			return nil, err
		}

		factors[i] = s.Factors // Allocates factor for faster generation
	}

	return sr, sr.GenerateNTTConstants(nil, factors)
}

// Concat concatenates other to the receiver producing a new extended ring.
func (r *Ring) Concat(other *Ring) (rnew *Ring) {
	return &Ring{
		SubRings: append(r.SubRings, other.SubRings...),
	}
}

// AddModuli returns an instance of the receiver with an additional modulus.
func (r *Ring) AddModuli(moduli []uint64) (rNew *Ring, err error) {

	if !utils.AllDistinct(append(r.ModuliChain(), moduli...)) {
		return nil, fmt.Errorf("invalid ModuliChain (moduli are not distinct)")
	}

	rNew = new(Ring)

	// Computes bigQ for all levels
	rNew.SubRings = r.SubRings

	var ntt func(*SubRing, int) NumberTheoreticTransformer

	switch r.Type() {
	case Standard:
		ntt = NewNumberTheoreticTransformerStandard
	case ConjugateInvariant:
		ntt = NewNumberTheoreticTransformerConjugateInvariant
	default:
		return nil, fmt.Errorf("invalid ring type")
	}

	for i := range moduli {

		var sNew *SubRing
		if sNew, err = NewSubRingWithCustomNTT(r.N(), moduli[i], 1, ntt, int(r.NthRoot())); err != nil {
			return
		}

		if err = sNew.GenerateNTTConstants(); err != nil {
			return nil, err
		}

		rNew.SubRings = append(rNew.SubRings, sNew)
	}

	rNew.level = len(rNew.SubRings) - 1

	return
}

// Modulus returns the full modulus.
// The internal level of the ring is taken into account.
func (r *Ring) Modulus() (modulus *big.Int) {
	modulus = bignum.NewInt(r.SubRings[0].Modulus)
	for i := 1; i < r.level+1; i++ {
		modulus.Mul(modulus, bignum.NewInt(r.SubRings[i].Modulus))
	}
	return
}

// RescaleConstants returns the rescaling constants for a given level.
func (r *Ring) RescaleConstants(level int) (out []uint64) {

	qj := r.SubRings[level].Modulus

	out = make([]uint64, level)

	for i := 0; i < level; i++ {
		qi := r.SubRings[i].Modulus
		out[i] = MForm(qi-ModExp(qj, qi-2, qi), qi, r.SubRings[i].BRedConstant)
	}

	return
}

// GenerateNTTConstants checks that N has been correctly initialized, and checks that each modulus is a prime congruent to 1 mod 2N (i.e. NTT-friendly).
// Then, it computes the variables required for the NTT. The purpose of ValidateParameters is to validate that the moduli allow the NTT, and to compute the
// NTT parameters.
func (r *Ring) GenerateNTTConstants(primitiveRoots []uint64, factors [][]uint64) (err error) {

	for i := range r.SubRings {

		if primitiveRoots != nil && factors != nil {
			r.SubRings[i].PrimitiveRoot = primitiveRoots[i]
			r.SubRings[i].Factors = factors[i]
		}

		if err = r.SubRings[i].GenerateNTTConstants(); err != nil {
			return
		}
	}

	return nil
}

// ringParametersLiteral is a struct to store the minimum information
// to uniquely identify a Ring and be able to reconstruct it efficiently.
// This struct's purpose is to facilitate the marshalling of Rings.
type ringParametersLiteral []subRingParametersLiteral

// parametersLiteral returns the RingParametersLiteral of the Ring.
func (r *Ring) parametersLiteral() ringParametersLiteral {
	p := make([]subRingParametersLiteral, len(r.SubRings))

	for i, s := range r.SubRings {
		p[i] = s.parametersLiteral()
	}

	return ringParametersLiteral(p)
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (r *Ring) MarshalBinary() (data []byte, err error) {
	return r.MarshalJSON()
}

// UnmarshalBinary decodes a slice of bytes generated by MarshalBinary or MarshalJSON on the object.
func (r *Ring) UnmarshalBinary(data []byte) (err error) {
	return r.UnmarshalJSON(data)
}

// MarshalJSON encodes the object into a binary form on a newly allocated slice of bytes with the json codec.
func (r *Ring) MarshalJSON() (data []byte, err error) {
	return json.Marshal(r.parametersLiteral())
}

// UnmarshalJSON decodes a slice of bytes generated by MarshalJSON or MarshalBinary on the object.
func (r *Ring) UnmarshalJSON(data []byte) (err error) {

	p := ringParametersLiteral{}

	if err = json.Unmarshal(data, &p); err != nil {
		return
	}

	var rr *Ring
	if rr, err = newRingFromparametersLiteral(p); err != nil {
		return
	}

	*r = *rr

	return
}

// newRingFromparametersLiteral creates a new Ring from the provided RingParametersLiteral.
func newRingFromparametersLiteral(p ringParametersLiteral) (r *Ring, err error) {

	r = new(Ring)

	r.SubRings = make([]*SubRing, len(p))

	r.level = len(p) - 1

	for i := range r.SubRings {

		if r.SubRings[i], err = newSubRingFromParametersLiteral(p[i]); err != nil {
			return
		}

		if i > 0 {
			if r.SubRings[i].N != r.SubRings[i-1].N || r.SubRings[i].NthRoot != r.SubRings[i-1].NthRoot {
				return nil, fmt.Errorf("invalid SubRings: all SubRings must have the same ring degree and NthRoot")
			}
		}
	}

	return
}
