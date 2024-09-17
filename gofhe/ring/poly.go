package ring

import (
	"bufio"
	"fmt"
	"io"
	"math/bits"

	"app/gofhe/utils"
	"app/gofhe/utils/buffer"
	"app/gofhe/utils/structs"
)

// Poly is the structure that contains the coefficients of an RNS polynomial.
// Coefficients are stored as a matrix backed by an 1D array.
type Poly struct {
	Coeffs structs.Matrix[uint64]
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (p *Poly) BufferSize(N, Level int) int {
	return N * (Level + 1)
}

// FromBuffer assigns new backing array to the receiver.
func (p *Poly) FromBuffer(N, Level int, buf []uint64) {

	if len(buf) < p.BufferSize(N, Level) {
		panic(fmt.Errorf("invalid buffer size: N=%d x (Level+1)=%d < len(p)=%d", N, Level+1, len(buf)))
	}

	p.Coeffs = make([][]uint64, Level+1)
	for i := range Level + 1 {
		p.Coeffs[i] = buf[i*N : (i+1)*N]
	}
}

// NewPoly creates a new polynomial with N coefficients set to zero and Level+1 moduli.
func NewPoly(N, Level int) (p Poly) {
	p.FromBuffer(N, Level, make([]uint64, p.BufferSize(N, Level)))
	return
}

// At returns the i-th row of the receiver.
func (p *Poly) At(i int) []uint64 {
	return p.Coeffs[i]
}

// Resize resizes the level of the target polynomial to the provided level.
// If the provided level is larger than the current level, then allocates zero
// coefficients, otherwise dereferences the coefficients above the provided level.
func (p *Poly) Resize(level int) {
	N := p.N()
	if p.Level() > level {
		p.Coeffs = p.Coeffs[:level+1]
	} else if level > p.Level() {
		prevLevel := p.Level()
		p.Coeffs = append(p.Coeffs, make([][]uint64, level-prevLevel)...)
		for i := prevLevel + 1; i < level+1; i++ {
			p.Coeffs[i] = make([]uint64, N)
		}
	}
}

// N returns the number of coefficients of the polynomial, which equals the degree of the Ring cyclotomic polynomial.
func (p Poly) N() int {
	if len(p.Coeffs) == 0 {
		return 0
	}
	return len(p.At(0))
}

// LogN returns the base two logarithm of the number of coefficients of the polynomial.
func (p Poly) LogN() int {
	return bits.Len64(uint64(p.N()) - 1)
}

// Level returns the current number of moduli minus 1.
func (p Poly) Level() int {
	return len(p.Coeffs) - 1
}

// Zero sets all coefficients of the target polynomial to 0.
func (p Poly) Zero() {
	for i := range p.Coeffs {
		ZeroVec(p.At(i))
	}
}

// Clone creates an exact copy of the target polynomial.
func (p Poly) Clone() *Poly {
	return &Poly{
		Coeffs: p.Coeffs.Clone(),
	}
}

// Copy copies the coefficients of p1 on the target polynomial.
// This method does nothing if the underlying arrays are the same.
// This method will resize the target polynomial to the level of
// the input polynomial.
func (p *Poly) Copy(p1 *Poly) {
	p.Resize(p1.Level())
	p.CopyLvl(p1.Level(), p1)
}

// CopyLvl copies the coefficients of p1 on the target polynomial.
// This method does nothing if the underlying arrays are the same.
// Expects the degree of both polynomials to be identical.
func (p *Poly) CopyLvl(level int, p1 *Poly) {
	for i := 0; i < level+1; i++ {
		if !utils.Alias1D(p.At(i), p1.At(i)) {
			copy(p.At(i), p1.At(i))
		}
	}
}

// SwitchRingDegree changes the ring degree of p0 to the one of p1.
// Maps Y^{N/n} -> X^{N} or X^{N} -> Y^{N/n}.
// Inputs are expected to not be in the NTT domain.
func (r Ring) SwitchRingDegree(p0, p1 Poly) {

	NIn, NOut := p0.N(), p1.N()

	gapIn, gapOut := NOut/NIn, 1
	if NIn > NOut {
		gapIn, gapOut = 1, NIn/NOut
	}

	for j := range r.SubRings[:r.level+1] {
		tmp0, tmp1 := p1.At(j), p0.At(j)
		for w0, w1 := 0, 0; w0 < NOut; w0, w1 = w0+gapIn, w1+gapOut {
			tmp0[w0] = tmp1[w1]
		}
	}
}

// SwitchRingDegreeNTT changes the ring degree of p0 to the one of p1.
// Maps Y^{N/n} -> X^{N} or X^{N} -> Y^{N/n}.
// Inputs are expected to be in the NTT domain.
func (r Ring) SwitchRingDegreeNTT(p0 Poly, buff []uint64, p1 Poly) {

	NIn, NOut := p0.N(), p1.N()

	if NIn > NOut {

		gap := NIn / NOut

		for j, s := range r.SubRings[:r.level+1] {

			tmpIn, tmpOut := p0.At(j), p1.At(j)

			s.INTT(tmpIn, buff)

			for w0, w1 := 0, 0; w0 < NOut; w0, w1 = w0+1, w1+gap {
				tmpOut[w0] = buff[w1]
			}

			switch r.Type() {
			case Standard:
				NTTStandard(tmpOut, tmpOut, NOut, s.Modulus, s.MRedConstant, s.BRedConstant, s.RootsForward)
			case ConjugateInvariant:
				NTTConjugateInvariant(tmpOut, tmpOut, NOut, s.Modulus, s.MRedConstant, s.BRedConstant, s.RootsForward)
			}
		}

	} else {
		gap := NOut / NIn

		for j := range p0.Coeffs {
			tmpIn := p0.At(j)
			tmpOut := p1.At(j)
			for i := range p0.At(0) {
				c := tmpIn[i]
				for w := 0; w < gap; w++ {
					tmpOut[i*gap+w] = c
				}
			}
		}
	}
}

// Equal returns true if the receiver Poly is equal to the provided other Poly.
// This function checks for strict equality between the polynomial coefficients
// (i.e., it does not consider congruence as equality within the ring like
// `Ring.Equal` does).
func (p Poly) Equal(other *Poly) bool {
	return p.Coeffs.Equal(other.Coeffs)
}

// BinarySize returns the serialized size of the object in bytes.
func (p Poly) BinarySize() (size int) {
	return p.Coeffs.BinarySize()
}

// WriteTo writes the object on an io.Writer. It implements the io.WriterTo
// interface, and will write exactly object.BinarySize() bytes on w.
//
// Unless w implements the buffer.Writer interface (see gofhe/utils/buffer/writer.go),
// it will be wrapped into a bufio.Writer. Since this requires allocations, it
// is preferable to pass a buffer.Writer directly:
//
//   - When writing multiple times to a io.Writer, it is preferable to first wrap the
//     io.Writer in a pre-allocated bufio.Writer.
//   - When writing to a pre-allocated var b []byte, it is preferable to pass
//     buffer.NewBuffer(b) as w (see gofhe/utils/buffer/buffer.go).
func (p Poly) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		if n, err = p.Coeffs.WriteTo(w); err != nil {
			return
		}
		return n, w.Flush()
	default:
		return p.WriteTo(bufio.NewWriter(w))
	}
}

// ReadFrom reads on the object from an io.Writer. It implements the
// io.ReaderFrom interface.
//
// Unless r implements the buffer.Reader interface (see see gofhe/utils/buffer/reader.go),
// it will be wrapped into a bufio.Reader. Since this requires allocation, it
// is preferable to pass a buffer.Reader directly:
//
//   - When reading multiple values from a io.Reader, it is preferable to first
//     first wrap io.Reader in a pre-allocated bufio.Reader.
//   - When reading from a var b []byte, it is preferable to pass a buffer.NewBuffer(b)
//     as w (see gofhe/utils/buffer/buffer.go).
func (p *Poly) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:
		if n, err = p.Coeffs.ReadFrom(r); err != nil {
			return
		}
		return n, nil
	default:
		return p.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (p Poly) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(p.BinarySize())
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (p *Poly) UnmarshalBinary(data []byte) (err error) {
	_, err = p.ReadFrom(buffer.NewBuffer(data))
	return
}
