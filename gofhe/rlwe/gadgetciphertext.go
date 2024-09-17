package rlwe

import (
	"bufio"
	"fmt"
	"io"
	"slices"

	"app/gofhe/ring"
	"app/gofhe/utils/buffer"
	"app/gofhe/utils/structs"

	"github.com/google/go-cmp/cmp"
)

// GadgetCiphertext is a struct for storing an encrypted
// plaintext times the gadget power matrix.
type GadgetCiphertext struct {
	*CompressionInfos
	DigitDecomposition
	structs.Vector[ring.Matrix]
}

// NewGadgetCiphertext returns a new Ciphertext key with pre-allocated zero-value.
// Ciphertext is always in the NTT domain.
// A GadgetCiphertext is created by default at degree 1 with the the maximum LevelQ and LevelP and with no base 2 decomposition.
// Give the optional GadgetCiphertextParameters struct to create a GadgetCiphertext with at a specific degree, LevelQ, LevelP and/or base 2 decomposition.
func NewGadgetCiphertext(params ParameterProvider, Degree, LevelQ, LevelP int, DD DigitDecomposition) (ct *GadgetCiphertext) {
	ct = new(GadgetCiphertext)
	ct.FromBuffer(params, Degree, LevelQ, LevelP, DD, make([]uint64, ct.BufferSize(params, Degree, LevelQ, LevelP, DD)))
	return
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (ct *GadgetCiphertext) BufferSize(params ParameterProvider, Degree, LevelQ, LevelP int, DD DigitDecomposition) (size int) {
	if LevelP > 0 {
		DD = DigitDecomposition{}
	}
	p := params.GetRLWEParameters()
	dims := p.DecompositionMatrixDimensions(LevelQ, LevelP, DD)
	return new(ring.Matrix).BufferSize(p.N(), LevelQ, LevelP, dims) * (Degree + 1)
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (ct *GadgetCiphertext) FromBuffer(params ParameterProvider, Degree, LevelQ, LevelP int, DD DigitDecomposition, buf []uint64) {

	if size := ct.BufferSize(params, Degree, LevelQ, LevelP, DD); len(buf) < size {
		panic(fmt.Errorf("invalid buffer size: len(buf)=%d < %d ", len(buf), size))
	}

	p := params.GetRLWEParameters()

	if LevelP > 0 {
		DD = DigitDecomposition{}
	}

	dims := p.DecompositionMatrixDimensions(LevelQ, LevelP, DD)

	var ptr int
	ct.Vector = make([]ring.Matrix, Degree+1)
	for i := range Degree + 1 {
		ct.Vector[i].FromBuffer(p.N(), LevelQ, LevelP, dims, buf[ptr:])
		ptr += ct.Vector[i].BufferSize(p.N(), LevelQ, LevelP, dims)
	}

	ct.DigitDecomposition = DD
}

// Degree returns the degree of the receiver.
func (ct GadgetCiphertext) Degree() int {
	return len(ct.Vector) - 1
}

// LevelQ returns the level of the modulus Q of the receiver.
func (ct GadgetCiphertext) LevelQ() int {
	return ct.Vector[0].LevelQ()
}

// LevelP returns the level of the modulus P of the receiver.
func (ct GadgetCiphertext) LevelP() int {
	return ct.Vector[0].LevelP()
}

// At returns the [rlwe.Ciphertext] at position [i][j] in the receiver.
func (ct GadgetCiphertext) At(i, j int) (el *Ciphertext) {
	el = &Ciphertext{}
	el.Vector = &ring.Vector{}
	el.MetaData = &MetaData{}
	el.IsNTT = true
	el.IsMontgomery = true

	if ct.Degree() == 0 {
		el.Q = []ring.Poly{ct.Vector[0].Q[i][j]}

		if ct.LevelP() > -1 {
			el.P = []ring.Poly{ct.Vector[0].P[i][j]}
		}
	} else {
		el.Q = []ring.Poly{ct.Vector[0].Q[i][j], ct.Vector[1].Q[i][j]}

		if ct.LevelP() > -1 {
			el.P = []ring.Poly{ct.Vector[0].P[i][j], ct.Vector[1].P[i][j]}
		}
	}

	return
}

// Dims returns the dimension of the receiver.
func (ct GadgetCiphertext) Dims() (dims []int) {
	return ct.Vector[0].Dims()
}

// Equal checks two Ciphertexts for equality.
func (ct GadgetCiphertext) Equal(other *GadgetCiphertext) bool {
	return (ct.DigitDecomposition == other.DigitDecomposition) && cmp.Equal(ct.Vector, other.Vector)
}

// Clone creates a deep copy of the receiver Ciphertext and returns it.
func (ct GadgetCiphertext) Clone() (ctCopy *GadgetCiphertext) {
	return &GadgetCiphertext{DigitDecomposition: ct.DigitDecomposition, Vector: ct.Vector.Clone()}
}

// BinarySize returns the serialized size of the object in bytes.
func (ct GadgetCiphertext) BinarySize() (dataLen int) {
	return 2 + ct.Vector.BinarySize()
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
func (ct GadgetCiphertext) WriteTo(w io.Writer) (n int64, err error) {

	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.WriteAsUint8[DigitDecompositionType](w, ct.Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[int](w, ct.Log2Basis); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = ct.Vector.WriteTo(w)

		return n + inc, err

	default:
		return ct.WriteTo(bufio.NewWriter(w))
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
func (ct *GadgetCiphertext) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.ReadAsUint8[DigitDecompositionType](r, &ct.Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[int](r, &ct.Log2Basis); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = ct.Vector.ReadFrom(r)

		return n + inc, err

	default:
		return ct.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (ct GadgetCiphertext) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(ct.BinarySize())
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (ct *GadgetCiphertext) UnmarshalBinary(p []byte) (err error) {
	_, err = ct.ReadFrom(buffer.NewBuffer(p))
	return
}

// AddPlaintextToMatrix takes a plaintext polynomial and adds the plaintext times the gadget decomposition
// matrix to the matrix ct.
func AddPlaintextToMatrix(rQ, rP *ring.Ring, pt, buff ring.Poly, ct ring.Matrix, dd DigitDecomposition) (err error) {

	LevelQ := ct.LevelQ()
	LevelP := ct.LevelP()

	rQ = rQ.AtLevel(LevelQ)

	if LevelP != -1 {
		rQ.MulScalarBigint(pt, rP.AtLevel(LevelP).Modulus(), buff) // P * pt
	} else {
		LevelP = 0
		buff.CopyLvl(LevelQ, &pt) // 1 * pt
	}

	dims := ct.Dims()

	N := rQ.N()

	var index int
	for j := range slices.Max(dims) {

		for i := range dims {

			if j < dims[i] {

				// e + (m * P * w^2j) * (q_star * q_tild) mod QP
				//
				// q_prod = prod(q[i*#Pi+j])
				// q_star = Q/qprod
				// q_tild = q_star^-1 mod q_prod
				//
				// Therefore : (pt * P * w^2j) * (q_star * q_tild) = pt*P*w^2j mod q[i*#Pi+j], else 0
				for k := 0; k < LevelP+1; k++ {

					index = i*(LevelP+1) + k

					// Handle cases where #pj does not divide #qi
					if index >= LevelQ+1 {
						break
					}

					qi := rQ.SubRings[index].Modulus
					p0tmp := buff.At(index)

					p1tmp := ct.Q[i][j].At(index)
					for w := 0; w < N; w++ {
						p1tmp[w] = ring.CRed(p1tmp[w]+p0tmp[w], qi)
					}
				}
			}
		}

		// w^2j
		rQ.MulScalar(buff, 1<<dd.Log2Basis, buff)
	}

	return
}

// GadgetPlaintext stores a plaintext value times the gadget vector.
type GadgetPlaintext struct {
	Value structs.Vector[ring.Poly]
}

// NewGadgetPlaintext creates a new gadget plaintext from value, which can be either uint64, int64 or *ring.Poly.
// Plaintext is returned in the NTT and Montgomery domain.
func NewGadgetPlaintext(p Parameters, value interface{}, LevelQ, LevelP int, dd DigitDecomposition) (pt *GadgetPlaintext, err error) {

	ringQ := p.RingQ().AtLevel(LevelQ)

	BaseTwoDecompositionVectorSize := slices.Max(p.DecompositionMatrixDimensions(LevelQ, LevelP, dd))

	pt = new(GadgetPlaintext)
	pt.Value = make([]ring.Poly, BaseTwoDecompositionVectorSize)

	switch el := value.(type) {
	case uint64:
		pt.Value[0] = ringQ.NewPoly()
		for i := 0; i < LevelQ+1; i++ {
			pt.Value[0].At(i)[0] = el
		}
	case int64:
		pt.Value[0] = ringQ.NewPoly()
		if el < 0 {
			for i := 0; i < LevelQ+1; i++ {
				pt.Value[0].At(i)[0] = ringQ.SubRings[i].Modulus - uint64(-el)
			}
		} else {
			for i := 0; i < LevelQ+1; i++ {
				pt.Value[0].At(i)[0] = uint64(el)
			}
		}
	case ring.Poly:
		pt.Value[0] = *el.Clone()
	default:
		return nil, fmt.Errorf("cannot NewGadgetPlaintext: unsupported type, must be either int64, uint64 or ring.Poly but is %T", el)
	}

	if LevelP > -1 {
		ringQ.MulScalarBigint(pt.Value[0], p.RingP().AtLevel(LevelP).Modulus(), pt.Value[0])
	}

	ringQ.NTT(pt.Value[0], pt.Value[0])
	ringQ.MForm(pt.Value[0], pt.Value[0])

	for i := 1; i < len(pt.Value); i++ {

		pt.Value[i] = *pt.Value[0].Clone()

		for j := 0; j < i; j++ {
			ringQ.MulScalar(pt.Value[i], 1<<dd.Log2Basis, pt.Value[i])
		}
	}

	return
}
