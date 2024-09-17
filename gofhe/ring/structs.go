package ring

import (
	"bufio"
	"fmt"
	"io"
	"slices"

	"app/gofhe/utils/buffer"
	"app/gofhe/utils/sampling"
	"app/gofhe/utils/structs"
)

// Point is a struct storing a
// polynomial in basis Q and P.
type Point struct {
	Q Poly
	P Poly
}

// NewPoint allocates a new [Point].
func NewPoint(N, LevelQ, LevelP int) (p Point) {
	p.FromBuffer(N, LevelQ, LevelP, make([]uint64, p.BufferSize(N, LevelQ, LevelP)))
	return p
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (p *Point) BufferSize(N, LevelQ, LevelP int) int {
	return N * (LevelQ + LevelP + 2)
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (p *Point) FromBuffer(N, LevelQ, LevelP int, buf []uint64) {

	if len(buf) < p.BufferSize(N, LevelQ, LevelP) {
		panic(fmt.Errorf("invalid buffer size: N=%d * (LevelQ+LevelP+2)=%d < len(buf)=%d", N, LevelQ+LevelP+2, len(buf)))
	}

	p.Q.FromBuffer(N, LevelQ, buf)
	p.P.FromBuffer(N, LevelP, buf[p.Q.BufferSize(N, LevelQ):])
}

// ConcatPtoQ returns an instance of the receiver where the modulus Q
// is increased to Q[:] + P[:n] and the modulus P reduced to P[n:].
// n must be a positive integer 0 <= n <= p.LevelP()+1.
// Backing arrays are shared.
func (p Point) ConcatPtoQ(n int) *Point {
	switch {
	case p.LevelP() == -1:
		return &p
	case p.LevelP()+1 >= n && n >= 0:
		return &Point{
			Q: Poly{append(p.Q.Coeffs, p.P.Coeffs[:n]...)},
			P: Poly{p.P.Coeffs[n:]},
		}
	default:
		panic("invalid n: must be a positive integer 0 <= n <= p.LevelP()+1")
	}
}

// ConcatQtoP returns an instance of the receiver where the modulus Q
// is reduced to Q[:n] and the modulus P increased to Q[n:] + P[:].
// n must be a positive integer 0 < n < p.LevelQ()+1.
// Backing arrays are shared.
func (p Point) ConcatQtoP(n int) *Point {
	switch {
	case p.LevelQ()+1 > n && n >= 0:
		offset := p.LevelQ() - n + 1
		return &Point{
			Q: Poly{p.Q.Coeffs[:offset]},
			P: Poly{append(p.Q.Coeffs[offset:], p.P.Coeffs...)},
		}
	default:
		panic("invalid n: must be a positive integer 0 < n < p.LevelQ()+1")
	}
}

func NewPointAtLevelFromPoly(LevelQ, LevelP int, pQ, pP Poly) (Point, error) {

	if pQ.Level() < LevelQ {
		return Point{}, fmt.Errorf("pQ.Level()=%d < LevelQ=%d", pQ.Level(), LevelQ)
	}

	var P Poly
	if pP.Level() < LevelP {
		return Point{}, fmt.Errorf("pP.Level()=%d < LevelP=%d", pP.Level(), LevelP)
	}
	if LevelP > -1 {
		P.Coeffs = pP.Coeffs[:LevelP+1]
	}

	return Point{Q: Poly{pQ.Coeffs[:LevelQ+1]}, P: P}, nil
}

// Equal performs a deep equal.
func (p Point) Equal(other *Point) (equal bool) {
	return p.Q.Equal(&other.Q) && p.P.Equal(&other.P)
}

// AsVector wraps the receiver in an [Vector].
func (p *Point) AsVector() *Vector {
	return &Vector{
		Q: []Poly{p.Q},
		P: []Poly{p.P},
	}
}

// ResizeQ resizes the field Q of the receiver.
func (p *Point) ResizeQ(LevelQ int) {
	if p.LevelQ() != LevelQ {
		p.Q.Resize(LevelQ)
	}
}

// ResizeP resizes the field Q of the receiver.
func (p *Point) ResizeP(LevelP int) {
	if p.LevelP() != LevelP {
		p.P.Resize(LevelP)
	}
}

// N returns the ring degree of the receiver.
func (p Point) N() int {
	return p.Q.N()
}

// LogN returns base two logarithm of the
// ring degree of the receiver.
func (p Point) LogN() int {
	return p.Q.LogN()
}

// Level returns the level of the modulus Q
// of the receiver.
func (p Point) Level() int {
	return p.LevelQ()
}

// LevelQ returns the level of the modulus Q
// of the receiver.
func (p Point) LevelQ() int {
	return p.Q.Level()
}

// LevelP returns the level of the modulus P
// of the receiver.
func (p Point) LevelP() int {
	return p.P.Level()
}

// Clone returns a deep copy of the receiver.
func (p Point) Clone() (clone *Point) {
	clone = new(Point)
	clone.Q = *p.Q.Clone()
	clone.P = *p.P.Clone()
	return
}

// Randomize overwrites the coefficients of the receiver with uniformly
// random coefficients modulo QP.
func (p Point) Randomize(rQ, rP *Ring, source *sampling.Source) {
	NewUniformSampler(source, rQ.ModuliChain()).AtLevel(p.LevelQ()).Read(p.Q)
	if rP != nil && p.LevelP() > -1 {
		NewUniformSampler(source, rP.ModuliChain()).AtLevel(p.LevelP()).Read(p.P)
	}
}

// Aggregate sets the receiver to a + b.
// The method returns an error  if operands do not match the receiver LevelQ(), LevelP().
func (p *Point) Aggregate(rQ, rP *Ring, a, b *Point) (err error) {

	LevelQ := p.LevelQ()
	LevelP := p.LevelP()

	if a.LevelQ() != LevelQ || b.LevelQ() != LevelQ {
		return fmt.Errorf("vectors LevelQ do not match: %d <- %d + %d", LevelQ, a.LevelQ(), b.LevelQ())
	}

	if a.LevelP() != LevelP || b.LevelP() != LevelP {
		return fmt.Errorf("vectors LevelP do not match: %d <- %d + %d", LevelP, a.LevelP(), b.LevelP())
	}

	rQ.AtLevel(LevelQ).Add(a.Q, b.Q, p.Q)

	if rP != nil && LevelP > -1 {
		rP.AtLevel(LevelP).Add(a.P, b.P, p.P)
	}

	return
}

// BinarySize returns the serialized size of the object in bytes.
func (p Point) BinarySize() (size int) {
	return p.Q.BinarySize() + p.P.BinarySize()
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
func (p Point) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = p.Q.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.P.WriteTo(w); err != nil {
			return n + inc, err
		}

		return n + inc, err

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
func (p *Point) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		if p == nil {
			return 0, fmt.Errorf("receiver is nil")
		}

		var inc int64

		if inc, err = p.Q.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.P.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return p.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (p Point) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(p.BinarySize())
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (p *Point) UnmarshalBinary(data []byte) (err error) {
	_, err = p.ReadFrom(buffer.NewBuffer(data))
	return
}

// Vector is a struct storing a vector of
// [ring.Poly] in basis Q and P.
type Vector struct {
	Q structs.Vector[Poly]
	P structs.Vector[Poly]
}

// NewVector allocates a new [ring.Vector].
func NewVector(N, LevelQ, LevelP, size int) (v Vector) {
	v.FromBuffer(N, LevelQ, LevelP, size, make([]uint64, v.BufferSize(N, LevelQ, LevelP, size)))
	return
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (v *Vector) FromBuffer(N, LevelQ, LevelP, size int, buf []uint64) {

	if len(buf) < v.BufferSize(N, LevelQ, LevelP, size) {
		panic(fmt.Errorf("invalid buffer size: N=%d * (LevelQ+LevelP+2)=%d * size=%d < len(buf)=%d", N, LevelQ+LevelP+2, size, len(buf)))
	}

	var ptr int

	v.Q = make([]Poly, size)
	polyBufferSize := v.Q[0].BufferSize(N, LevelQ)
	for i := range size {
		v.Q[i].FromBuffer(N, LevelQ, buf[ptr:])
		ptr += polyBufferSize
	}

	if LevelP > -1 {
		v.P = make([]Poly, size)
		polyBufferSize := v.P[0].BufferSize(N, LevelP)
		for i := range size {
			v.P[i].FromBuffer(N, LevelP, buf[ptr:])
			ptr += polyBufferSize
		}
	}
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (v *Vector) BufferSize(N, LevelQ, LevelP, size int) int {
	return N * (LevelQ + LevelP + 2) * size
}

func NewVectorAtLevelFromPoly(LevelQ, LevelP int, pQ, pP []Poly) (Vector, error) {

	Q := make([]Poly, len(pQ))
	for i := range Q {
		if pQ[i].Level() < LevelQ {
			return Vector{}, fmt.Errorf("pQ[%d].Level()=%d < LevelQ=%d", i, pQ[i].Level(), LevelQ)
		}

		Q[i] = Poly{pQ[i].Coeffs[:LevelQ+1]}
	}

	P := make([]Poly, len(pP))
	for i := range P {
		if pP[i].Level() < LevelP {
			return Vector{}, fmt.Errorf("pP[%d].Level()=%d < LevelP=%d", i, pP[i].Level(), LevelP)
		}

		P[i] = Poly{pP[i].Coeffs[:LevelP+1]}
	}

	return Vector{Q: Q, P: P}, nil
}

// ConcatPtoQ returns an instance of the receiver where the modulus Q
// is increased to Q[:] + P[:n] and the modulus P reduced to P[n:].
// n must be a positive integer 0 <= n <= v.LevelP()+1.
// Backing arrays are shared.
func (v *Vector) ConcatPtoQ(n int) *Vector {
	switch {
	case v.LevelP() == -1:
		return v
	case v.LevelP()+1 >= n && n >= 0:

		Q := make([]Poly, v.Size())
		P := make([]Poly, v.Size())

		for i := range Q {
			Q[i].Coeffs = append(v.Q[i].Coeffs[:], v.P[i].Coeffs[:n]...)
			P[i].Coeffs = v.P[i].Coeffs[n:]
		}

		return &Vector{
			Q: Q,
			P: P,
		}

	default:
		panic("invalid n: must be a positive integer 0 <= n <= v.LevelP()+1")
	}
}

// ConcatQtoP returns an instance of the receiver where the modulus Q
// is reduced to Q[:n] and the modulus P increased to Q[n:] + P[:].
// n must be a positive integer 0 <= n < v.LevelQ()+1.
func (v Vector) ConcatQtoP(n int) *Vector {
	switch {
	case v.LevelQ()+1 > n && n >= 0:

		Q := make([]Poly, v.Size())
		P := make([]Poly, v.Size())

		offset := v.LevelQ() - n + 1

		for i := range Q {
			Q[i].Coeffs = v.Q[i].Coeffs[:offset]
		}

		if v.LevelP() > -1 {
			for i := range Q {
				P[i].Coeffs = append(v.Q[i].Coeffs[offset:], v.P[i].Coeffs...)
			}
		} else {
			for i := range Q {
				P[i].Coeffs = v.Q[i].Coeffs[offset:]
			}
		}

		return &Vector{
			Q: Q,
			P: P,
		}

	default:
		panic("invalid n: must be a positive integer 0 <= n < v.LevelQ()+1")
	}
}

// AsPoint wraps the receiver in an [Point].
func (v *Vector) AsPoint() *Point {
	var P Poly
	if v.LevelP() > -1 {
		P = v.P[0]
	}
	return &Point{Q: v.Q[0], P: P}
}

// N returns the ring degree of the receiver.
func (v Vector) N() int {
	return v.Q[0].N()
}

// LogN returns the base 2 logarithm of the
// ring degree of the receiver.
func (v Vector) LogN() int {
	return v.Q[0].LogN()
}

// Level returns the level of the modulus Q
// of the receiver.
func (v Vector) Level() int {
	return v.LevelQ()
}

// LevelQ returns the level of the modulus Q
// of the receiver.
func (v Vector) LevelQ() int {
	return v.Q[0].Level()
}

// LevelP returns the level of the modulus P
// of the receiver.
func (v Vector) LevelP() int {
	if len(v.P) != 0 {
		return v.P[0].Level()
	}
	return -1
}

// Size returns the size of the receiver.
func (v Vector) Size() int {
	return len(v.Q)
}

// Copy copies the input on the receiver.
func (v *Vector) Copy(other *Vector) {

	if v != other {
		for i := 0; i < min(len(v.Q), len(other.Q)); i++ {
			v.Q[i].Copy(&other.Q[i])
		}

		for i := 0; i < min(len(v.P), len(other.P)); i++ {
			v.P[i].Copy(&other.P[i])
		}
	}
}

// Clone returns a new Point which is a deep copy
// of the receiver.
func (v Vector) Clone() (clone *Vector) {
	clone = new(Vector)
	clone.Q = v.Q.Clone()
	clone.P = v.P.Clone()
	return
}

func (v Vector) Equal(other *Vector) (equal bool) {
	return v.Q.Equal(other.Q) && v.P.Equal(other.P)
}

// Randomize overwrites the coefficients of the receiver with uniformly
// random coefficients modulo QP.
func (v Vector) Randomize(rQ, rP *Ring, source *sampling.Source) {

	xQ := NewUniformSampler(source, rQ.ModuliChain()).AtLevel(v.LevelQ())

	var xP Sampler
	if rP != nil && v.LevelP() > -1 {
		xP = NewUniformSampler(source, rP.ModuliChain()).AtLevel(v.LevelP())
	}

	for i := 0; i < v.Size(); i++ {
		xQ.Read(v.Q[i])
		if v.LevelP() > -1 {
			xP.Read(v.P[i])
		}
	}
}

func (v *Vector) ResizeSize(size int) {
	if v.Size() > size {
		v.Q = v.Q[:size]
		if v.LevelP() > -1 {
			v.P = v.P[:size]
		}
	} else if v.Size() < size {
		for v.Size() < size {
			v.Q = append(v.Q, []Poly{NewPoly(v.N(), v.Q[0].Level())}...)
			if v.LevelP() > -1 {
				v.P = append(v.P, []Poly{NewPoly(v.N(), v.P[0].Level())}...)
			}
		}
	}
}

// ResizeQ resizes the field Q of the target element.
func (v *Vector) ResizeQ(LevelQ int) {
	if v.LevelQ() != LevelQ {
		for i := range v.Q {
			v.Q[i].Resize(LevelQ)
		}
	}
}

// ResizeP resizes the field P of the target element.
func (v *Vector) ResizeP(LevelP int) {
	if v.LevelP() != LevelP {
		for i := range v.P {
			v.P[i].Resize(LevelP)
		}
	}
}

// Aggregate sets the receiver to a + b.
// The method returns an error  if operands do not match the receiver
// LevelQ(), LevelP(), Size().
func (v *Vector) Aggregate(rQ, rP *Ring, a, b *Vector) (err error) {

	LevelQ := v.LevelQ()
	LevelP := v.LevelP()

	if a.LevelQ() != LevelQ || b.LevelQ() != LevelQ {
		return fmt.Errorf("vectors LevelQ do not match: %d <- %d + %d", LevelQ, a.LevelQ(), b.LevelQ())
	}

	if a.LevelP() != LevelP || b.LevelP() != LevelP {
		return fmt.Errorf("vectors LevelP do not match: %d <- %d + %d", LevelP, a.LevelP(), b.LevelP())
	}

	size := v.Size()

	if a.Size() != size || b.Size() != size {
		return fmt.Errorf("vectors size do not match: %v <- %v + %v", size, a.Size(), b.Size())
	}

	rQ = rQ.AtLevel(LevelQ)

	if rP != nil && LevelP > -1 {
		rP = rP.AtLevel(LevelP)
	}

	for i := 0; i < size; i++ {
		rQ.Add(a.Q[i], b.Q[i], v.Q[i])
		if LevelP > -1 {
			rP.Add(a.P[i], b.P[i], v.P[i])
		}
	}

	return
}

// BinarySize returns the serialized size of the object in bytes.
func (v Vector) BinarySize() (size int) {
	return v.Q.BinarySize() + v.P.BinarySize()
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
func (v Vector) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = v.Q.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = v.P.WriteTo(w); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return v.WriteTo(bufio.NewWriter(w))
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
func (v *Vector) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		if v == nil {
			return 0, fmt.Errorf("receiver is nil")
		}

		var inc int64

		if inc, err = v.Q.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = v.P.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return v.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (v Vector) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(v.BinarySize())
	_, err = v.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (v *Vector) UnmarshalBinary(p []byte) (err error) {
	_, err = v.ReadFrom(buffer.NewBuffer(p))
	return
}

// Matrix is a struct storing a matrix of
// polynomials modulo in basis Q and P.
type Matrix struct {
	Q structs.Matrix[Poly]
	P structs.Matrix[Poly]
}

// NewMatrix allocates a new [ring.Matrix].
func NewMatrix(N, LevelQ, LevelP int, dims []int) (m Matrix) {
	m.FromBuffer(N, LevelQ, LevelP, dims, make([]uint64, m.BufferSize(N, LevelQ, LevelP, dims)))
	return
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (m *Matrix) FromBuffer(N, LevelQ, LevelP int, dims []int, buf []uint64) {

	if len(buf) < m.BufferSize(N, LevelQ, LevelP, dims) {
		panic(fmt.Errorf("invalid buffer size: N=%d * (LevelQ+LevelP+2)=%d * dims=%v < len(buf)=%d", N, LevelQ+LevelP+2, dims, len(buf)))
	}

	var ptr int
	rows := len(dims)

	polyBufferSize := new(Poly).BufferSize(N, LevelQ)
	m.Q = make([][]Poly, rows)
	for i := range rows {
		cols := dims[i]
		m.Q[i] = make([]Poly, cols)
		for j := range cols {
			m.Q[i][j].FromBuffer(N, LevelQ, buf[ptr:])
			ptr += polyBufferSize
		}
	}

	if LevelP > -1 {
		polyBufferSize := new(Poly).BufferSize(N, LevelP)
		m.P = make([][]Poly, rows)
		for i := range rows {
			cols := dims[i]
			m.P[i] = make([]Poly, cols)
			for j := range cols {
				m.P[i][j].FromBuffer(N, LevelP, buf[ptr:])
				ptr += polyBufferSize
			}
		}
	}
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (m *Matrix) BufferSize(N, LevelQ, LevelP int, dims []int) (size int) {
	base := N * (LevelQ + LevelP + 2)
	for _, i := range dims {
		size += base * i
	}
	return
}

// ConcatPtoQ returns an instance of the receiver where the modulus Q
// is increased to Q[:] + P[:n] and the modulus P reduced to P[n:].
// n must be a positive integer 0 <= n <= m.LevelP()+1.
// Backing arrays are shared.
func (m Matrix) ConcatPtoQ(n int) *Matrix {
	switch {
	case m.LevelP()+1 >= n && n >= 0:

		dims := m.Dims()
		rows := len(dims)

		Q := make([][]Poly, rows)
		var P [][]Poly

		for i := range rows {
			cols := dims[i]
			Q[i] = make([]Poly, cols)
			for j := range cols {
				Q[i][j].Coeffs = m.Q[i][j].Coeffs
			}
		}

		if m.LevelP() > -1 {
			P = make([][]Poly, rows)
			for i := range rows {
				cols := dims[i]
				P[i] = make([]Poly, cols)
				for j := range cols {
					Q[i][j].Coeffs = append(Q[i][j].Coeffs, m.P[i][j].Coeffs[:n]...)
					P[i][j].Coeffs = m.P[i][j].Coeffs[n:]
				}
			}
		}

		return &Matrix{
			Q: Q,
			P: P,
		}

	default:
		panic("invalid n: must be a positive integer 0 <= n <= m.LevelP()+1")
	}
}

// ConcatQtoP returns an instance of the receiver where the modulus Q
// is reduced to Q[:n] and the modulus P increased to Q[n:] + P[:].
// n must be a positive integer 0 <= n < m.LevelQ()+1.
// Backing arrays are shared.
func (m Matrix) ConcatQtoP(n int) *Matrix {
	switch {
	case n == 0:

		dims := m.Dims()

		rows := len(dims)

		Q := make([][]Poly, rows)
		for i := range rows {
			cols := dims[i]
			Q[i] = make([]Poly, cols)
			for j := range cols {
				Q[i][j].Coeffs = m.Q[i][j].Coeffs
			}
		}

		var P [][]Poly
		if m.LevelP() > -1 {
			P = make([][]Poly, rows)
			for i := range rows {
				cols := dims[i]
				P[i] = make([]Poly, cols)
				for j := range cols {
					P[i][j].Coeffs = m.P[i][j].Coeffs
				}
			}
		}

		return &Matrix{
			Q: Q,
			P: P,
		}

	case m.LevelQ()+1 > n && n > 0:

		dims := m.Dims()
		rows := len(dims)

		Q := make([][]Poly, rows)
		P := make([][]Poly, rows)

		offset := m.LevelQ() + 1 - n

		for i := range rows {
			cols := dims[i]
			Q[i] = make([]Poly, cols)
			for j := range cols {
				Q[i][j].Coeffs = m.Q[i][j].Coeffs[:offset]
			}
		}

		if m.LevelP() > -1 {
			for i := range rows {
				cols := dims[i]
				P[i] = make([]Poly, cols)
				for j := range cols {
					P[i][j].Coeffs = append(m.Q[i][j].Coeffs[offset:], m.P[i][j].Coeffs...)
				}
			}
		} else {
			for i := range rows {
				cols := dims[i]
				P[i] = make([]Poly, cols)
				for j := range cols {
					P[i][j].Coeffs = m.Q[i][j].Coeffs[offset:]
				}
			}
		}

		return &Matrix{
			Q: Q,
			P: P,
		}

	default:
		panic("invalid n: must be a positive integer 0 <= n < m.LevelQ()+1")
	}
}

// Aggregate sets the receiver to a + b.
// The method returns an error  if operands do not match the receiver
// LevelQ(), LevelP(), Dims().
func (m *Matrix) Aggregate(rQ, rP *Ring, a, b *Matrix) (err error) {

	LevelQ := m.LevelQ()
	LevelP := m.LevelP()

	if a.LevelQ() != LevelQ || b.LevelQ() != LevelQ {
		return fmt.Errorf("matrices LevelQ do not match: %d <- %d + %d", LevelQ, a.LevelQ(), b.LevelQ())
	}

	if a.LevelP() != LevelP || b.LevelP() != LevelP {
		return fmt.Errorf("matrices LevelP do not match: %d <- %d + %d", LevelP, a.LevelP(), b.LevelP())
	}

	dims := m.Dims()

	if !slices.Equal(a.Dims(), dims) || !slices.Equal(b.Dims(), dims) {
		return fmt.Errorf("matrices dimensions do not match: %v <- %v + %v", dims, a.Dims(), b.Dims())
	}

	rQ = rQ.AtLevel(LevelQ)

	if rP != nil && LevelP > -1 {
		rP = rP.AtLevel(LevelP)
	}

	rows := len(dims)

	for i := range rows {
		for j := range dims[i] {

			rQ.Add(a.Q[i][j], b.Q[i][j], m.Q[i][j])

			if LevelP > -1 {
				rP.Add(a.P[i][j], b.P[i][j], m.P[i][j])
			}
		}
	}

	return
}

// N returns the receiver ring degree.
func (m Matrix) N() int {
	return m.Q[0][0].N()
}

// LogN returns the base 2 logarithm of the receiver ring degree.
func (m Matrix) LogN() int {
	return m.Q[0][0].LogN()
}

// Dims returns the dimension of the receiver.
func (m Matrix) Dims() (dims []int) {
	dims = make([]int, len(m.Q))
	for i := range m.Q {
		dims[i] = len(m.Q[i])
	}
	return
}

// Level returns the level of the modulus
// Q of the receiver.
func (m Matrix) Level() int {
	return m.LevelQ()
}

// LevelQ returns the level of the modulus
// Q of the receiver.
func (m Matrix) LevelQ() int {
	return m.Q[0][0].Level()
}

// LevelP returns the level of the modulus
// P of the receiver.
func (m Matrix) LevelP() int {
	if len(m.P) != 0 {
		return m.P[0][0].Level()
	}
	return -1
}

// Equal performs a deep equal between the operand and the receiver.
func (m Matrix) Equal(other *Matrix) bool {
	return m.Q.Equal(other.Q) && m.P.Equal(other.P)
}

// Clone returns a deep copy of the receiver.
func (m Matrix) Clone() *Matrix {
	return &Matrix{Q: m.Q.Clone(), P: m.P.Clone()}
}

// Randomize overwrites the coefficients of the receiver with uniformly
// random coefficients modulo QP.
func (m Matrix) Randomize(rQ, rP *Ring, source *sampling.Source) {

	xQ := NewUniformSampler(source, rQ.ModuliChain()).AtLevel(m.LevelQ())
	var xP Sampler
	if rP != nil && m.LevelP() > -1 {
		xP = NewUniformSampler(source, rP.ModuliChain()).AtLevel(m.LevelP())
	}

	dims := m.Dims()

	for i := range dims {
		for j := range dims[i] {
			xQ.Read(m.Q[i][j])
			if xP != nil {
				xP.Read(m.P[i][j])
			}
		}
	}
}

// Copy copies the input on the receiver.
func (m *Matrix) Copy(other *Matrix) {
	if m != other {
		m.Q.Copy(other.Q)
		m.P.Copy(other.P)
	}
}

// BinarySize returns the serialized size of the object in bytes.
func (m Matrix) BinarySize() (size int) {
	return m.Q.BinarySize() + m.P.BinarySize()
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
func (m Matrix) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = m.Q.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = m.P.WriteTo(w); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return m.WriteTo(bufio.NewWriter(w))
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
func (m *Matrix) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		if m == nil {
			return 0, fmt.Errorf("receiver is nil")
		}

		var inc int64

		if inc, err = m.Q.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = m.P.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return m.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (m Matrix) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(m.BinarySize())
	_, err = m.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (m *Matrix) UnmarshalBinary(p []byte) (err error) {
	_, err = m.ReadFrom(buffer.NewBuffer(p))
	return
}
