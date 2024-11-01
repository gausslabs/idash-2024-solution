package innermax

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"gonum.org/v1/gonum/mat"

	"app/matrix"
	"app/utils"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/structs"
)

type Evaluator struct {
	Parameters
	*matrix.Evaluator
	he.Bootstrapper[rlwe.Ciphertext]
}

type Parameters struct {
	AbsMax       int
	CoeffsString [][]string
	CoeffsFloat  [][]float64
}

func (p Parameters) Depth() (depth int) {
	for _, c := range p.CoeffsString {
		depth += int(math.Ceil(math.Log2(float64(len(c)))))
	}
	depth++ // x * sign(x)
	return
}

func NewEvaluator(p Parameters, eval *matrix.Evaluator, btp he.Bootstrapper[rlwe.Ciphertext]) *Evaluator {
	return &Evaluator{
		Parameters:   p,
		Evaluator:    eval,
		Bootstrapper: btp,
	}
}

func (eval *Evaluator) InnerMaxPlaintext(in []*mat.Dense) {

	f := func(a, b, c []float64) {
		eval.approximateMax(a, b, c)
	}

	_, k := in[0].Dims()

	Max := make([]float64, len(in[0].RawMatrix().Data))

	for i := range in {

		m := in[i].RawMatrix().Data

		for i := range Max {
			Max[i] = m[i] / float64(eval.AbsMax)
		}

		utils.InnerFunction(Max, 1, k, f, Max)

		utils.MaskAndReplicate(Max, float64(eval.AbsMax), k)

		for i := range m {
			m[i] -= Max[i]
		}
	}

	return

}

func (eval *Evaluator) approximateMax(a, b []float64, c []float64) {

	max := make([]float64, len(a))
	for i := range max {
		max[i] = a[i] - b[i]
	}

	step := make([]float64, len(a))
	for i := range step {
		step[i] = utils.CompositeEval(eval.CoeffsFloat, -1, 1, max[i])
	}

	// (a-b)*step + b -> (a-b) * 1 + b | (a-b)*
	for i := range step {
		c[i] = (max[i] * (0.5*step[i] + 0.5)) + b[i]
	}

	return
}

func (eval *Evaluator) InnerMax(in []rlwe.Ciphertext, k int) (out []rlwe.Ciphertext, err error) {

	params := eval.Evaluators[0].Parameters()

	nb := len(in)

	var shift int
	d := k
	prevk := k

	step := k

	totPack := 1
	keys := make([]int, k)
	keys[0] = 1

	iter := 0

	for k != 1 {

		if k&1 == 0 {
			shift = k >> 1
		} else {
			step = k
			shift = k - (1 << (bits.Len64(uint64(k)-1) - 1))
		}

		if in[0].Level() < 1+eval.Parameters.Depth() {
			if in, err = eval.BootstrapMany(in); err != nil {
				return nil, fmt.Errorf("[BootstrapMany][in]: %w", err)
			}
		}

		tmp := structs.Vector[rlwe.Ciphertext](in).Clone()

		for i := range tmp {
			if err = eval.Evaluators[0].Rotate(&tmp[i], shift, &tmp[i]); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator][Rotate]: %w", err)
			}
		}

		mask := make([]float64, params.MaxSlots())

		var scale float64
		if iter == 0 {
			scale = 1 / float64(eval.AbsMax)
		} else {
			scale = 1
		}
		iter++

		for i := range params.MaxSlots() / step {
			offset0 := i * step
			for j := range step / k {
				offset1 := j * k
				for m := range k - shift {
					mask[offset0+offset1+m] = scale
				}
			}
		}

		if err = eval.DotVec(in, mask, in); err != nil {
			return
		}

		if err = eval.DotVec(tmp, mask, tmp); err != nil {
			return
		}

		if err = eval.Rescale(in, in); err != nil {
			return
		}

		if err = eval.Rescale(tmp, tmp); err != nil {
			return
		}

		if in, err = eval.Max(in, tmp); err != nil {
			return
		}

		if pack := prevk / (k - shift); pack > 1 {

			buff := make([]int, len(keys))
			copy(buff, keys)

			for j := 1; j < pack; j++ {

				for i, c := range buff {
					if c != 0 {
						keys[i+shift*j] = c + j*totPack
					}
				}

				for i := range (len(in) + pack - 1) / pack {

					if pack*i+j >= len(in) {
						break
					}

					if err = eval.Evaluators[0].Rotate(&in[pack*i+j], -shift*j, &in[pack*i+j]); err != nil {
						return
					}

					if err = eval.Evaluators[0].Add(&in[pack*i], &in[pack*i+j], &in[pack*i]); err != nil {
						return
					}
				}
			}

			for i := range (len(in) + pack - 1) / pack {
				in[i] = in[pack*i]
			}

			in = append(in[:(len(in)+pack-1)/pack])

			prevk = (k >> 1)

			totPack *= pack
		}

		k -= shift
	}

	if in, err = eval.BootstrapMany(in); err != nil {
		return nil, fmt.Errorf("[BootstrapMany][in]: %w", err)
	}

	if err = eval.MulScalar(in, float64(eval.AbsMax), in); err != nil {
		return
	}

	m := map[int]int{}
	for i := range keys {
		if k := keys[i]; k != 0 {
			m[k-1] = i
		}
	}

	out = make([]rlwe.Ciphertext, nb)

	for i := range in {

		var tmp []rlwe.Ciphertext
		if tmp, err = eval.Extract(&in[i], d); err != nil {
			return nil, fmt.Errorf("[Extract][in,d]: %w", err)
		}

		for j := range totPack {
			if j+i*totPack >= len(out) {
				break
			}
			out[j+i*totPack] = tmp[m[j]]
		}
	}

	return out, nil
}

// Step evaluates f(x) = 1 if x > 0, 0 if x < 0, else 0.5 (i.e. (sign+1)/2).
// This will ensure that step.Scale = params.DefaultScale().
func (eval *Evaluator) Max(A, B []rlwe.Ciphertext) (C []rlwe.Ciphertext, err error) {

	C = structs.Vector[rlwe.Ciphertext](A).Clone()

	if err = eval.SubCt(A, B, C); err != nil {
		return
	}

	var step []rlwe.Ciphertext
	if step, err = eval.Step(C); err != nil {
		return
	}

	if err = eval.Rescale(step, step); err != nil {
		return
	}

	if err = eval.DropLevel(C, C[0].Level()-step[0].Level()-1); err != nil {
		return
	}

	if err = eval.MatchScalesForMul(step, C, A[0].Scale); err != nil {
		return
	}

	if err = eval.DotCt(step, C, step); err != nil {
		return
	}

	if err = eval.Rescale(step, step); err != nil {
		return
	}

	if err = eval.SetScale(C, step[0].Scale); err != nil {
		return
	}

	// max = step(a-b) * (a-b) + b
	if err = eval.AddCt(step, B, C); err != nil {
		return
	}

	return
}

func (eval *Evaluator) Step(in []rlwe.Ciphertext) (out []rlwe.Ciphertext, err error) {

	polyCMP := hefloat.NewMinimaxCompositePolynomial(eval.CoeffsString)

	n := len(polyCMP)

	stepPoly := make([]*he.Polynomial, n)

	for i := 0; i < n; i++ {
		stepPoly[i] = he.NewPolynomial(&polyCMP[i])
	}

	half := new(big.Float).SetFloat64(0.5)

	// (x+1)/2
	lastPoly := polyCMP[n-1].Clone()
	for i := range lastPoly.Coeffs {
		lastPoly.Coeffs[i][0].Mul(&lastPoly.Coeffs[i][0], half)
	}
	lastPoly.Coeffs[0][0].Add(&lastPoly.Coeffs[0][0], half)

	stepPoly[n-1] = he.NewPolynomial(lastPoly)

	if in[0].Level() < stepPoly[0].Depth() {
		if out, err = eval.BootstrapMany(in); err != nil {
			return nil, fmt.Errorf("btp.BootstrapMany: %w", err)
		}
	} else {
		out = in
	}

	if out, err = eval.Polynomial(out, stepPoly[0]); err != nil {
		return nil, fmt.Errorf("[matrix.Evaluator][Polynomial][in,stepPoly]: %w", err)
	}

	for i := 1; i < len(stepPoly); i++ {

		if err = eval.Rescale(out, out); err != nil {
			return nil, fmt.Errorf("[matrix.Evaluator][Rescale][out,out]: %w", err)
		}

		if out[0].Level() < stepPoly[i].Depth() {
			if out, err = eval.BootstrapMany(out); err != nil {
				return nil, fmt.Errorf("btp.BootstrapMany: %w", err)
			}
		}

		if out, err = eval.Polynomial(out, stepPoly[i]); err != nil {
			return nil, fmt.Errorf("[matrix.Evaluator][Polynomial][out,stepPoly]: %w", err)
		}
	}
	return
}

func GaloisElements(params hefloat.Parameters, k, d int) (galEls []uint64) {

	var shift int
	prevk := k
	nb := d
	tot := k

	for k != 1 {

		if k&1 == 0 {
			shift = k >> 1
		} else {
			shift = k - (1 << (bits.Len64(uint64(k)-1) - 1))
		}

		galEls = append(galEls, params.GaloisElement(shift))

		if pack := prevk / (k - shift); pack > 1 {

			for i := range (d + pack - 1) / pack {

				for j := 1; j < pack; j++ {

					if pack*i+j >= d {
						break
					}

					galEls = append(galEls, params.GaloisElement(-shift*j))
				}

			}

			d = (d + pack - 1) / pack

			prevk = (k >> 1)
		}

		k -= shift
	}

	t := 1

	for m := 1 << bits.Len64(uint64(tot-1)); m > 0; m >>= 1 {

		h := m >> 1

		for i, j1, j2 := 0, 0, t; i < h; i, j1, j2 = i+1, j1+2*t, j2+2*t {
			for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+1, jy+1 {

				if jy >= nb {
					break
				}

				galEls = append(galEls, params.GaloisElement(t))
			}
		}
		t <<= 1
	}

	return
}
