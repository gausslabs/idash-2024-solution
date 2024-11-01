package matrix

import (
	"fmt"
	"math/bits"
	"slices"

	"github.com/Pro7ech/lattigo/utils/concurrency"

	"golang.org/x/exp/maps"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

func MaskAndCompressGaloisElements(params hefloat.Parameters, k, d int) (galEls []uint64) {

	m := map[uint64]bool{}

	shifts := []int{}
	if d == 1 {
		return
	} else {

		for d != 0 {

			shift := 1 << (bits.Len64(uint64(d)) - 1)

			for _, galEl := range packPow2GaloisElements(params, shift) {
				m[galEl] = true
			}

			for j := range shifts {
				m[params.GaloisElement(shifts[j])] = true
			}

			shifts = append(shifts, -shift)

			d -= shift
		}
	}

	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (eval *Evaluator) MaskAndCompress(in []rlwe.Ciphertext, A, B float64, k, n int, rescale bool) (out *rlwe.Ciphertext, err error) {

	if len(in) > k {
		return nil, fmt.Errorf("len(in)=%d > k = %d", len(in), k)
	}

	if n == 0 || n%k != 0 {
		return nil, fmt.Errorf("n must non-zero and a multiple of k=%d but is %d", k, n)
	}

	mask := make([]float64, n)
	for j := 0; j < len(mask); j += k {
		mask[j] = A
	}

	if err = eval.DotVec(in, mask, in); err != nil {
		return
	}

	for j := 0; j < len(mask); j += k {
		mask[j] = B
	}

	if err = eval.AddVec(in, mask, in); err != nil {
		return
	}

	shifts := []int{}

	if len(in) == 1 {
		out = &in[0]
	} else {

		for len(in) != 0 {

			shift := 1 << (bits.Len64(uint64(len(in))) - 1)

			var ct *rlwe.Ciphertext
			if ct, err = eval.packPow2(in[:shift]); err != nil {
				return
			}

			if out != nil {

				for j := range shifts {
					if err = eval.Evaluators[0].Rotate(ct, shifts[j], ct); err != nil {
						return
					}
				}

				if err = eval.Evaluators[0].Add(out, ct, out); err != nil {
					return
				}

			} else {
				out = ct
			}

			shifts = append(shifts, -shift)

			in = in[shift:]
		}
	}

	if err = eval.Evaluators[0].Rescale(out, out); err != nil {
		return nil, err
	}

	return
}

func packPow2GaloisElements(params hefloat.Parameters, d int) (galEls []uint64) {
	shift := 1
	for d != 0 {
		galEls = append(galEls, params.GaloisElement(-shift))
		d >>= 1
		shift <<= 1
	}

	return
}

func (eval *Evaluator) packPow2(in []rlwe.Ciphertext) (out *rlwe.Ciphertext, err error) {

	shift := 1
	for len(in) != 1 {

		m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)

		for i := range len(in) >> 1 {

			m.Run(func(eval *hefloat.Evaluator) (err error) {

				if err = eval.Rotate(&in[2*i+1], -shift, &in[2*i+1]); err != nil {
					return
				}

				if err = eval.Add(&in[2*i], &in[2*i+1], &in[2*i]); err != nil {
					return
				}

				return
			})
		}

		if err = m.Wait(); err != nil {
			return
		}

		for i := range len(in) >> 1 {
			in[i] = in[2*i]
		}

		in = in[:len(in)>>1]

		shift <<= 1
	}

	return &in[0], nil
}

func (eval *Evaluator) Extract(in *rlwe.Ciphertext, k int) (out []rlwe.Ciphertext, err error) {

	out = make([]rlwe.Ciphertext, k)

	for j := range k {
		out[j] = *in.Clone()
	}

	t := 1

	for m := 1 << bits.Len64(uint64(k-1)); m > 0; m >>= 1 {

		h := m >> 1

		for i, j1, j2 := 0, 0, t; i < h; i, j1, j2 = i+1, j1+2*t, j2+2*t {

			m := concurrency.NewRessourceManager[*hefloat.Evaluator](eval.Evaluators)

			for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+1, jy+1 {
				if jy >= k {
					break
				}
				m.Run(func(eval *hefloat.Evaluator) (err error) {
					return eval.Rotate(&out[jy], t, &out[jy])
				})
			}

			if err = m.Wait(); err != nil {
				return
			}
		}
		t <<= 1
	}

	return
}

func (eval *Evaluator) MaskAndReplicate(cts []rlwe.Ciphertext, scaling float64, k int, rescale bool) (err error) {

	params := eval.Evaluators[0].Parameters()

	var n int

	if maxSlots := params.MaxSlots(); maxSlots%k == 0 {
		n = maxSlots
	} else {
		n = (maxSlots/k)*k - 1
	}

	mask := make([]float64, n)
	for i := range mask {
		if i%k == 0 {
			mask[i] = scaling
		}
	}

	if err = eval.DotVec(cts, mask, cts); err != nil {
		return
	}

	if err = eval.Replicate(cts, 1, k, cts); err != nil {
		return
	}

	if rescale {
		return eval.Rescale(cts, cts)
	}

	return
}
