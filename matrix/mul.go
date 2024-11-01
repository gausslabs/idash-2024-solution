package matrix

import (
	"fmt"
	"math"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type MulParameters struct {
	PermuteRows *he.LinearTransformation
	PermuteCols *he.LinearTransformation
	RotateRows  []*he.LinearTransformation
	RotateCols  []*he.LinearTransformation
}

func (p MulParameters) Level() int {
	return p.PermuteRows.LevelQ
}

func (p MulParameters) Dimensions() int {
	return len(p.RotateCols) + 1
}

func (eval *Evaluator) NewMulParameters(LevelQ int, scaling float64, transposeLeft, transposeRight bool, inputAScale, inputBScale rlwe.Scale) (p *MulParameters, err error) {

	if LevelQ < 3 {
		return nil, fmt.Errorf("invalid LevelQ: must be greater than 3 but is %d", LevelQ)
	}

	params := eval.Evaluators[0].Parameters()
	dims := eval.dims

	ecds := make([]*hefloat.Encoder, len(eval.Evaluators))
	for i := range ecds {
		ecds[i] = eval.Evaluators[i].Encoder
	}

	p = new(MulParameters)

	defaultScale := params.DefaultScale()

	scaleOut := rlwe.NewScale(rlwe.NewScale(params.Q()[LevelQ-2]))

	scalingRows := math.Sqrt(math.Abs(scaling))
	scalingCols := scalingRows
	if scaling < 0 {
		scalingRows = -scalingRows
	}

	if p.PermuteRows, err = eval.NewLinearTransformation(
		LevelQ,
		inputAScale,
		defaultScale,
		false,
		PermuteRowsDiagonals(params, dims, scalingRows, transposeLeft)); err != nil {
		return
	}

	if p.PermuteCols, err = eval.NewLinearTransformation(
		LevelQ,
		inputBScale,
		scaleOut,
		false,
		PermuteColsDiagonals(params, dims, scalingCols, transposeRight)); err != nil {
		return
	}

	p.RotateCols = make([]*he.LinearTransformation, dims-1)

	for i := range dims - 1 {
		if p.RotateCols[i], err = eval.NewLinearTransformation(
			LevelQ-1,
			scaleOut,
			scaleOut,
			true,
			RotateRowsDiagonals(params, dims, i+1)); err != nil {
			return
		}
	}

	// If dims^2 number of slots, we do not need linear
	// transformation to perform the rows rotations.
	if dims*dims != params.MaxSlots() {
		p.RotateRows = make([]*he.LinearTransformation, dims-1)
		for i := range dims - 1 {
			if p.RotateRows[i], err = eval.NewLinearTransformation(
				LevelQ-1,
				scaleOut,
				scaleOut,
				true,
				RotateRowsDiagonals(params, dims*dims, (i+1)*dims)); err != nil {
				return
			}
		}
	}

	return
}

func MulParametersGaloisElements(params hefloat.Parameters, dims int, transposeLeft, transposeRight bool) (galEls []uint64) {

	m := map[uint64]bool{}

	for _, galEl := range PermuteRowsGaloisElements(params, dims, transposeLeft) {
		m[galEl] = true
	}

	for _, galEl := range PermuteColsGaloisElements(params, dims, transposeRight) {
		m[galEl] = true
	}

	for i := range dims - 1 {
		for _, galEl := range RotateRowsGaloisElements(params, dims, i+1) {
			m[galEl] = true
		}
	}

	if dims*dims != params.MaxSlots() {
		for i := range dims - 1 {
			for _, galEl := range RotateRowsGaloisElements(params, dims*dims, (i+1)*dims) {
				m[galEl] = true
			}
		}
	} else {
		for i := range dims - 1 {
			m[params.GaloisElement((i+1)*dims)] = true
		}
	}

	galEls = maps.Keys(m)
	slices.Sort(galEls)
	return
}

func (p *MulParameters) GaloisElements(params hefloat.Parameters) (galEls []uint64) {

	m := map[uint64]bool{}

	for _, galEl := range p.PermuteRows.GaloisElements(params) {
		m[galEl] = true
	}

	for _, galEl := range p.PermuteCols.GaloisElements(params) {
		m[galEl] = true
	}

	for _, rc := range p.RotateCols {
		for _, galEl := range rc.GaloisElements(params) {
			m[galEl] = true
		}
	}

	if p.RotateRows != nil {
		for _, rr := range p.RotateRows {
			for _, galEl := range rr.GaloisElements(params) {
				m[galEl] = true
			}
		}
	} else {
		dims := p.Dimensions()
		for i := range dims - 1 {
			m[params.GaloisElement((i+1)*dims)] = true
		}
	}

	galEls = maps.Keys(m)

	slices.Sort(galEls)

	return
}
