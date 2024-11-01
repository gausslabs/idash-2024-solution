package layers

import (
	"gonum.org/v1/gonum/mat"
)

type Dense struct {
	Weights *mat.Dense
	Bias    []float64
}

func NewDense(w *mat.Dense, b []float64) *Dense {
	return &Dense{
		Weights: w,
		Bias:    b,
	}
}

func (d *Dense) Evaluate(in, out *mat.Dense) {
	out.Mul(in, d.Weights)
	if bias := d.Bias; bias != nil {
		rows, cols := out.Dims()
		for i := range rows {
			m := out.RawMatrix().Data[i*cols:]
			for j := range cols {
				m[j] += bias[j]
			}
		}
	}
}
