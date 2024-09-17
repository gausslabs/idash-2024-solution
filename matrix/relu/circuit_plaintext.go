package relu

import (
	"app/utils"

	"gonum.org/v1/gonum/mat"
)

func (eval *Evaluator) EvaluateExact(in, out []*mat.Dense) {

	f := func(i, j int, x float64) (y float64) {
		if x <= 0 {
			return 0
		}
		return x
	}

	for i := range in {
		out[i].Apply(f, in[i])
	}

	return
}

func (eval *Evaluator) EvaluateApproximate(in, out []*mat.Dense) {

	f := func(i, j int, x float64) (y float64) {
		sign := utils.CompositeEval(eval.CoeffsFloat, -1, 1, x)
		return (x*sign + x) / 2
	}

	for i := range in {
		out[i].Apply(f, in[i])
	}
	return
}
