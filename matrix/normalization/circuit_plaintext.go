package normalization

import (
	"math"
	"slices"

	"app/utils"

	"gonum.org/v1/gonum/mat"
)

func (eval *Evaluator) EvaluateApproximate(in, out *mat.Dense) (Min, Max float64) {

	rows, cols := in.Dims()

	f := func(a, b, c []float64) {
		for i := range c {
			c[i] = a[i] + b[i]
		}
	}

	mean := make([]float64, rows*cols)
	variance := make([]float64, rows*cols)

	copy(mean, in.RawMatrix().Data)
	copy(variance, in.RawMatrix().Data)

	// E[x]
	utils.InnerFunction(mean, 1, cols, f, mean)
	utils.MaskAndReplicate(mean, 1, cols)
	for i := range mean {
		mean[i] /= float64(cols)
	}

	outRaw := out.RawMatrix().Data
	for i := range outRaw {
		outRaw[i] = in.RawMatrix().Data[i] - mean[i]
	}

	// Var[x]
	for i := range variance {
		variance[i] = outRaw[i] * outRaw[i]
	}

	utils.InnerFunction(variance, 1, cols, f, variance)

	utils.MaskAndReplicate(variance, 1/float64(cols), cols)
	for i := range mean {
		variance[i] += 1e-6
	}

	Max = slices.Max(variance)
	Min = slices.Min(variance)

	coeffs := eval.InvSqrtPoly.Float64()

	for i := range variance {
		y := utils.ChebEval(coeffs, eval.InvSqrtMin, eval.InvSqrtMax, variance[i])
		variance[i] = InvSqrtQuadratic(variance[i], y, eval.InvSqrtIter)
	}

	gamma := eval.Gamma
	beta := eval.Beta

	for i := range rows {
		col := out.RawRowView(i)
		v := variance[i*cols : (i+1)*cols]
		for j := range col {
			col[j] = col[j]*v[j]*gamma[j] + beta[j]
		}
	}

	return
}

func InvSqrtQuadratic(x, y float64, r int) float64 {
	x /= 2
	for range r {
		y = y * (1.5 - x*y*y)
	}
	return y
}

func (eval *Evaluator) EvaluateExact(in, out *mat.Dense) (Min, Max float64) {

	gamma := eval.Gamma
	beta := eval.Beta

	rows, cols := in.Dims()

	Min = 1e300
	Max = -Min

	for i := range rows {

		mi := in.RawMatrix().Data[i*cols : (i+1)*cols]
		mo := out.RawMatrix().Data[i*cols : (i+1)*cols]

		mean := 0.0
		for j := range cols {
			mean += mi[j]
		}

		mean /= float64(cols)

		variance := 0.0
		for j := range cols {
			xi := mi[j] - mean
			mo[j] = xi
			variance += xi * xi
		}
		variance /= float64(cols)

		varInv := 1.0 / math.Sqrt(variance+1e-6)

		Min = min(Min, variance+1e-6)
		Max = max(Max, variance+1e-6)

		for j := range cols {
			mo[j] = mo[j]*varInv*gamma[j] + beta[j]
		}
	}

	return
}
