package softmax

import (
	"fmt"
	"math"
	"slices"

	"app/matrix/softmax/innermax"
	"app/utils"

	"gonum.org/v1/gonum/mat"
)

func (eval *Evaluator) EvaluateExact(in, out []*mat.Dense) {

	rows, cols := in[0].Dims()

	for k := range in {
		for i := range rows {
			ini := in[k].RawRowView(i)
			outi := out[k].RawRowView(i)
			xmax := slices.Max(ini)
			sum := 0.0
			for j := range cols {
				outi[j] = math.Exp(ini[j] - xmax)
				sum += outi[j]
			}
			inv := 1 / sum
			for j := range cols {
				outi[j] *= inv
			}
		}
	}
}

func pp() {
	fmt.Println()
}

func (eval *Evaluator) EvaluateApproximate(in, out []*mat.Dense) (StatsIn, StatsExp, StatsNorm utils.Stats) {

	_, cols := in[0].Dims()

	coeffsExp := eval.ExpPoly.Float64()
	coeffsInvPoly := eval.InvPoly.Float64()

	StatsIn = utils.StatsRows(out)

	for k := range in {
		if in[k] != out[k] {
			out[k].Copy(in[k])
		}
	}

	innermax.NewEvaluator(eval.MaxParameters, nil, nil).InnerMaxPlaintext(out)

	StatsExp = utils.StatsRows(out)

	offset := eval.ExpOffset

	fInvExp := func(i, j int, x float64) (y float64) {
		return utils.ChebEval(coeffsExp, eval.ExpMin, eval.ExpMax, x+offset)
	}

	// exp(x-max(x))/lib.GDDNorm
	for k := range out {
		out[k].Apply(fInvExp, out[k])
	}

	num := out
	norm := make([]*mat.Dense, len(out))

	for k := range norm {
		norm[k] = mat.DenseCopyOf(num[k])

		m := norm[k].RawMatrix().Data

		// sum(exp(x-max(x)))
		utils.InnerFunction(m, 1, cols, func(a, b, c []float64) {
			for i := range c {
				c[i] = a[i] + b[i]
			}
		}, m)
		utils.MaskAndReplicate(m, 1, cols)
	}

	StatsNorm = utils.StatsRows(norm)

	var fInv func(i, j int, x float64) (y float64)

	if eval.InvSqrtIter > 0 {
		fInv = func(i, j int, x float64) (y float64) {
			y = utils.ChebEval(coeffsInvPoly, eval.InvMin, eval.InvMax, x)
			y = InvSqrtQuadratic(x, y, eval.InvSqrtIter)
			return y * y
		}
	} else {
		fInv = func(i, j int, x float64) (y float64) {
			return utils.ChebEval(coeffsInvPoly, eval.InvMin, eval.InvMax, x)
		}
	}

	for k := range norm {
		norm[k].Apply(fInv, norm[k])
	}

	for k := range norm {
		out[k].MulElem(out[k], norm[k])
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

func NormalizePlaintext(in []float64, A, B float64, k int, scaling float64) (out []float64) {

	Max := make([]float64, len(in))
	for i := range in {
		Max[i] = in[i] / (B - A)
	}

	f := func(a, b, c []float64) {
		ApproximateMax(a, b, c)
	}

	utils.InnerMax(Max, k, f)

	utils.MaskAndReplicate(Max, B-A, k)

	out = make([]float64, len(in))
	copy(out, in)

	for i := range out {
		out[i] = (out[i] - Max[i]) * scaling
	}

	return
}

func ApproximateMax(a, b []float64, c []float64) {

	max := make([]float64, len(a))
	for i := range max {
		max[i] = a[i] - b[i]
	}

	step := make([]float64, len(a))
	for i := range step {
		step[i] = utils.CompositeEval(CoeffsSignPolyAlpha6Err15Prec19, -1, 1, max[i])
	}

	// (a-b)*step + b -> (a-b) * 1 + b | (a-b)*
	for i := range step {
		c[i] = (max[i] * (0.5*step[i] + 0.5)) + b[i]
	}

	return
}

// hefloat.GenMinimaxCompositePolynomialForSign(256, 6, 15, []int{31, 31})
var CoeffsSignPolyAlpha6Err15Prec19 = [][]float64{
	{0, 0.864988119247, 0, -0.288377920222, 0, 0.173071422437, 0, -0.123816194144, 0, 0.096394642789, 0, -0.078902169290, 0, 0.066945006659, 0, -0.058020100531, 0, 0.051332266735, 0, -0.046482123811, 0, 0.042138711193, 0, -0.038528692000, 0, 0.035978793808, 0, -0.033437153812, 0, 0.031680300044, 0, -0.335319740231},
	{0, 1.266504742898, 0, -0.404596922995, 0, 0.222869371220, 0, -0.139872558754, 0, 0.091346906097, 0, -0.059846068329, 0, 0.038558545509, 0, -0.024103625427, 0, 0.014456545301, 0, -0.008227671984, 0, 0.004387825299, 0, -0.002157400000, 0, 0.000955384598, 0, -0.000366901589, 0, 0.000113649172, 0, -0.000023655795},
}

func GoldschmidtDivisionNew(iters int, in, out []float64) {
	b := make([]float64, len(in))
	for i := range b {
		out[i] = -in[i]
		b[i] = out[i] + 1
		out[i] += 2
	}
	for i := 1; i < iters; i++ {
		for j := range b {
			b[j] *= b[j]
			out[j] += out[j] * b[j]
		}
	}
}

func IntervalNormalization(Max, fac float64, in, out []float64) (norm []float64) {

	copy(out, in)

	norm = make([]float64, len(in))
	for i := range norm {
		norm[i] = 1
	}

	L := 2.45

	n := int(math.Ceil(math.Log2(Max) / math.Log2(L)))

	for i := range n {

		c := (4.0 * fac * fac) / (27 * math.Pow(L, 2*(float64(n-1-i))))
		for j := range norm {
			z0 := (out[j] * c)
			z1 := out[j] * out[j]
			z2 := norm[j] * out[j]

			out[j] -= z0 * z1
			norm[j] -= z0 * z2
		}
	}

	for i := range out {
		out[i] *= fac
	}

	return
}
