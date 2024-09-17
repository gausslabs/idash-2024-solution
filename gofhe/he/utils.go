package he

import (
	"app/gofhe/ring"
)

// GenXPow2NTT generates X^({-1 if div else 1} * {2^{0 <= i < LogN}}) in NTT.
func GenXPow2NTT(r *ring.Ring, logN int, div bool) (xPow []ring.Poly) {

	// Compute X^{-n} from 0 to LogN
	xPow = make([]ring.Poly, logN)

	moduli := r.ModuliChain()[:r.Level()+1]
	BRC := r.BRedConstants()

	var idx int
	for i := 0; i < logN; i++ {

		idx = 1 << i

		if div {
			idx = r.N() - idx
		}

		xPow[i] = r.NewPoly()

		if i == 0 {

			for j := range moduli {
				xPow[i].At(j)[idx] = ring.MForm(1, moduli[j], BRC[j])
			}

			r.NTT(xPow[i], xPow[i])

		} else {
			r.MulCoeffsMontgomery(xPow[i-1], xPow[i-1], xPow[i]) // X^{n} = X^{1} * X^{n-1}
		}
	}

	if div {
		r.Neg(xPow[0], xPow[0])
	}

	return
}
