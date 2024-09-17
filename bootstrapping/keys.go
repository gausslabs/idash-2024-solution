package bootstrapping

import (
	"app/keys"

	"app/gofhe/he/hefloat/bootstrapping"
	"app/gofhe/ring"
	"app/gofhe/rlwe"
)

func GenEvaluationKeys(NumCPU int, skN1 *rlwe.SecretKey, p bootstrapping.Parameters) (btpkeys *bootstrapping.EvaluationKeys, skN2 *rlwe.SecretKey, err error) {

	var EvkN1ToN2, EvkN2ToN1 *rlwe.EvaluationKey
	var EvkRealToCmplx *rlwe.EvaluationKey
	var EvkCmplxToReal *rlwe.EvaluationKey
	paramsN2 := p.BootstrappingParameters

	kgen := rlwe.NewKeyGenerator(paramsN2)

	if p.ResidualParameters.N() != paramsN2.N() {
		// If the ring degree do not match
		// (if the residual parameters are Conjugate Invariant, N1 = N2/2)
		skN2 = kgen.GenSecretKeyNew()

		if p.ResidualParameters.RingType() == ring.ConjugateInvariant {
			EvkCmplxToReal, EvkRealToCmplx = kgen.GenEvaluationKeysForRingSwapNew(skN2, skN1)
		} else {
			EvkN1ToN2 = kgen.GenEvaluationKeyNew(skN1, skN2)
			EvkN2ToN1 = kgen.GenEvaluationKeyNew(skN2, skN1)
		}

	} else {

		rQ := paramsN2.RingQ()
		rP := paramsN2.RingP()

		// Else, keeps the same secret, but extends to the full modulus of the bootstrapping parameters.
		skN2 = rlwe.NewSecretKey(paramsN2)
		buff := rQ.NewPoly()

		// Extends basis Q0 -> QL * P
		paramsN2.RingQ().AtLevel(0).INTT(skN1.Q, buff)
		paramsN2.RingQ().AtLevel(0).IMForm(buff, buff)
		ring.ExtendBasisSmallNorm(rQ.SubRings[0].Modulus, rQ.ModuliChain(), buff, skN2.Q)
		ring.ExtendBasisSmallNorm(rQ.SubRings[0].Modulus, rP.ModuliChain(), buff, skN2.P)
		rQ.NTT(skN2.Q, skN2.Q)
		rQ.MForm(skN2.Q, skN2.Q)
		rP.NTT(skN2.P, skN2.P)
		rP.MForm(skN2.P, skN2.P)
	}

	EvkDenseToSparse, EvkSparseToDense := p.GenEncapsulationEvaluationKeysNew(skN2)

	galEls := append(p.GaloisElements(paramsN2), paramsN2.GaloisElementForComplexConjugation())
	km := keys.NewManager(NumCPU, paramsN2, len(galEls), skN2)
	km.LoadGaloisKeys(galEls)

	return &bootstrapping.EvaluationKeys{
		EvkN1ToN2:           EvkN1ToN2,
		EvkN2ToN1:           EvkN2ToN1,
		EvkRealToCmplx:      EvkRealToCmplx,
		EvkCmplxToReal:      EvkCmplxToReal,
		MemEvaluationKeySet: km.AsMemEvaluationKeySet(),
		EvkDenseToSparse:    EvkDenseToSparse,
		EvkSparseToDense:    EvkSparseToDense,
	}, skN2, nil
}
