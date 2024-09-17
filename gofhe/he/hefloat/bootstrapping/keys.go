package bootstrapping

import (
	"app/gofhe/rlwe"
)

// EvaluationKeys is a struct storing the different
// evaluation keys required by the bootstrapper.
type EvaluationKeys struct {

	// EvkN1ToN2 is the evaluation key to switch from the residual parameters'
	// ring degree (N1) to the bootstrapping parameters' ring degree (N2)
	EvkN1ToN2 *rlwe.EvaluationKey

	// EvkN2ToN1 is the evaluation key to switch from the bootstrapping parameters'
	// ring degree (N2) to the residual parameters' ring degree (N1)
	EvkN2ToN1 *rlwe.EvaluationKey

	// EvkRealToCmplx is the evaluation key to switch from the standard ring to the
	// conjugate invariant ring.
	EvkRealToCmplx *rlwe.EvaluationKey

	// EvkCmplxToReal is the evaluation key to switch from the conjugate invariant
	// ring to the standard ring.
	EvkCmplxToReal *rlwe.EvaluationKey

	// EvkDenseToSparse is the evaluation key to switch
	// from the dense secret to the sparse secret.
	// https://eprint.iacr.org/2022/024
	EvkDenseToSparse *rlwe.EvaluationKey

	// EvkSparseToDense is the evaluation key to switch
	// from the sparse secret to the dense secret.
	// https://eprint.iacr.org/2022/024
	EvkSparseToDense *rlwe.EvaluationKey

	// MemEvaluationKeySet is the evaluation key set storing the relinearization
	// key and the Galois keys necessary for the bootstrapping circuit.
	*rlwe.MemEvaluationKeySet
}

// BinarySize returns the total binary size of the bootstrapper's keys.
func (b EvaluationKeys) BinarySize() (dLen int) {
	if b.EvkN1ToN2 != nil {
		dLen += b.EvkN1ToN2.BinarySize()
	}

	if b.EvkN2ToN1 != nil {
		dLen += b.EvkN2ToN1.BinarySize()
	}

	if b.EvkRealToCmplx != nil {
		dLen += b.EvkRealToCmplx.BinarySize()
	}

	if b.EvkCmplxToReal != nil {
		dLen += b.EvkCmplxToReal.BinarySize()
	}

	if b.EvkDenseToSparse != nil {
		dLen += b.EvkDenseToSparse.BinarySize()
	}

	if b.EvkSparseToDense != nil {
		dLen += b.EvkSparseToDense.BinarySize()
	}

	if b.MemEvaluationKeySet != nil {
		dLen += b.MemEvaluationKeySet.BinarySize()
	}

	return
}

// GenEncapsulationEvaluationKeysNew generates the low level encapsulation EvaluationKeys for the bootstrapping.
func (p Parameters) GenEncapsulationEvaluationKeysNew(skDense *rlwe.SecretKey) (EvkDenseToSparse, EvkSparseToDense *rlwe.EvaluationKey) {

	params := p.BootstrappingParameters

	if p.EphemeralSecretWeight == 0 {
		return
	}

	paramsSparse, _ := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN: params.LogN(),
		Q:    params.Q()[:1],
		P:    params.P()[:1],
	})

	kgenSparse := rlwe.NewKeyGenerator(paramsSparse)
	kgenDense := rlwe.NewKeyGenerator(params)
	skSparse := kgenSparse.GenSecretKeyWithHammingWeightNew(p.EphemeralSecretWeight)

	EvkDenseToSparse = kgenDense.GenEvaluationKeyNew(skDense, skSparse)
	EvkSparseToDense = kgenDense.GenEvaluationKeyNew(skSparse, skDense)
	return
}
