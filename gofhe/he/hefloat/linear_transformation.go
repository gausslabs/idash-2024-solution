package hefloat

import (
	"app/gofhe/rlwe"
)

// TraceNew maps X -> sum((-1)^i * X^{i*n+1}) for 0 <= i < N and returns the result on a new ciphertext.
// For log(n) = logSlots.
func (eval Evaluator) TraceNew(ctIn *rlwe.Ciphertext, logSlots int) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), 1, ctIn.Level())
	return opOut, eval.Trace(ctIn, logSlots, opOut)
}
