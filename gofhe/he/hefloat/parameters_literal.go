package hefloat

import (
	"math"

	"app/gofhe/ring"
	"app/gofhe/rlwe"
	"app/gofhe/utils/structs"
)

// ParametersLiteral is a literal representation of CKKS parameters.  It has public
// fields and is used to express unchecked user-defined parameters literally into
// Go programs. The NewParametersFromLiteral function is used to generate the actual
// checked parameters from the literal representation.
//
// Users must set the polynomial degree (in log_2, LogN) and the coefficient modulus, by either setting
// the Q and P fields to the desired moduli chain, or by setting the LogQ and LogP fields to
// the desired moduli sizes (in log_2). Users must also specify a default initial scale for the plaintexts.
//
// Optionally, users may specify the error variance (Sigma), the secrets' density (H), the ring
// type (RingType) and the number of slots (in log_2, LogSlots). If left unset, standard default values for
// these field are substituted at parameter creation (see NewParametersFromLiteral).
type ParametersLiteral struct {
	LogN            int
	LogNthRoot      int                         `json:",omitempty"`
	Q               structs.Vector[uint64]      `json:",omitempty"`
	P               structs.Vector[uint64]      `json:",omitempty"`
	LogQ            structs.Vector[int]         `json:",omitempty"`
	LogP            structs.Vector[int]         `json:",omitempty"`
	Xe              ring.DistributionParameters `json:",omitempty"`
	Xs              ring.DistributionParameters `json:",omitempty"`
	RingType        ring.Type                   `json:",omitempty"`
	LogDefaultScale int                         `json:",omitempty"`
}

// GetRLWEParametersLiteral returns the rlwe.ParametersLiteral from the target ckks.ParameterLiteral.
func (p ParametersLiteral) GetRLWEParametersLiteral() rlwe.ParametersLiteral {
	return rlwe.ParametersLiteral{
		LogN:         p.LogN,
		LogNthRoot:   p.LogNthRoot,
		Q:            p.Q,
		P:            p.P,
		LogQ:         p.LogQ,
		LogP:         p.LogP,
		Xe:           p.Xe,
		Xs:           p.Xs,
		RingType:     p.RingType,
		NTTFlag:      true,
		DefaultScale: rlwe.NewScale(math.Exp2(float64(p.LogDefaultScale))),
	}
}
