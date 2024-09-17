package rlwe

import (
	"fmt"

	"app/gofhe/ring"
)

// GadgetProduct evaluates poly x Gadget -> RLWE where
//
// ct = [<decomp(cx), gadget[0]>, <decomp(cx), gadget[1]>] mod Q
func (eval Evaluator) GadgetProduct(LevelQ int, cx ring.Poly, cxIsNTT bool, gadgetCt *GadgetCiphertext, ct *Ciphertext) {

	LevelQ = min(LevelQ, gadgetCt.LevelQ())
	LevelP := gadgetCt.LevelP()

	ctTmp := &Ciphertext{}
	ctTmp.Vector = &ring.Vector{}
	ctTmp.Q = []ring.Poly{ct.Q[0], ct.Q[1]}
	if LevelP > -1 {
		ctTmp.P = []ring.Poly{eval.BuffP[0], eval.BuffP[1]}
	}
	ctTmp.MetaData = ct.MetaData.Clone()
	ctTmp.IsNTT = true // GadgetProductLazy always returns in the NTT domain

	if err := eval.GadgetProductLazy(LevelQ, true, cx, cxIsNTT, gadgetCt, ctTmp); err != nil {
		panic(fmt.Errorf("eval.GadgetProductLazy: %w", err))
	}

	eval.ModDown(LevelQ, LevelP, ctTmp, ct)
}

// ModDown takes elQP (mod QP) and returns elQ = (elQP/P) (mod Q).
func (eval Evaluator) ModDown(LevelQ, LevelP int, elQP, elQ *Ciphertext) {

	rQ := eval.params.RingQ().AtLevel(LevelQ)

	if LevelP != -1 {

		if elQP.IsNTT {
			if elQ.IsNTT {
				// NTT -> NTT
				eval.BasisExtender.ModDownQPtoQNTT(LevelQ, LevelP, elQP.Q[0], elQP.P[0], elQ.Q[0])
				eval.BasisExtender.ModDownQPtoQNTT(LevelQ, LevelP, elQP.Q[1], elQP.P[1], elQ.Q[1])
			} else {
				// NTT -> INTT
				rP := eval.params.RingP().AtLevel(LevelP)
				rQ.INTTLazy(elQP.Q[0], elQP.Q[0])
				rQ.INTTLazy(elQP.Q[1], elQP.Q[1])
				rP.INTTLazy(elQP.P[0], elQP.P[0])
				rP.INTTLazy(elQP.P[1], elQP.P[1])

				eval.BasisExtender.ModDownQPtoQ(LevelQ, LevelP, elQP.Q[0], elQP.P[0], elQ.Q[0])
				eval.BasisExtender.ModDownQPtoQ(LevelQ, LevelP, elQP.Q[1], elQP.P[1], elQ.Q[1])
			}
		} else {
			if elQ.IsNTT {
				// INTT -> NTT
				eval.BasisExtender.ModDownQPtoQ(LevelQ, LevelP, elQP.Q[0], elQP.P[0], elQ.Q[0])
				eval.BasisExtender.ModDownQPtoQ(LevelQ, LevelP, elQP.Q[1], elQP.P[1], elQ.Q[1])

				rQ.NTT(elQ.Q[0], elQ.Q[0])
				rQ.NTT(elQ.Q[1], elQ.Q[1])

			} else {
				// INTT -> INTT
				eval.BasisExtender.ModDownQPtoQ(LevelQ, LevelP, elQP.Q[0], elQP.P[0], elQ.Q[0])
				eval.BasisExtender.ModDownQPtoQ(LevelQ, LevelP, elQP.Q[1], elQP.P[1], elQ.Q[1])
			}
		}
	} else {
		if elQP.IsNTT {
			if elQ.IsNTT {
				// NTT -> NTT
				elQP.Q[0].CopyLvl(LevelQ, &elQ.Q[0])
				elQP.Q[1].CopyLvl(LevelQ, &elQ.Q[1])
			} else {
				// NTT -> INTT
				rQ.INTT(elQP.Q[0], elQ.Q[0])
				rQ.INTT(elQP.Q[1], elQ.Q[1])
			}
		} else {
			if elQ.IsNTT {
				// INTT -> NTT
				rQ.NTT(elQP.Q[0], elQ.Q[0])
				rQ.NTT(elQP.Q[1], elQ.Q[1])

			} else {
				// INTT -> INTT
				elQP.Q[0].CopyLvl(LevelQ, &elQ.Q[0])
				elQP.Q[1].CopyLvl(LevelQ, &elQ.Q[1])
			}
		}
	}
}

// GadgetProductLazy evaluates poly x Gadget -> RLWE where
//
// ct = [<decomp(cx), gadget[0]>, <decomp(cx), gadget[1]>] mod QP
//
// Result is always written (overwrite = true) / added (overwrite = false) on ct in the NTT domain, regardless of the NTT flag of ct.
func (eval Evaluator) GadgetProductLazy(LevelQ int, overwrite bool, cx ring.Poly, cxIsNTT bool, gadgetCt *GadgetCiphertext, ct *Ciphertext) (err error) {

	if ct.LevelP() < gadgetCt.LevelP() {
		return fmt.Errorf("ct.LevelP()=%d < gadgetCt.LevelP()=%d", ct.Level(), gadgetCt.LevelP())
	}

	switch gadgetCt.DigitDecomposition.Type {
	case Signed, SignedBalanced:
		eval.gadgetProductWithSignedDigitDecompositionLazy(LevelQ, overwrite, cx, cxIsNTT, gadgetCt, ct)
	case Unsigned:
		eval.gadgetProductWithUnsignedDigitDecompositionLazy(LevelQ, overwrite, cx, cxIsNTT, gadgetCt, ct)
	default:
		eval.gadgetProductLazy(LevelQ, overwrite, cx, cxIsNTT, gadgetCt, ct)
	}

	return
}

func (eval Evaluator) gadgetProductLazy(LevelQ int, overwrite bool, cx ring.Poly, cxIsNTT bool, gadgetCt *GadgetCiphertext, ct *Ciphertext) {

	LevelP := gadgetCt.LevelP()

	rQ := eval.params.RingQ().AtLevel(LevelQ)
	QiOverF := eval.params.QiOverflowMargin(LevelQ) >> 1

	var rP *ring.Ring
	var PiOverF int
	if rP = eval.params.RingP(); rP != nil && LevelP > -1 {
		rP = rP.AtLevel(LevelP)
		PiOverF = eval.params.PiOverflowMargin(LevelP) >> 1
	}

	c2QP := eval.BuffDecompQP[0]

	var cxNTT, cxINTT ring.Poly
	if cxIsNTT {
		cxNTT = cx
		cxINTT = eval.BuffInvNTT
		rQ.INTT(cxNTT, cxINTT)
	} else {
		cxNTT = eval.BuffInvNTT
		cxINTT = cx
		rQ.NTT(cxINTT, cxNTT)
	}

	gdel := gadgetCt.Vector

	var reduce int
	for i := range eval.params.DecompositionMatrixDimensions(LevelQ, LevelP, DigitDecomposition{}) {

		eval.DecomposeSingleNTT(LevelQ, LevelP, LevelP+1, i, cxNTT, cxINTT, c2QP[0], c2QP[1])

		if i == 0 && overwrite {

			rQ.MulCoeffsMontgomeryLazy(gdel[0].Q[i][0], c2QP[0], ct.Q[0])
			rQ.MulCoeffsMontgomeryLazy(gdel[1].Q[i][0], c2QP[0], ct.Q[1])

			if LevelP > -1 {
				rP.MulCoeffsMontgomeryLazy(gdel[0].P[i][0], c2QP[1], ct.P[0])
				rP.MulCoeffsMontgomeryLazy(gdel[1].P[i][0], c2QP[1], ct.P[1])
			}

		} else {

			rQ.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].Q[i][0], c2QP[0], ct.Q[0])
			rQ.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].Q[i][0], c2QP[0], ct.Q[1])

			if LevelP > -1 {
				rP.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].P[i][0], c2QP[1], ct.P[0])
				rP.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].P[i][0], c2QP[1], ct.P[1])
			}

		}

		if reduce%QiOverF == QiOverF-1 {
			rQ.Reduce(ct.Q[0], ct.Q[0])
			rQ.Reduce(ct.Q[1], ct.Q[1])
		}

		if LevelP > -1 && reduce%PiOverF == PiOverF-1 {
			rP.Reduce(ct.P[0], ct.P[0])
			rP.Reduce(ct.P[1], ct.P[1])
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		rQ.Reduce(ct.Q[0], ct.Q[0])
		rQ.Reduce(ct.Q[1], ct.Q[1])
	}

	if LevelP > -1 && reduce%PiOverF != 0 {
		rP.Reduce(ct.P[0], ct.P[0])
		rP.Reduce(ct.P[1], ct.P[1])
	}
}

func (eval Evaluator) gadgetProductWithSignedDigitDecompositionLazy(LevelQ int, overwrite bool, cx ring.Poly, cxIsNTT bool, gadgetCt *GadgetCiphertext, ct *Ciphertext) {

	LevelP := gadgetCt.LevelP()

	rQ := eval.params.RingQ().AtLevel(LevelQ)

	var cxINTT ring.Poly
	if cxIsNTT {
		cxINTT = eval.BuffInvNTT
		rQ.INTT(cx, cxINTT)
	} else {
		cxINTT = cx
	}

	rows := LevelQ + 1
	dims := gadgetCt.Dims()

	log2basis := gadgetCt.DigitDecomposition.Log2Basis

	buff := eval.BuffInvNTT.At(0)
	carry := eval.BuffDigitDecomp[0]
	cw := eval.BuffDigitDecomp[1]
	cwNTT := cw

	var decompose func(s *ring.SubRing, i int, log2basis uint64, in, carry, out []uint64)
	switch gadgetCt.DigitDecomposition.Type {
	case Signed:
		decompose = func(s *ring.SubRing, i int, log2basis uint64, in, carry, out []uint64) {
			s.DecomposeSigned(i, log2basis, in, carry, out)
		}
	case SignedBalanced:
		decompose = func(s *ring.SubRing, i int, log2basis uint64, in, carry, out []uint64) {
			s.DecomposeSignedBalanced(i, log2basis, in, carry, out)
		}
	}

	QiOverF := eval.params.QiOverflowMargin(LevelQ) >> 1

	var PiOverF int
	var rP *ring.Ring
	if LevelP != -1 {
		rP = eval.params.RingP().AtLevel(LevelP)
		PiOverF = eval.params.PiOverflowMargin(LevelP) >> 1
	}

	gdel := gadgetCt.Vector

	// Re-encryption with CRT decomposition for the Qi
	var reduceQ, reduceP int
	for i := 0; i < rows; i++ {

		rQ.SubRings[i].CenterModU64(cxINTT.At(i), buff)

		for u, s := range rQ.SubRings[:LevelQ+1] {

			reduceQ = 0

			for j := 0; j < dims[i]; j++ {

				decompose(s, j, uint64(log2basis), buff, carry, cw)
				s.NTTLazy(cw, cwNTT)

				if i == 0 && j == 0 && overwrite {
					s.MulCoeffsMontgomeryLazy(gdel[0].Q[i][j].At(u), cwNTT, ct.Q[0].At(u))
					s.MulCoeffsMontgomeryLazy(gdel[1].Q[i][j].At(u), cwNTT, ct.Q[1].At(u))
				} else {
					s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].Q[i][j].At(u), cwNTT, ct.Q[0].At(u))
					s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].Q[i][j].At(u), cwNTT, ct.Q[1].At(u))
				}

				if reduceQ%QiOverF == QiOverF-1 {
					s.Reduce(ct.Q[0].At(u), ct.Q[0].At(u))
					s.Reduce(ct.Q[1].At(u), ct.Q[1].At(u))
				}

				reduceQ++
			}
		}

		if rP != nil {
			for u, s := range rP.SubRings[:LevelP+1] {

				reduceP = 0

				for j := 0; j < dims[i]; j++ {

					decompose(s, j, uint64(log2basis), buff, carry, cw)
					s.NTTLazy(cw, cwNTT)

					if i == 0 && j == 0 && overwrite {
						s.MulCoeffsMontgomeryLazy(gdel[0].P[i][j].At(u), cwNTT, ct.P[0].At(u))
						s.MulCoeffsMontgomeryLazy(gdel[1].P[i][j].At(u), cwNTT, ct.P[1].At(u))
					} else {
						s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].P[i][j].At(u), cwNTT, ct.P[0].At(u))
						s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].P[i][j].At(u), cwNTT, ct.P[1].At(u))
					}

					if reduceP%PiOverF == PiOverF-1 {
						s.Reduce(ct.P[0].At(u), ct.P[0].At(u))
						s.Reduce(ct.P[1].At(u), ct.P[1].At(u))
					}

					reduceP++
				}
			}
		}
	}

	if reduceQ%QiOverF != 0 {
		rQ.Reduce(ct.Q[0], ct.Q[0])
		rQ.Reduce(ct.Q[1], ct.Q[1])
	}

	if rP != nil && reduceP%PiOverF != 0 {
		rP.Reduce(ct.P[0], ct.P[0])
		rP.Reduce(ct.P[1], ct.P[1])
	}
}

func (eval Evaluator) gadgetProductWithUnsignedDigitDecompositionLazy(LevelQ int, overwrite bool, cx ring.Poly, cxIsNTT bool, gadgetCt *GadgetCiphertext, ct *Ciphertext) {

	LevelP := gadgetCt.LevelP()

	rQ := eval.params.RingQ().AtLevel(LevelQ)

	var cxINTT ring.Poly
	if cxIsNTT {
		cxINTT = eval.BuffInvNTT
		rQ.INTT(cx, cxINTT)
	} else {
		cxINTT = cx
	}

	log2basis := gadgetCt.DigitDecomposition.Log2Basis

	cw := eval.BuffDigitDecomp[0]
	cwNTT := eval.BuffDigitDecomp[1]

	QiOverF := eval.params.QiOverflowMargin(LevelQ) >> 1

	var PiOverF int
	var rP *ring.Ring
	if LevelP != -1 {
		rP = eval.params.RingP().AtLevel(LevelP)
		PiOverF = eval.params.PiOverflowMargin(LevelP) >> 1
	}

	gdel := gadgetCt.Vector

	rows := LevelQ + 1
	dims := gadgetCt.Dims()

	var reduceQ, reduceP int
	for i := 0; i < rows; i++ {

		reduceP = 0
		reduceQ = 0

		for j := 0; j < dims[i]; j++ {

			rQ.SubRings[0].DecomposeUnsigned(j, uint64(log2basis), cxINTT.At(i), cw)

			for u, s := range rQ.SubRings[:LevelQ+1] {

				s.NTTLazy(cw, cwNTT)

				if i == 0 && j == 0 && overwrite {
					s.MulCoeffsMontgomeryLazy(gdel[0].Q[i][j].At(u), cwNTT, ct.Q[0].At(u))
					s.MulCoeffsMontgomeryLazy(gdel[1].Q[i][j].At(u), cwNTT, ct.Q[1].At(u))
				} else {
					s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].Q[i][j].At(u), cwNTT, ct.Q[0].At(u))
					s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].Q[i][j].At(u), cwNTT, ct.Q[1].At(u))
				}
			}

			if reduceQ%QiOverF == QiOverF-1 {
				rQ.Reduce(ct.Q[0], ct.Q[0])
				rQ.Reduce(ct.Q[1], ct.Q[1])
			}

			reduceQ++

			if rP != nil {
				for u, s := range rP.SubRings[:LevelP+1] {

					s.NTTLazy(cw, cwNTT)

					if i == 0 && j == 0 && overwrite {
						s.MulCoeffsMontgomeryLazy(gdel[0].P[i][j].At(u), cwNTT, ct.P[0].At(u))
						s.MulCoeffsMontgomeryLazy(gdel[1].P[i][j].At(u), cwNTT, ct.P[1].At(u))
					} else {
						s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].P[i][j].At(u), cwNTT, ct.P[0].At(u))
						s.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].P[i][j].At(u), cwNTT, ct.P[1].At(u))
					}
				}

				if reduceP%PiOverF == PiOverF-1 {
					rP.Reduce(ct.P[0], ct.P[0])
					rP.Reduce(ct.P[1], ct.P[1])
				}

				reduceP++
			}
		}
	}

	if reduceQ%QiOverF != 0 {
		rQ.Reduce(ct.Q[0], ct.Q[0])
		rQ.Reduce(ct.Q[1], ct.Q[1])
	}

	if rP != nil && reduceP%PiOverF != 0 {
		rP.Reduce(ct.P[0], ct.P[0])
		rP.Reduce(ct.P[1], ct.P[1])
	}
}

// GadgetProductHoisted applies the key-switch to the decomposed polynomial c2 mod QP (BuffQPDecompQP)
// divides the result by P, reducing the basis from QP to Q, and stores the result in ct.
//
// ct = [<BuffQPDecompQP, gadget[0]>, <BuffQPDecompQP, gadget[1]>] mod Q
//
// BuffQPDecompQP is expected to be in the NTT domain.
//
// Result NTT domain is returned according to the NTT flag of ct.
func (eval Evaluator) GadgetProductHoisted(LevelQ int, BuffQPDecompQP [][2]ring.Poly, gadgetCt *GadgetCiphertext, ct *Ciphertext) {

	ctTmp := &Ciphertext{}
	ctTmp.Vector = &ring.Vector{}
	ctTmp.Q = []ring.Poly{ct.Q[0], ct.Q[1]}
	ctTmp.P = []ring.Poly{eval.BuffP[0], eval.BuffP[1]}
	ctTmp.MetaData = ct.MetaData.Clone()
	ctTmp.IsNTT = true // GadgetProductHoistedLazy always returns in the NTT domain

	if err := eval.GadgetProductHoistedLazy(LevelQ, true, BuffQPDecompQP, gadgetCt, ctTmp); err != nil {
		panic(fmt.Errorf("eval.GadgetProductHoistedLazy: %w", err))
	}

	eval.ModDown(LevelQ, gadgetCt.LevelP(), ctTmp, ct)
}

// GadgetProductHoistedLazy applies the gadget product to the decomposed polynomial c2 mod QP (BuffQPDecompQP)
//
// (c0, c1) = dot(BuffQPDecompQ * gadgetCt[0]) mod QP
// BuffQP3 = dot(BuffQPDecompQ * gadgetCt[1]) mod QP
//
// BuffQPDecompQP is expected to be in the NTT domain.
//
// Result is always written (overwrite = true) / added (overwrite = false) on ct in the NTT domain, regardless of the NTT flag of ct.
func (eval Evaluator) GadgetProductHoistedLazy(LevelQ int, overwrite bool, BuffQPDecompQP [][2]ring.Poly, gadgetCt *GadgetCiphertext, ct *Ciphertext) (err error) {

	// Sanity check for invalid parameters.
	if int(gadgetCt.DigitDecomposition.Type) != 0 {
		return fmt.Errorf("cannot GadgetProductHoistedLazy: method is unsupported for BaseTwoDecomposition != 0")
	}

	if ct.LevelP() < gadgetCt.LevelP() {
		return fmt.Errorf("ct.LevelP()=%d < gadgetCt.LevelP()=%d", ct.LevelP(), gadgetCt.LevelP())
	}

	eval.gadgetProductMultiplePLazyHoisted(LevelQ, overwrite, BuffQPDecompQP, gadgetCt, ct)

	return
}

func (eval Evaluator) gadgetProductMultiplePLazyHoisted(LevelQ int, overwrite bool, BuffQPDecompQP [][2]ring.Poly, gadgetCt *GadgetCiphertext, ct *Ciphertext) {

	LevelP := gadgetCt.LevelP()

	rQ := eval.params.RingQ().AtLevel(LevelQ)
	rP := eval.params.RingP().AtLevel(LevelP)

	QiOverF := eval.params.QiOverflowMargin(LevelQ) >> 1
	PiOverF := eval.params.PiOverflowMargin(LevelP) >> 1

	gdel := gadgetCt.Vector

	// Key switching with CRT decomposition for the Qi
	var reduce int
	for i := range eval.params.DecompositionMatrixDimensions(LevelQ, LevelP, DigitDecomposition{}) {

		if i == 0 && overwrite {
			rQ.MulCoeffsMontgomeryLazy(gdel[0].Q[i][0], BuffQPDecompQP[i][0], ct.Q[0])
			rQ.MulCoeffsMontgomeryLazy(gdel[1].Q[i][0], BuffQPDecompQP[i][0], ct.Q[1])
			rP.MulCoeffsMontgomeryLazy(gdel[0].P[i][0], BuffQPDecompQP[i][1], ct.P[0])
			rP.MulCoeffsMontgomeryLazy(gdel[1].P[i][0], BuffQPDecompQP[i][1], ct.P[1])
		} else {
			rQ.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].Q[i][0], BuffQPDecompQP[i][0], ct.Q[0])
			rQ.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].Q[i][0], BuffQPDecompQP[i][0], ct.Q[1])
			rP.MulCoeffsMontgomeryLazyThenAddLazy(gdel[0].P[i][0], BuffQPDecompQP[i][1], ct.P[0])
			rP.MulCoeffsMontgomeryLazyThenAddLazy(gdel[1].P[i][0], BuffQPDecompQP[i][1], ct.P[1])
		}

		if reduce%QiOverF == QiOverF-1 {
			rQ.Reduce(ct.Q[0], ct.Q[0])
			rQ.Reduce(ct.Q[1], ct.Q[1])
		}

		if reduce%PiOverF == PiOverF-1 {
			rP.Reduce(ct.P[0], ct.P[0])
			rP.Reduce(ct.P[1], ct.P[1])
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		rQ.Reduce(ct.Q[0], ct.Q[0])
		rQ.Reduce(ct.Q[1], ct.Q[1])
	}

	if reduce%PiOverF != 0 {
		rP.Reduce(ct.P[0], ct.P[0])
		rP.Reduce(ct.P[1], ct.P[1])
	}
}

// DecomposeNTT applies the full RNS basis decomposition on c2.
// BuffQPDecompQ and BuffQPDecompQ are vectors of polynomials (mod Q and mod P) that store the
// special RNS decomposition of c2 (in the NTT domain)
func (eval Evaluator) DecomposeNTT(LevelQ, LevelP, nbPi int, cx ring.Poly, cxIsNTT bool, decompQP [][2]ring.Poly) {

	rQ := eval.params.RingQAtLevel(LevelQ)

	var polyNTT, polyInvNTT ring.Poly

	if cxIsNTT {
		polyNTT = cx
		polyInvNTT = eval.BuffInvNTT
		rQ.INTT(polyNTT, polyInvNTT)
	} else {
		polyNTT = eval.BuffInvNTT
		polyInvNTT = cx
		rQ.NTT(polyInvNTT, polyNTT)
	}

	for i := range eval.params.DecompositionMatrixDimensions(LevelQ, LevelP, DigitDecomposition{}) {
		eval.DecomposeSingleNTT(LevelQ, LevelP, nbPi, i, polyNTT, polyInvNTT, decompQP[i][0], decompQP[i][1])
	}
}

// DecomposeSingleNTT takes the input polynomial c2 (c2NTT and c2InvNTT, respectively in the NTT and out of the NTT domain)
// modulo the RNS basis, and returns the result on c2QiQ and c2QiP, the receiver polynomials respectively mod Q and mod P (in the NTT domain)
func (eval Evaluator) DecomposeSingleNTT(LevelQ, LevelP, nbPi, BaseRNSDecompositionVectorSize int, c2NTT, c2InvNTT, c2QiQ, c2QiP ring.Poly) {

	rQ := eval.params.RingQAtLevel(LevelQ)
	rP := eval.params.RingPAtLevel(LevelP)

	eval.Decomposer.DecomposeAndSplit(LevelQ, LevelP, nbPi, BaseRNSDecompositionVectorSize, c2InvNTT, c2QiQ, c2QiP)

	start := BaseRNSDecompositionVectorSize * nbPi
	end := start + nbPi

	// c2_qi = cx mod qi mod qi
	for x := 0; x < LevelQ+1; x++ {
		if start <= x && x < end {
			copy(c2QiQ.At(x), c2NTT.At(x))
		} else {
			rQ.SubRings[x].NTT(c2QiQ.At(x), c2QiQ.At(x))
		}
	}

	if LevelP > -1 {
		// c2QiP = c2 mod qi mod pj
		rP.NTT(c2QiP, c2QiP)
	}
}
