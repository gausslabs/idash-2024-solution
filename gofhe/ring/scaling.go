package ring

// DivFloorByLastModulusNTT divides (floored) the polynomial by its last modulus.
// The input must be in the NTT domain.
// Output poly level must be equal or one less than input level.
func (r *Ring) DivFloorByLastModulusNTT(p0, buff, p1 Poly) {

	level := r.level

	r.SubRings[level].INTTLazy(p0.At(level), buff.At(0))

	RescaleConstants := r.RescaleConstants(level)

	for i, s := range r.SubRings[:level] {
		s.NTTLazy(buff.At(0), buff.Coeffs[1])
		// (-x[i] + x[-1]) * -InvQ
		s.SubThenMulScalarMontgomeryTwoModulus(buff.At(1), p0.At(i), RescaleConstants[i], p1.At(i))
	}
}

// DivFloorByLastModulus divides (floored) the polynomial by its last modulus.
// Output poly level must be equal or one less than input level.
func (r *Ring) DivFloorByLastModulus(p0, p1 Poly) {

	level := r.level

	RescaleConstants := r.RescaleConstants(level)

	for i, s := range r.SubRings[:level] {
		s.SubThenMulScalarMontgomeryTwoModulus(p0.At(level), p0.At(i), RescaleConstants[i], p1.At(i))
	}
}

// DivFloorByLastModulusManyNTT divides (floored) sequentially nbRescales times the polynomial by its last modulus. Input must be in the NTT domain.
// Output poly level must be equal or nbRescales less than input level.
func (r *Ring) DivFloorByLastModulusManyNTT(nbRescales int, p0, buff, p1 Poly) {

	if nbRescales == 0 {

		if !p0.Equal(&p1) {
			p1.Copy(&p0)
		}

	} else {

		rCpy := r.AtLevel(r.Level())

		rCpy.INTT(p0, buff)

		for i := 0; i < nbRescales; i++ {
			rCpy.DivFloorByLastModulus(buff, buff)
			rCpy = rCpy.AtLevel(rCpy.Level() - 1)
		}

		rCpy.NTT(buff, p1)
	}
}

// DivFloorByLastModulusMany divides (floored) sequentially nbRescales times the polynomial by its last modulus.
// Output poly level must be equal or nbRescales less than input level.
func (r *Ring) DivFloorByLastModulusMany(nbRescales int, p0, buff, p1 Poly) {

	if nbRescales == 0 {

		if !p0.Equal(&p1) {
			p1.Copy(&p0)
		}

	} else {

		if nbRescales > 1 {

			rCpy := r.AtLevel(r.Level())

			rCpy.DivFloorByLastModulus(p0, buff)
			rCpy = rCpy.AtLevel(rCpy.Level() - 1)

			for i := 1; i < nbRescales; i++ {

				if i == nbRescales-1 {
					rCpy.DivFloorByLastModulus(buff, p1)
				} else {
					rCpy.DivFloorByLastModulus(buff, buff)
				}

				rCpy = rCpy.AtLevel(rCpy.Level() - 1)
			}

		} else {
			r.DivFloorByLastModulus(p0, p1)
		}
	}
}

// DivRoundByLastModulusNTT divides (rounded) the polynomial by its last modulus. The input must be in the NTT domain.
// Output poly level must be equal or one less than input level.
func (r *Ring) DivRoundByLastModulusNTT(p0, buff, p1 Poly) {

	level := r.level

	r.SubRings[level].INTTLazy(p0.At(level), buff.At(level))

	// Center by (p-1)/2
	pHalf := (r.SubRings[level].Modulus - 1) >> 1

	r.SubRings[level].AddScalar(buff.At(level), pHalf, buff.Coeffs[level])

	RescaleConstants := r.RescaleConstants(level)

	for i, s := range r.SubRings[:level] {
		s.AddScalarLazy(buff.At(level), s.Modulus-BRedAdd(pHalf, s.Modulus, s.BRedConstant), buff.At(i))
		s.NTTLazy(buff.At(i), buff.At(i))
		s.SubThenMulScalarMontgomeryTwoModulus(buff.At(i), p0.At(i), RescaleConstants[i], p1.At(i))
	}
}

// DivRoundByLastModulus divides (rounded) the polynomial by its last modulus. The input must be in the NTT domain.
// Output poly level must be equal or one less than input level.
func (r *Ring) DivRoundByLastModulus(p0, p1 Poly) {

	level := r.level

	// Center by (p-1)/2
	pHalf := (r.SubRings[level].Modulus - 1) >> 1

	r.SubRings[level].AddScalar(p0.At(level), pHalf, p0.Coeffs[level])

	RescaleConstants := r.RescaleConstants(level)

	for i, s := range r.SubRings[:level] {
		s.AddScalarLazyThenNegTwoModulusLazy(p0.At(i), s.Modulus-BRedAdd(pHalf, s.Modulus, s.BRedConstant), p0.At(i))
		s.AddLazyThenMulScalarMontgomery(p0.At(level), p0.At(i), RescaleConstants[i], p1.At(i))
	}
}

// DivRoundByLastModulusManyNTT divides (rounded) sequentially nbRescales times the polynomial by its last modulus. The input must be in the NTT domain.
// Output poly level must be equal or nbRescales less than input level.
func (r *Ring) DivRoundByLastModulusManyNTT(nbRescales int, p0, buff, p1 Poly) {

	if nbRescales == 0 {

		if !p0.Equal(&p1) {
			p1.Copy(&p0)
		}

	} else {

		if nbRescales > 1 {

			rCpy := r.AtLevel(r.Level())

			rCpy.INTT(p0, buff)
			for i := 0; i < nbRescales; i++ {
				rCpy.DivRoundByLastModulus(buff, buff)
				rCpy = rCpy.AtLevel(rCpy.Level() - 1)
			}

			rCpy.NTT(buff, p1)

		} else {
			r.DivRoundByLastModulusNTT(p0, buff, p1)
		}
	}
}

// DivRoundByLastModulusMany divides (rounded) sequentially nbRescales times the polynomial by its last modulus.
// Output poly level must be equal or nbRescales less than input level.
func (r *Ring) DivRoundByLastModulusMany(nbRescales int, p0, buff, p1 Poly) {

	if nbRescales == 0 {

		if !p0.Equal(&p1) {
			p1.Copy(&p0)
		}

	} else {

		if nbRescales > 1 {

			rCpy := r.AtLevel(r.Level())

			rCpy.DivRoundByLastModulus(p0, buff)
			rCpy = rCpy.AtLevel(rCpy.Level() - 1)

			for i := 1; i < nbRescales; i++ {

				if i == nbRescales-1 {
					rCpy.DivRoundByLastModulus(buff, p1)
				} else {
					rCpy.DivRoundByLastModulus(buff, buff)
				}

				rCpy = rCpy.AtLevel(rCpy.Level() - 1)
			}

		} else {
			r.DivRoundByLastModulus(p0, p1)
		}
	}
}
