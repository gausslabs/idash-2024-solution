package utils

import (
	"encoding/csv"
	"fmt"
	"math"
	"math/big"
	"os"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/Pro7ech/lattigo/utils/concurrency"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

func LoadWithBench(msg string, f func() (err error)) (err error) {
	fmt.Printf("%s:\n", msg)
	now := time.Now()
	if err = f(); err != nil {
		fmt.Println()
		return
	}
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("	Time: %10s | Current: %5v MB | Peak: %5v MB\n", time.Since(now), m.Alloc>>20, m.Sys>>20)
	return
}

func RunWithBench(msg string, f func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error)) (err error) {
	fmt.Printf("%s:\n", msg)
	now := time.Now()
	var LevelIn, LevelOut int
	var LogScaleIn, LogScaleOut float64
	if LevelIn, LevelOut, LogScaleIn, LogScaleOut, err = f(); err != nil {
		fmt.Println()
		return
	}
	runtime.GC()
	fmt.Printf("	Time: %10s (%2d,%15.12f)->(%2d,%15.12f)\n", time.Since(now), LevelIn, LogScaleIn, LevelOut, LogScaleOut)
	return
}

func GetChebyshevPoly(A, B float64, degree int, f64 func(x float64) (y float64)) *he.Polynomial {

	FBig := func(x *big.Float) (y *big.Float) {
		xF64, _ := x.Float64()
		return new(big.Float).SetPrec(x.Prec()).SetFloat64(f64(xF64))
	}

	var prec uint = 128

	interval := bignum.Interval{
		A:     *bignum.NewFloat(A, prec),
		B:     *bignum.NewFloat(B, prec),
		Nodes: degree,
	}

	return he.NewPolynomial(bignum.ChebyshevApproximation(FBig, interval))
}

func ChebEval(coeffs []float64, A, B, x float64) (y float64) {
	n := len(coeffs)
	u := (2*x - A - B) / (B - A)
	Tprev := 1.0
	T := u
	y = coeffs[0]
	var Tnext float64
	for i := 1; i < n; i++ {
		y = y + T*coeffs[i]
		Tnext = 2*u*T - Tprev
		Tprev = T
		T = Tnext
	}
	return y
}

func CompositeEval(coeffs [][]float64, A, B, x float64) (y float64) {
	for i := range coeffs {
		if i == 0 {
			y = ChebEval(coeffs[0], A, B, x)
		} else {
			y = ChebEval(coeffs[i], -1, 1, y)
		}
	}
	return
}

func Rotate(in []float64, k int) {
	utils.RotateSliceInPlace(in, k)
}

func MaskAndReplicate(in []float64, scaling float64, k int) {

	var n int
	if maxSlots := len(in); maxSlots%k == 0 {
		n = maxSlots
	} else {
		n = (maxSlots/k)*k - 1
	}

	mask := make([]float64, n)
	for i := range mask {
		if i%k == 0 {
			mask[i] = scaling
		}
	}

	for i := range in {
		in[i] *= mask[i]
	}

	f := func(a, b, c []float64) {
		for i := range c {
			c[i] = a[i] + b[i]
		}
	}

	InnerFunction(in, -1, k, f, in)
}

func InnerFunction(in []float64, batchSize, n int, f func(a, b, c []float64), out []float64) {

	inCpy := make([]float64, len(in))
	copy(inCpy, in)

	acc := make([]float64, len(in))
	tmp := make([]float64, len(in))

	state := false
	first := true
	for i, j := 0, n; j > 0; i, j = i+1, j>>1 {
		if j&1 == 1 {
			k := n - (n & ((2 << i) - 1))
			k *= batchSize
			if k != 0 {
				if first {
					utils.RotateSliceAllocFree(inCpy, k, acc)
					first = false
				} else {
					utils.RotateSliceAllocFree(inCpy, k, tmp)
					f(acc, tmp, acc)
				}
			} else {
				state = true
				if n&(n-1) != 0 {
					copy(out, acc)
					f(out, inCpy, out)
				} else {
					copy(out, inCpy)
				}
			}
		}

		if !state {
			utils.RotateSliceAllocFree(inCpy, (1<<i)*batchSize, tmp)
			f(inCpy, tmp, inCpy)
		}
	}

	return
}

func InnerMax(in []float64, k int, f func(a, b, c []float64)) {
	tmp := make([]float64, len(in))
	for k != 1 {
		utils.RotateSliceAllocFree(in, k>>1, tmp)
		f(in, tmp, in)
		if k&1 == 1 {
			k++
		}
		k >>= 1
	}
}

func MaxIndex(data []float64) (idx int) {
	m := -1e300
	for i := range data {
		if c := data[i]; c > m {
			idx = i
			m = c
		}
	}
	return
}

func Precision(have, want []*mat.Dense) (accuracy, noise float64) {
	if len(have) != len(want) {
		panic(fmt.Errorf("invalid input: len(have) != len(want)"))
	}

	rows, cols := have[0].Dims()

	for i := range have {

		m0 := have[i].RawMatrix().Data
		m1 := want[i].RawMatrix().Data

		predHave := MaxIndex(m0)
		predHwant := MaxIndex(m1)

		if predHave == predHwant {
			accuracy += 1
		}

		for j := range m0 {
			noise += math.Abs(m0[j] - m1[j])
		}
	}

	accuracy /= float64(len(have))
	noise /= float64(len(have) * rows * cols)
	return
}

type Stats struct {
	Min []float64
	Max []float64
	Avg []float64
	Std []float64
}

func (s *Stats) Print() {
	for i := range s.Min {
		fmt.Printf("%3d", i)
		fmt.Printf("%15.7f", s.Min[i])
		fmt.Printf("%15.7f", s.Max[i])
		fmt.Printf("%15.7f", s.Avg[i])
		fmt.Printf("%15.7f", s.Std[i])
		fmt.Println()
	}
}

func StatsRows(m []*mat.Dense) Stats {
	rows, cols := m[0].Dims()

	Min := make([]float64, rows)
	Max := make([]float64, rows)
	Avg := make([]float64, rows)
	Std := make([]float64, rows)

	for i := range rows {
		Min[i] = 1e300
		Max[i] = -1e300
	}

	n := float64(len(m) * cols)

	for k := range m {

		for i := range rows {

			vec := m[k].RawRowView(i)

			Min[i] = min(Min[i], slices.Min(vec))
			Max[i] = max(Max[i], slices.Max(vec))

			for j := range cols {
				Avg[i] += vec[j]
			}
		}
	}

	for i := range rows {
		Avg[i] /= n
	}

	for k := range m {

		for i := range rows {

			vec := m[k].RawRowView(i)

			for j := range cols {
				x := vec[j] - Avg[i]
				Std[i] += x * x
			}
		}
	}

	for i := range rows {
		Std[i] = math.Sqrt(Std[i] / n)
	}

	return Stats{
		Min: Min,
		Max: Max,
		Avg: Avg,
		Std: Std,
	}
}

func Flatten(m [][]*mat.Dense) (flattened []*mat.Dense) {
	rows, cols := len(m), len(m[0])
	flattened = make([]*mat.Dense, len(m)*len(m[0]))
	for i := range rows {
		for j := range cols {
			flattened[i*cols+j] = m[i][j]
		}
	}
	return
}

// MinDiff[0]: minimum difference between two values of a row
// MinDiff[1]: minimum of the row having the minimum differen
func StatsDiff(m *mat.Dense) (MaxDiff, Min, Max float64) {

	MaxDiff = 0
	Min = 1e300
	Max = -1e300

	rows, cols := m.Dims()

	for i := range rows {
		data := m.RawMatrix().Data[i*cols : (i+1)*cols]

		a := slices.Min(data)
		b := slices.Max(data)
		diff := math.Abs(b - a)

		if diff > MaxDiff {
			MaxDiff = diff
			Min = a
			Max = b
		}
	}

	return
}

func PrettyPrint(in *mat.Dense) {
	rows, cols := in.Dims()
	raw := in.RawMatrix().Data
	for i := range rows {
		for j := range cols {
			fmt.Printf("%7.4f ", raw[i*cols+j])
		}
		fmt.Println()
	}
	fmt.Println()
}

func BiasToDense(rows int, b []float64) *mat.Dense {

	cols := len(b)

	m := make([]float64, rows*cols)

	for i := range rows {
		copy(m[i*cols:], b)
	}

	return mat.NewDense(rows, cols, m)
}

func Debug(n int, ct *rlwe.Ciphertext, dec *rlwe.Decryptor, ecd *hefloat.Encoder) {
	v := make([]float64, n)
	if err := ecd.Decode(dec.DecryptNew(ct), v); err != nil {
		panic(err)
	}

	fmt.Printf("Level: %d - LogScale: %f - [", ct.Level(), math.Log2(ct.Scale.Float64()))

	for i := 0; i < n; i++ {
		fmt.Printf("%15.10f, ", v[i])
	}
	fmt.Printf("]\n")
}

func ReadFile(path string, separator rune, drop int, header bool, NumCPU int) (records [][]float64, err error) {

	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	r := csv.NewReader(f)

	r.Comma = separator

	data, err := r.ReadAll()

	if err != nil {
		return nil, err
	}

	records = make([][]float64, len(data))

	for i := range records {
		records[i] = make([]float64, len(data[0][drop:]))
	}

	m := concurrency.NewRessourceManager[bool](make([]bool, NumCPU))

	for i := range data {
		m.Run(func(b bool) (err error) {
			line := data[i][drop:]
			v := records[i]

			for j := 0; j < len(line); j++ {
				if v[j], err = strconv.ParseFloat(line[j], 64); err != nil {
					return
				}
			}
			return
		})
	}

	if err = m.Wait(); err != nil {
		return
	}

	if header {
		return records[1:], nil
	}

	return
}
