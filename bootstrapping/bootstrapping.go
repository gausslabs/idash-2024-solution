package bootstrapping

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/Pro7ech/lattigo/utils/concurrency"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/he/hefloat/bootstrapping"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Bootstrapper struct {
	hefloat.Parameters
	Bootstrappers []he.Bootstrapper[rlwe.Ciphertext]
	Count         int
	Sk            *rlwe.SecretKey
	Debug         bool
}

func (btp *Bootstrapper) BootstrappingParameters() bootstrapping.Parameters {
	return btp.Bootstrappers[0].(*bootstrapping.Evaluator).Parameters
}

func NewBootstrapper(NumCPU int, btpParams bootstrapping.Parameters, sk *rlwe.SecretKey) *Bootstrapper {

	fmt.Println(btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogQP())

	fmt.Println("Generating Bootstrapping Keys")
	now := time.Now()
	evkBTP, _, err := GenEvaluationKeys(NumCPU, sk, btpParams)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", time.Since(now))

	fmt.Println("Instantiating Bootstrapper")
	now = time.Now()
	btp, err := bootstrapping.NewEvaluator(btpParams, evkBTP)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", time.Since(now))

	Bootstrappers := make([]he.Bootstrapper[rlwe.Ciphertext], NumCPU)
	Bootstrappers[0] = btp
	for i := range NumCPU - 1 {
		Bootstrappers[i+1] = btp.ShallowCopy()
	}

	return &Bootstrapper{Bootstrappers: Bootstrappers, Parameters: btpParams.ResidualParameters, Sk: sk}
}

func NewDummyBootstrapper(NumCPU int, params hefloat.Parameters, sk *rlwe.SecretKey) *Bootstrapper {

	Bootstrappers := make([]he.Bootstrapper[rlwe.Ciphertext], NumCPU)
	for i := range NumCPU {
		Bootstrappers[i] = bootstrapping.NewSecretKeyBootstrapper(params, sk)
	}

	return &Bootstrapper{Bootstrappers: Bootstrappers, Parameters: params, Sk: sk}
}

func (btp *Bootstrapper) Bootstrap(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	cts := []rlwe.Ciphertext{*ct}
	var err error
	cts, err = btp.BootstrapMany(cts)
	return &cts[0], err
}

func (btp *Bootstrapper) BootstrapMany(cts []rlwe.Ciphertext) ([]rlwe.Ciphertext, error) {

	var dec *rlwe.Decryptor
	var ecd *hefloat.Encoder
	var before [][]float64
	if btp.Debug {
		dec = rlwe.NewDecryptor(btp.Parameters, btp.Sk)
		ecd = hefloat.NewEncoder(btp.Parameters)

		before = make([][]float64, len(cts))

		Max := []float64{}
		for i := range cts {
			before[i] = make([]float64, cts[i].Slots())
			ecd.Decode(dec.DecryptNew(&cts[i]), before[i])
			Max = append(Max, slices.Max(before[i]), slices.Min(before[i]))
		}

		fmt.Printf("	BootstrapMany %d %f: %d->%d - Max:%v ->", len(cts), cts[0].LogScale(), cts[0].Level(), btp.OutputLevel(), Max)
	} else {
		fmt.Printf("	BootstrapMany %d %f: %d->%d ", len(cts), cts[0].LogScale(), cts[0].Level(), btp.OutputLevel())
	}

	var err error
	m := concurrency.NewRessourceManager[he.Bootstrapper[rlwe.Ciphertext]](btp.Bootstrappers)
	now := time.Now()
	for i := 0; i < (len(cts)+1)>>1; i++ {
		m.Run(func(btp he.Bootstrapper[rlwe.Ciphertext]) (err error) {
			if (i<<1)+1 < len(cts) {
				var tmp []rlwe.Ciphertext
				if tmp, err = btp.BootstrapMany(cts[i<<1 : (i+1)<<1]); err != nil {
					return
				}
				cts[(i<<1)+0] = tmp[0]
				cts[(i<<1)+1] = tmp[1]
			} else {
				var tmp *rlwe.Ciphertext
				if tmp, err = btp.Bootstrap(&cts[i<<1]); err != nil {
					return
				}
				cts[i<<1] = *tmp
			}
			return
		})
	}

	if err = m.Wait(); err != nil {
		return nil, err
	}

	since := time.Since(now)

	if btp.Debug {
		after := make([][]float64, len(cts))
		Max := []float64{}
		for i := range cts {
			after[i] = make([]float64, cts[i].Slots())
			ecd.Decode(dec.DecryptNew(&cts[i]), after[i])
			Max = append(Max, slices.Max(after[i]), slices.Min(after[i]))
		}

		var maxerr float64
		for i := range cts {
			for j := range cts[i].Slots() {
				maxerr = max(math.Abs(before[i][j] - after[i][j]))
			}
		}

		fmt.Printf("%v - err: %20.17f - time:%s\n", Max, -math.Log2(maxerr), since)

		//fmt.Println(hefloat.GetPrecisionStats(btp.Parameters, ecd, nil, before[0], after[0], 30, false))
	} else {
		fmt.Printf("time: %s\n", since)
	}

	return cts, err
}

func (btp *Bootstrapper) Depth() int {
	return btp.Bootstrappers[0].Depth()
}

func (btp *Bootstrapper) MinimumInputLevel() int {
	return btp.Bootstrappers[0].MinimumInputLevel()
}

func (btp *Bootstrapper) OutputLevel() int {
	return btp.Bootstrappers[0].OutputLevel()
}
