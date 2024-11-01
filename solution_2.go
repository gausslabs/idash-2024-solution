package main

import (
	"flag"
	"fmt"
	"time"

	"app/bootstrapping"
	"app/client"
	"app/lib"
	"app/matrix/normalization"
	"app/matrix/relu"
	"app/matrix/softmax"
	"app/matrix/softmax/innermax"
	"app/server"
	"app/utils"

	"github.com/Pro7ech/lattigo/rlwe"
)

var input_path = flag.String("i", "./data/example_AA_sequences.list", "input path")
var debug = flag.Bool("debug", false, "debug mode")
var dummy = flag.Bool("dummy", false, "uses dummy bootstrapping")
var verify = flag.Bool("verify", false, "verifies predictions against plaintext model")

func main() {

	lib.SamplesStart = 0
	lib.SamplesEnd = 100
	lib.SoftMaxParameters = SoftMaxParameters
	lib.Norm1Parameters = Norm1Parameters
	lib.Norm2Parameters = Norm2Parameters
	lib.ReLUParameters = ReLUParameters

	flag.Parse()

	now := time.Now()

	params := lib.NewParameters()

	fmt.Printf("Residual Parameters: logN=%d, logSlots=%d, H=%d, sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		params.LogN(),
		params.LogMaxSlots(),
		params.XsHammingWeight(),
		params.Xe(), params.LogQP(),
		params.MaxLevel(),
		params.LogDefaultScale())

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	c := client.NewClient(params, sk)

	data, _, err := c.Load(*input_path, lib.SamplesStart, lib.SamplesEnd)
	//data, err := c.LoadFuzzy(lib.SamplesEnd - lib.SamplesStart)
	if err != nil {
		panic(err)
	}

	var btp *bootstrapping.Bootstrapper

	if *dummy {
		btp = lib.NewDummyBootstrapper(params, sk)
	} else {
		btp = lib.NewBootstrapper(params, sk)

		paramsBTP := btp.BootstrappingParameters()

		fmt.Printf("Bootstrapping Parameters: logN=%d, logSlots=%d, H(%d; %d), sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
			paramsBTP.BootstrappingParameters.LogN(),
			paramsBTP.BootstrappingParameters.LogMaxSlots(),
			paramsBTP.BootstrappingParameters.XsHammingWeight(),
			paramsBTP.EphemeralSecretWeight,
			paramsBTP.BootstrappingParameters.Xe(),
			paramsBTP.BootstrappingParameters.LogQP(),
			paramsBTP.BootstrappingParameters.QCount(),
			paramsBTP.BootstrappingParameters.LogDefaultScale())
	}

	btp.Debug = *debug

	s := server.NewServer("./weights", lib.NumCPU)

	if *debug {
		s.Sk = sk
	}

	km := c.GetKeyManager(lib.MaxConcurrentGaloisKeys, sk)

	s.SetKeyManager(km)

	ct, err := c.EncryptNew(data, 0, lib.NbMatPerCtIn)
	if err != nil {
		panic(err)
	}

	if ct, err = s.RunEncrypted(ct, btp); err != nil {
		panic(err)
	}

	result, err := c.DecryptNew(ct, 1, lib.Classes, lib.Cols-lib.Classes, lib.Rows*lib.NbMatPerCtIn)

	result = client.GetResults(result)

	if err = c.Dump("./result/pred_enc.csv", result); err != nil {
		panic(err)
	}

	fmt.Printf("Done: %s\n", time.Since(now))

	if *verify {

		pred := s.RunExact(data)

		if err = c.Dump("./result/pred_plain.csv", pred); err != nil {
			panic(err)
		}

		accuracy, noise := utils.Precision(result, pred)

		fmt.Printf("PT vs. CT Accuracy: %f\n", accuracy)
		fmt.Printf("CT AVG Noise: %f\n", noise)
	}

}

/*
======== Samples
SoftMaxApproximate: -14.846192 14.617589
SoftMaxExact: -14.846256 14.616425
======== Fuzzing
SoftMaxApproximate: -25.143211 22.050325
*/
var SoftMaxParameters = softmax.Parameters{
	ExpOffset:   0,
	ExpMin:      -50.0,
	ExpMax:      5.0,
	ExpDeg:      31,
	InvMin:      0.5,
	InvMax:      256,
	InvDeg:      31,
	K:           lib.Rows,
	ToTVecSize:  lib.NbMatPerCtIn * lib.Rows * lib.Rows * lib.Split,
	InvSqrtIter: 2,
	MaxParameters: innermax.Parameters{
		AbsMax: 60,
		CoeffsString: [][]string{
			{"0", "1.27020217932", "0", "-0.41513217792", "0", "0.23969221445", "0", "-0.16067723908", "0", "0.11530467170", "0", "-0.08537291689", "0", "0.06375404757", "0", "-0.10285141221"},
		},
		CoeffsFloat: [][]float64{
			{0, 1.27020217932, 0, -0.41513217792, 0, 0.23969221445, 0, -0.16067723908, 0, 0.11530467170, 0, -0.08537291689, 0, 0.06375404757, 0, -0.10285141221},
		},
	},
}

/*
======== Samples
Norm1Approximate: 15.098900 119.320461
Norm1Exact: 15.096791 119.296482
======== Fuzzing
Norm1Approximate: 15.310283 179.325047
*/
var Norm1Parameters = normalization.Parameters{
	InvSqrtMin:     1,
	InvSqrtMax:     216,
	InvSqrtDeg:     63,
	InvSqrtIter:    1,
	BootstrapAfter: true,
	ToTVecSize:     lib.NbMatPerCtIn * lib.Rows * lib.Cols,
}

/*
======== Samples
Normalize2Approximate: 2.800122 256.607479
Normalize2Exact: 2.798778 256.573511
======== Fuzzing
Normalize2Approximate: 2.554534 270.796120
*/
var Norm2Parameters = normalization.Parameters{
	InvSqrtMin: 1,
	InvSqrtMax: 280,
	InvSqrtDeg: 31,
	ToTVecSize: lib.NbMatPerCtIn * lib.Rows * lib.Cols,
}

// hefloat.GenMinimaxCompositePolynomial(512, 5, 10, []int{127}, bignum.Sign)
var ReLUParameters = relu.Parameters{
	CoeffsFloat: [][]float64{
		{0, 1.272129035899513, 0, -0.421091879255116, 0, 0.249146260085848, 0, -0.174259510661971, 0, 0.131777951391126, 0, -0.104081189870054, 0, 0.084401445655405, 0, -0.069587192942794, 0, 0.057974710905923, 0, -0.048603776548697, 0, 0.040881513298993, 0, -0.034421666471770, 0, 0.028961023059828, 0, -0.024312877767999, 0, 0.020340082936784, 0, -0.016938465046402, 0, 0.014026336178818, 0, -0.011537731080080, 0, 0.009417941026674, 0, -0.007620579730076, 0, 0.006105439236114, 0, -0.004837036299154, 0, 0.003783963601656, 0, -0.002917977991100, 0, 0.002213425327161, 0, -0.001647277156547, 0, 0.001198804963407, 0, -0.000849322063176, 0, 0.000582094452881, 0, -0.000382336269914, 0, 0.000237122355400, 0, -0.000187573707069},
	},
	CoeffsString: [][]string{
		{"0", "1.272129035899513", "0", "-0.421091879255116", "0", "0.249146260085848", "0", "-0.174259510661971", "0", "0.131777951391126", "0", "-0.104081189870054", "0", "0.084401445655405", "0", "-0.069587192942794", "0", "0.057974710905923", "0", "-0.048603776548697", "0", "0.040881513298993", "0", "-0.034421666471770", "0", "0.028961023059828", "0", "-0.024312877767999", "0", "0.020340082936784", "0", "-0.016938465046402", "0", "0.014026336178818", "0", "-0.011537731080080", "0", "0.009417941026674", "0", "-0.007620579730076", "0", "0.006105439236114", "0", "-0.004837036299154", "0", "0.003783963601656", "0", "-0.002917977991100", "0", "0.002213425327161", "0", "-0.001647277156547", "0", "0.001198804963407", "0", "-0.000849322063176", "0", "0.000582094452881", "0", "-0.000382336269914", "0", "0.000237122355400", "0", "-0.000187573707069"},
	},
	AbsMax: 50,
}
