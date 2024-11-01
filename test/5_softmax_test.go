package qkv

import (
	"fmt"
	"testing"
	"time"

	//"slices"

	"app/client"
	"app/lib"
	"app/server"
	"app/utils"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

func TestSoftMax(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, lib.LevelBootstrapping)

	if tot := lib.NbMatPerCtIn * lib.Split * (lib.Rows * (lib.Cols/lib.Split + lib.Padding)); tot > params.MaxSlots() {
		panic(fmt.Errorf("invalid parameters: %d slots < split * #padded matrices = %d", params.MaxSlots(), tot))
	}

	ecd := hefloat.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	//btp := lib.NewDummyBootstrapper(params, sk)
	btp := lib.NewBootstrapper(params, sk)
	btp.Debug = true

	now := time.Now()
	fmt.Printf("Server: ")
	s := server.NewServer("../weights", lib.NumCPU)
	fmt.Printf("%s\n", time.Since(now))

	galEls := s.SoftMaxGaloisElements(params)

	t.Logf("GaloisElements: %d\n", len(galEls))

	fmt.Printf("Client: ")
	now = time.Now()
	c := client.NewClient(params, sk)
	fmt.Printf("%s\n", time.Since(now))

	fmt.Printf("Kgen: ")
	now = time.Now()
	evk := c.GetKeyManager(len(galEls), sk)
	s.SetKeyManager(evk)
	fmt.Printf("%s\n", time.Since(now))

	data, _, err := c.Load("../data/example_AA_sequences.list", lib.SamplesStart, lib.SamplesEnd)

	//data, err := c.LoadFuzzy(lib.SamplesEnd - lib.SamplesStart)
	require.NoError(t, err)

	QMulKTPlain, _ := s.UpToQMulKT(data)

	var QMulKTEnc []rlwe.Ciphertext

	fmt.Println(QMulKTPlain[0][0].RawMatrix().Data[:8])

	QMulKTEnc, err = c.EncryptNew(utils.Flatten(QMulKTPlain), 0, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)

	SoftMaxPlain := QMulKTPlain
	s.SoftMaxApproximate(SoftMaxPlain)
	fmt.Println(SoftMaxPlain[0][0].RawMatrix().Data[:8])

	require.NoError(t, s.SoftMaxEncrypted(QMulKTEnc, btp))
	_ = ecd
	SoftMaxHave, err := c.DecryptNew(QMulKTEnc, lib.Rows, lib.Rows, 0, lib.NbMatPerCtIn*lib.Split)
	require.NoError(t, err)
	for i := range SoftMaxPlain {
		for j := range SoftMaxPlain[i] {

			/*
				if i == 0 && j == 0 {
					for k := range SoftMaxPlain[i][j].RawMatrix().Data {
						if k != 0 && k%lib.Rows == 0 {
							fmt.Println()
						}
						fmt.Printf("%4d %15.10f %15.10f\n", k, SoftMaxPlain[i][j].RawMatrix().Data[k], SoftMaxHave[i*lib.Split+j].RawMatrix().Data[k])
					}
				}
			*/

			stats := hefloat.GetPrecisionStats(params, ecd, nil, SoftMaxPlain[i][j].RawMatrix().Data, SoftMaxHave[i*lib.Split+j].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	}
}
