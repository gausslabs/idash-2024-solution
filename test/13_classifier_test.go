package qkv

import (
	"fmt"
	"testing"
	"time"

	"app/client"
	"app/lib"
	"app/server"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

func TestClassifier(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, 12)

	if tot := lib.NbMatPerCtIn * lib.Split * (lib.Rows * (lib.Cols/lib.Split + lib.Padding)); tot > params.MaxSlots() {
		panic(fmt.Errorf("invalid parameters: %d slots < split * #padded matrices = %d", params.MaxSlots(), tot))
	}

	ecd := hefloat.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	now := time.Now()
	fmt.Printf("Server: ")
	s := server.NewServer("../weights", lib.NumCPU)
	fmt.Printf("%s\n", time.Since(now))

	galEls := append(s.PoolingGaloisElements(params), s.ClassifierGaloisElements(params)...)

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
	require.NoError(t, err)

	outPlain := s.UpToNorm2(data)

	fmt.Println(outPlain[0].RawMatrix().Data[:4])

	var outEnc []rlwe.Ciphertext
	outEnc, err = c.EncryptNew(outPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	outPlain = s.PoolingApproximate(outPlain)
	outPlain = s.ClassifierApproximate(outPlain)

	outEnc, err = s.PoolingEncrypted(outEnc)
	require.NoError(t, err)
	require.NoError(t, s.ClassifierEncrypted(outEnc))

	outHave, err := c.DecryptNew(outEnc, 1, lib.Classes, lib.Cols-lib.Classes, lib.NbMatPerCtIn*lib.Rows)
	require.NoError(t, err)

	outHave = client.GetResults(outHave)

	for i := range outPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, outPlain[i].RawMatrix().Data, outHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}
}
