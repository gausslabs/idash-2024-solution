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

func TestCombine(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, 1)

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

	galEls := s.CombineGaloisElements(params)

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

	outPlain, headsPlain := s.UptToMergeHeads(data)

	var outEnc []rlwe.Ciphertext
	outEnc, err = c.EncryptNew(outPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	var headsEnc []rlwe.Ciphertext
	headsEnc, err = c.EncryptNew(headsPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	s.CombineApproximate(outPlain, headsPlain)

	require.NoError(t, s.CombineEncrypted(outEnc, headsEnc))

	outHave, err := c.DecryptNew(outEnc, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)
	for i := range outPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, outPlain[i].RawMatrix().Data, outHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}
}