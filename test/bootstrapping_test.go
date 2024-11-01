package qkv

import (
	"fmt"
	"testing"
	"time"
	"app/lib"
	"app/client"
	"app/server"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

func TestBootstrapping(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, lib.LevelBootstrapping)

	if tot := lib.NbMatPerCtIn * lib.Split * (lib.Rows * (lib.Cols/lib.Split + lib.Padding)); tot > params.MaxSlots() {
		panic(fmt.Errorf("invalid parameters: %d slots < split * #padded matrices = %d", params.MaxSlots(), tot))
	}

	ecd := hefloat.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	btp := lib.NewBootstrapper(params, sk)
	btp.Debug = true

	c := client.NewClient(params, sk)
	s := server.NewServer("../weights", lib.NumCPU)

	data, _, err := c.Load("../data/example_AA_sequences.list", lib.SamplesStart, lib.SamplesEnd)
	require.NoError(t, err)

	outPlain := s.UpToCombine(data)

	var outEnc []rlwe.Ciphertext
	outEnc, err = c.EncryptNew(outPlain, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	now := time.Now()
	outEnc, err = btp.BootstrapMany(outEnc)
	require.NoError(t, err)
	fmt.Printf("Done: %s\n", time.Since(now))

	outHave, err := c.DecryptNew(outEnc, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)
	for i := range outPlain {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, outPlain[i].RawMatrix().Data, outHave[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}
}
