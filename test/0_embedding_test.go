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

func TestEmbedding(t *testing.T) {

	params := lib.NewParametersCustom(lib.LogN, lib.LevelEncryption)

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

	fmt.Printf("Client: ")
	now = time.Now()
	c := client.NewClient(params, sk)
	fmt.Printf("%s\n", time.Since(now))

	fmt.Printf("Kgen: ")
	now = time.Now()
	evk := c.GetKeyManager(0, sk)
	s.SetKeyManager(evk)
	fmt.Printf("%s\n", time.Since(now))

	data, _, err := c.Load("../data/example_AA_sequences.list", lib.SamplesStart, lib.SamplesEnd)
	require.NoError(t, err)

	in := s.EmbedExact(data)

	var cts []rlwe.Ciphertext
	cts, err = c.EncryptNew(data, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	cts, err = s.EmbedEncrypted(cts)
	require.NoError(t, err)

	have, err := c.DecryptNew(cts, lib.Rows, lib.Cols, 0, lib.NbMatPerCtIn)
	require.NoError(t, err)

	for i := range in {
		stats := hefloat.GetPrecisionStats(params, ecd, nil, in[i].RawMatrix().Data, have[i].RawMatrix().Data, 0, true)
		fmt.Println(stats)
	}
}
