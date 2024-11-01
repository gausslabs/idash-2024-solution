package bootstrapping

import (
	"fmt"
	"testing"
	"time"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"

	"github.com/stretchr/testify/require"
)

func TestBootstrapping(t *testing.T) {

	params := lib.NewParametersAtLevel(12)

	if tot := lib.NbMatPerCtIn * lib.Split * (lib.Rows * (lib.Cols/lib.Split + lib.Padding)); tot > params.MaxSlots() {
		panic(fmt.Errorf("invalid parameters: %d slots < split * #padded matrices = %d", params.MaxSlots(), tot))
	}

	ecd := hefloat.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)
	btp := NewBootstrapper(sk)

	/*
		c := client.NewClient(params, sk)
		s := server.NewServer()

		data, err := c.LoadData("../data/data.txt")
		require.NoError(t, err)

		// Where to bootstrap
		outPlain := s.UpToEmbed(data[:lib.NbSamples])
	*/

	r := sampling.NewSource([32]byte{})

	values := make([]float64, params.MaxSlots())
	for i := range values {
		values[i] = r.Float64(-1, 1)
	}

	pt := hefloat.NewPlaintext(params, 0)
	require.NoError(t, ecd.Encode(values, pt))
	ct := hefloat.NewCiphertext(params, 1, pt.Level())
	require.NoError(t, enc.Encrypt(pt, ct))

	/*
		var outEnc []rlwe.Ciphertext
		outEnc, err = c.EncryptNew(outPlain, 0, lib.NbMatPerCtIn)
		require.NoError(t, err)
	*/

	//outEnc, err = btp.BootstrapMany(outEnc)
	var err error
	now := time.Now()
	ct, err = btp.Bootstrap(ct)
	require.NoError(t, err)
	fmt.Printf("Done: %s\n", time.Since(now))

	//outHave, err := c.DecryptNew(outEnc, 1, lib.Classes, lib.Cols-lib.Classes, min(lib.NbSamples, lib.NbMatPerCtIn*lib.Rows))
	//require.NoError(t, err)

	have := make([]float64, params.MaxSlots())
	require.NoError(t, ecd.Decode(dec.DecryptNew(ct), have))

	/*
		for i := range outPlain {
			stats := hefloat.GetPrecisionStats(params, ecd, nil, outPlain[i].RawMatrix().Data, outHave[i].RawMatrix().Data, 0, true)
			fmt.Println(stats)
		}
	*/

	stats := hefloat.GetPrecisionStats(params, ecd, nil, values, have, 0, true)
	fmt.Println(stats)
}
