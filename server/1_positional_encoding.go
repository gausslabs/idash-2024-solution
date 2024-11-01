package server

import (
	"app/lib"
	"app/utils"

	"github.com/Pro7ech/lattigo/rlwe"

	"gonum.org/v1/gonum/mat"
)

func (s *Server) PositionalEncodingEncrypted(in, out []rlwe.Ciphertext) (err error) {

	var w *mat.Dense
	if err = utils.LoadWithBench("Load Positional Encoding", func() (err error) {
		w = LoadPositionalEncoding(s.path)
		return
	}); err != nil {
		return
	}

	return utils.RunWithBench("PositionalEncoding(In)  ", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {
		LevelIn = in[0].Level()
		LogScaleIn = in[0].LogScale()
		if err = s.AddPt(in, w, out); err != nil {
			return
		}
		LevelOut = out[0].Level()
		LogScaleOut = out[0].LogScale()
		return
	})
}

func (s *Server) PositionalEncodingApproximate(in, out []*mat.Dense) {
	s.PositionalEncodingExact(in, out)
}

func (s *Server) PositionalEncodingExact(in, out []*mat.Dense) {
	w := LoadPositionalEncoding(s.path)
	for i := range in {
		out[i].Add(in[i], w)
	}
}

func LoadPositionalEncoding(path string) (w *mat.Dense) {
	data, err := utils.ReadFile(path+"/positional_encoding.csv", ',', 0, false, lib.NumCPU)
	if err != nil {
		panic(err)
	}

	return mat.NewDense(lib.Rows, lib.Cols, data[0][:lib.Rows*lib.Cols])
}
