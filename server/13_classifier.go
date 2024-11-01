package server

import (
	"fmt"

	"app/layers"
	"app/lib"
	"app/matrix"
	"app/matrix/softmax"
	"app/utils"
	"app/weights"

	"gonum.org/v1/gonum/mat"

	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) ClassifierEncrypted(in []rlwe.Ciphertext) (err error) {

	if err = utils.LoadWithBench("Load GaloisKeys", func() (err error) {
		s.KeyManager.LoadGaloisKeys(s.ClassifierGaloisElements(s.Evaluator.Evaluators[0].Parameters()))
		s.SetKeys(s.KeyManager)
		return
	}); err != nil {
		return
	}

	var ClassifierWeights *matrix.Plaintext
	var classifierB []float64
	if err = utils.LoadWithBench("Load Classifier", func() (err error) {
		var classifierW *mat.Dense
		classifierW, classifierB = weights.LoadClassifierWeights(s.path)
		classifierWPadded := mat.NewDense(lib.Cols, lib.Cols, make([]float64, lib.Cols*lib.Cols))
		paddingMat := mat.NewDense(lib.Cols, lib.Cols-lib.Classes, make([]float64, lib.Cols*(lib.Cols-lib.Classes)))
		classifierWPadded.Augment(classifierW, paddingMat)
		ClassifierWeights, err = s.EncodeMulNew(classifierWPadded, lib.LevelClassifier)
		return
	}); err != nil {
		return
	}

	if err = utils.RunWithBench("Classifier", func() (LevelIn, LevelOut int, LogScaleIn, LogScaleOut float64, err error) {

		LevelIn = in[0].Level()
		LogScaleIn = in[0].LogScale()

		if err != nil {
			panic(fmt.Errorf("[NewServer][matrix.Encoder][EncodeMulNew][classifierWPadded]: %w", err))
		}

		if err = s.MulPt(in, ClassifierWeights, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[MulPt][in,ClassifierWeights,in]: %w", err)
		}

		if err = s.AddPt(in, weights.GetBias(1, append(classifierB, make([]float64, lib.Cols-lib.Classes)...)), in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[AddPt][in,ClassifierBias,in]: %w", err)
		}

		if err = s.Rescale(in, in); err != nil {
			return LevelIn, LevelOut, LogScaleIn, LogScaleOut, fmt.Errorf("[Rescale][in,in]: %w", err)
		}

		LevelOut = in[0].Level()
		LogScaleOut = in[0].LogScale()

		return

	}); err != nil {
		return
	}

	return
}

func (s *Server) ClassifierApproximate(in []*mat.Dense) (out []*mat.Dense) {
	return s.ClassifierExact(in)
}

func (s *Server) ClassifierExact(in []*mat.Dense) (out []*mat.Dense) {
	weights, bias := weights.LoadClassifierWeights(s.path)
	Dense := layers.NewDense(weights, bias)
	_, cols := Dense.Weights.Dims()
	rows, _ := in[0].Dims()
	out = make([]*mat.Dense, len(in))
	for i := range in {
		out[i] = mat.NewDense(rows, cols, make([]float64, rows*cols))
		Dense.Evaluate(in[i], out[i])
	}
	return
}

func (s *Server) SoftmaxExact(in []*mat.Dense) {
	sf := softmax.NewEvaluator(lib.SoftMaxParameters, nil, nil)
	sf.EvaluateExact(in, in)
}
