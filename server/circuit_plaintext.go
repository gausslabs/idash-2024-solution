package server

import (
	"fmt"

	"gonum.org/v1/gonum/mat"
)

func (s *Server) RunApproximate(in []*mat.Dense) (out []*mat.Dense) {
	out = s.EmbedApproximate(in)
	s.PositionalEncodingApproximate(out, out)
	Q, K, V := s.QKVApproximate(out)
	QSplit, KSplit, VSplit := s.SplitHeadsApproximate(Q, K, V)
	QKTSplit := s.QMulKTApproximate(QSplit, KSplit)

	if s.Debug {
		statsIn, statsExp, statsNorm := s.SoftMaxApproximate(QKTSplit)
		fmt.Println("SOFTMAX INPUT")
		statsIn.Print()
		fmt.Println("SOFTMAX EXP")
		statsExp.Print()
		fmt.Println("SOFTMAX Norm")
		statsNorm.Print()
	} else {
		s.SoftMaxApproximate(QKTSplit)
	}

	QKTVSplit := s.QKTMulVApproximate(QKTSplit, VSplit)
	QKTV := s.MergeHeadsApproximate(QKTVSplit)
	s.CombineApproximate(out, QKTV)
	s.Norm1Approximate(out)
	s.FNNApproximate(out)
	s.Norm2Approximate(out)
	out = s.PoolingApproximate(out)
	return s.ClassifierApproximate(out)
}

func (s *Server) RunExact(in []*mat.Dense) (out []*mat.Dense) {
	out = s.EmbedExact(in)
	s.PositionalEncodingExact(out, out)
	Q, K, V := s.QKVExact(out)
	QSplit, KSplit, VSplit := s.SplitHeadsExact(Q, K, V)
	QKTSplit := s.QMulKTExact(QSplit, KSplit)
	s.SoftMaxExact(QKTSplit)
	QKTVSplit := s.QKTMulVExact(QKTSplit, VSplit)
	QKTV := s.MergeHeadsExact(QKTVSplit)
	s.CombineExact(out, QKTV)
	s.Norm1Exact(out)
	s.FNNExact(out)
	s.Norm2Exact(out)
	out = s.PoolingExact(out)
	return s.ClassifierExact(out)
}

func (s *Server) UpToEmbed(in []*mat.Dense) (out []*mat.Dense) {
	return s.EmbedApproximate(in)
}

func (s *Server) UpToPositionalEncoding(in []*mat.Dense) (out []*mat.Dense) {
	out = s.UpToEmbed(in)
	s.PositionalEncodingApproximate(out, out)
	return
}

func (s *Server) UpToQKV(in []*mat.Dense) (Q, K, V []*mat.Dense) {
	out := s.UpToPositionalEncoding(in)
	Q, K, V = s.QKVApproximate(out)
	return
}

func (s *Server) UpToSplitHeads(in []*mat.Dense) (QSplit, KSplit, VSplit [][]*mat.Dense) {
	Q, K, V := s.UpToQKV(in)
	QSplit, KSplit, VSplit = s.SplitHeadsApproximate(Q, K, V)
	return
}

func (s *Server) UpToQMulKT(in []*mat.Dense) (QMulKT, VSplit [][]*mat.Dense) {
	QSplit, KSplit, VSplit := s.UpToSplitHeads(in)
	return s.QMulKTApproximate(QSplit, KSplit), VSplit
}

func (s *Server) UpToSoftMax(in []*mat.Dense) (QMulKT, VSplit [][]*mat.Dense) {
	QMulKT, VSplit = s.UpToQMulKT(in)
	s.SoftMaxApproximate(QMulKT)
	return
}

func (s *Server) UpToQMulKTMulV(in []*mat.Dense) (QMulKTMulV [][]*mat.Dense) {
	QMulKT, VSplit := s.UpToSoftMax(in)
	return s.QKTMulVApproximate(QMulKT, VSplit)
}

func (s *Server) UptToMergeHeads(in []*mat.Dense) (out, heads []*mat.Dense) {
	out = s.EmbedApproximate(in)
	s.PositionalEncodingApproximate(out, out)
	Q, K, V := s.QKVApproximate(out)
	QSplit, KSplit, VSplit := s.SplitHeadsApproximate(Q, K, V)
	QSplit = s.QMulKTApproximate(QSplit, KSplit)
	s.SoftMaxApproximate(QSplit)
	return out, s.MergeHeadsApproximate(s.QKTMulVApproximate(QSplit, VSplit))
}

func (s *Server) UpToCombine(in []*mat.Dense) (out []*mat.Dense) {
	var heads []*mat.Dense
	out, heads = s.UptToMergeHeads(in)
	s.CombineApproximate(out, heads)
	return
}

func (s *Server) UpToNorm1(in []*mat.Dense) (out []*mat.Dense) {
	out = s.UpToCombine(in)
	s.Norm1Approximate(out)
	return
}

func (s *Server) UpToFNN(in []*mat.Dense) (out []*mat.Dense) {
	out = s.UpToNorm1(in)
	s.FNNApproximate(out)
	return
}

func (s *Server) UpToNorm2(in []*mat.Dense) (out []*mat.Dense) {
	out = s.UpToFNN(in)
	s.Norm2Approximate(out)
	return
}

func (s *Server) UpToPooling(in []*mat.Dense) (out []*mat.Dense) {
	return s.PoolingApproximate(s.UpToNorm2(in))
}
