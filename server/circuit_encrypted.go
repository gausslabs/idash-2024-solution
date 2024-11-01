package server

import (
	"fmt"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
)

func (s *Server) RunEncrypted(in []rlwe.Ciphertext, btp he.Bootstrapper[rlwe.Ciphertext]) (out []rlwe.Ciphertext, err error) {

	if out, err = s.EmbedEncrypted(in); err != nil {
		return nil, fmt.Errorf("[Embed]: %w", err)
	}

	if err = s.PositionalEncodingEncrypted(out, out); err != nil {
		return nil, fmt.Errorf("[PositionalEncoding]: %w", err)
	}

	var Q, K, V []rlwe.Ciphertext

	if Q, K, V, err = s.QKVEncrypted(out); err != nil {
		return nil, fmt.Errorf("[QKV]: %w", err)
	}

	if err = s.SplitHeadsEncrypted(Q, K, V); err != nil {
		return nil, fmt.Errorf("[SplitHeads]: %w", err)
	}

	if err = s.QMulKTEncrypted(Q, K, Q); err != nil {
		return nil, fmt.Errorf("[QMulKT]: %w", err)
	}

	if Q, err = btp.BootstrapMany(Q); err != nil {
		return nil, fmt.Errorf("[BootstrapMany]: %w", err)
	}

	if err = s.SoftMaxEncrypted(Q, btp); err != nil {
		return nil, fmt.Errorf("[SoftMax]: %w", err)
	}

	if err = s.QKTMulVEncrypted(Q, V, Q, btp); err != nil {
		return nil, fmt.Errorf("[QKTMulV]: %w", err)
	}

	if err = s.MergeHeadsEncrypted(Q); err != nil {
		return nil, fmt.Errorf("[MergeHeads]: %w", err)
	}

	if err = s.CombineEncrypted(out, Q); err != nil {
		return nil, fmt.Errorf("[Combine]: %w", err)
	}

	if out, err = btp.BootstrapMany(out); err != nil {
		return nil, fmt.Errorf("[BootstrapMany]: %w", err)
	}

	if err = s.Norm1Encrypted(out, btp); err != nil {
		return nil, fmt.Errorf("[Norm1]: %w", err)
	}

	if err = s.FNNEncrypted(out, btp); err != nil {
		return nil, fmt.Errorf("[FNN]: %w", err)
	}

	if out[0].Level() < 3 {
		if out, err = btp.BootstrapMany(out); err != nil {
			return nil, fmt.Errorf("[BootstrapMany]: %w", err)
		}
	}

	if err = s.Norm2Encrypted(out, btp); err != nil {
		return nil, fmt.Errorf("[Norm1]: %w", err)
	}

	if out, err = s.PoolingEncrypted(out); err != nil {
		return nil, fmt.Errorf("[Pooling]: %w", err)
	}

	if out[0].Level() < 1 {
		if out, err = btp.BootstrapMany(out); err != nil {
			return nil, fmt.Errorf("[BootstrapMany]: %w", err)
		}
	}

	if err = s.ClassifierEncrypted(out); err != nil {
		return nil, fmt.Errorf("[Classifier]: %w", err)
	}

	return
}
