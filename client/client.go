package client

import (
	"app/gofhe/he/hefloat"
	"app/gofhe/rlwe"
	"app/keys"
	"app/lib"
)

type Client struct {
	hefloat.Parameters
	*Encryptor
	*Decryptor
}

func NewClient(params hefloat.Parameters, sk *rlwe.SecretKey) *Client {
	return &Client{
		Parameters: params,
		Encryptor:  NewEncryptor(params, sk),
		Decryptor:  NewDecryptor(params, sk),
	}
}

func (c *Client) GetKeyManager(maxconcurrentkeys int, sk *rlwe.SecretKey) (evk *keys.Manager) {
	return keys.NewManager(lib.NumCPU, c.Parameters, maxconcurrentkeys, sk)
}
