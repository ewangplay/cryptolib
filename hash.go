package cryptolib

import (
	"hash"
)

type hasher struct {
	hash func() hash.Hash
}

func (c *hasher) Hash(msg []byte, opts HashOpts) ([]byte, error) {
	h := c.hash()
	h.Write(msg)
	return h.Sum(nil), nil
}
