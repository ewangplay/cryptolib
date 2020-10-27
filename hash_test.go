package cryptolib

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func ExampleHash() {
	h := &hasher{hash: sha256.New}

	msg := []byte("hello,world")
	digest, err := h.Hash(msg, &SHA256Opts{})
	if err != nil {
		fmt.Printf("Hash failed %v\n", err)
		return
	}

	fmt.Println(hex.EncodeToString(digest))
	// Output:
	// 77df263f49123356d28a4a8715d25bf5b980beeeb503cab46ea61ac9f3320eda
}
