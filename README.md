# cryptolib

A common cryptographical library in Golang.

## Feature

* Ed25519 signing / verifying algorithm.

## Usage

Get package:
```
go get github.com/ewangplay/cryptolib
```

A sample:
```
package main

import (
	"fmt"
	"os"

	ch "github.com/ewangplay/cryptolib"
)

func main() {
	cfg := &ch.Config{
		ProviderName: "SW",
	}
	csp, err := ch.GetCSP(cfg)
	if err != nil {
		fmt.Printf("Get default CSP failed: %v\n", err)
		os.Exit(1)
	}

	k, err := csp.KeyGen(&ch.ED25519KeyGenOpts{})
	if err != nil {
		fmt.Printf("KeyGen failed: %v\n", err)
		os.Exit(1)
	}

	digest := []byte("hello,world")
	signature, err := csp.Sign(k, digest)
	if err != nil {
		fmt.Printf("Sign failed: %v\n", err)
		os.Exit(1)
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		fmt.Printf("Get public key failed: %v\n", err)
		os.Exit(1)
	}

	valid, err := csp.Verify(pubKey, digest, signature)
	if err != nil {
		fmt.Printf("Verify failed: %v\n", err)
		os.Exit(1)
	}
	if !valid {
		fmt.Println("The signature should be validated.")
		os.Exit(1)
	}

	fmt.Println("The signature is validated successfully.")
}
```