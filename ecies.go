package cryptolib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type eciesEncrypter struct{}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (ec *eciesEncrypter) Encrypt(k Key, plaintext []byte, opts EnciphermentOpts) (ciphertext []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("ECIES encrypting error: %v", e)
		}
	}()

	pubKeyBytes, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey := pubInterface.(*ecdsa.PublicKey)

	eciesPubKey := ecies.ImportECDSAPublic(ecdsaPubKey)
	ciphertext, err = ecies.Encrypt(rand.Reader, eciesPubKey, plaintext, nil, nil)

	return
}

type eciesDecrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (ec *eciesDecrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("ECIES decrypting error: %v", e)
		}
	}()

	priKeyBytes, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	ecPriKey, err := x509.ParseECPrivateKey(priKeyBytes)
	if err != nil {
		return nil, err
	}

	eciesPriKey := ecies.ImportECDSA(ecPriKey)
	plaintext, err = eciesPriKey.Decrypt(ciphertext, nil, nil)

	return
}
