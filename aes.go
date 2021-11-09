package cryptolib

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	aesV1            = 1
	aesKeyDefaultLen = 16
)

type aesPrivateKey struct {
	privKey []byte
}

// Version returns the version of this key
func (k *aesPrivateKey) Version() int {
	return aesV1
}

// Type returns the type of this key
func (k *aesPrivateKey) Type() string {
	return AES
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *aesPrivateKey) Bytes() (raw []byte, err error) {
	return k.privKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *aesPrivateKey) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *aesPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *aesPrivateKey) PublicKey() (Key, error) {
	return nil, errors.New("Oh~, I'm a symmetric key.")
}

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len <= 0 {
		return nil, errors.New("len must be larger than 0")
	}

	buf := make([]byte, len)
	n, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buf, nil
}

type aesKeyGenerator struct{}

// GenKey generates a key of aes algorithm
func (kg *aesKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	len := aesKeyDefaultLen
	keyGenOpts := opts.(*AESKeyGenOpts)
	if keyGenOpts.Len > 0 {
		len = keyGenOpts.Len
	}

	key, err := GetRandomBytes(len)
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", len, err)
	}

	return &aesPrivateKey{key}, nil
}

type aesEncrypter struct{}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesEncrypter) Encrypt(k Key, plaintext []byte, opts EnciphermentOpts) (ciphertext []byte, err error) {
	return
}

type aesDecrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesDecrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	return
}
