package cryptolib

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
)

// sm2PublicKey represents the sm2 public key
type sm2PublicKey struct {
	PubKey *sm2.PublicKey
}

// Type returns the type of this key
func (k *sm2PublicKey) Type() string {
	return SM2
}

// Bytes converts this key to its byte representation.
func (k *sm2PublicKey) Bytes() ([]byte, error) {
	return json.Marshal(k.PubKey)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *sm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PublicKey) PublicKey() (Key, error) {
	return k, nil
}

// sm2PrivateKey represents the sm2 private key
type sm2PrivateKey struct {
	PrivKey *sm2.PrivateKey
}

// Type returns the type of this key
func (k *sm2PrivateKey) Type() string {
	return SM2
}

// Bytes converts this key to its byte representation.
func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return json.Marshal(k.PrivKey)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PrivateKey) PublicKey() (Key, error) {

	return &sm2PublicKey{&k.PrivKey.PublicKey}, nil
}

type sm2KeyGenerator struct{}

// GenKey generates a key of sm2 algorithm
func (kg *sm2KeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	priKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating SM2 key: %v", err)
	}
	return &sm2PrivateKey{
		PrivKey: priKey,
	}, nil
}
