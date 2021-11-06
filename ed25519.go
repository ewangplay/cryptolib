package cryptolib

import (
	"crypto/ed25519"
	"fmt"
)

const ed25519V1 = 1

// Ed25519PublicKey represents the ed25519 public key
type Ed25519PublicKey struct {
	PubKey ed25519.PublicKey
}

// Version returns the version of this key
func (k *Ed25519PublicKey) Version() int {
	return ed25519V1
}

// Type returns the type of this key
func (k *Ed25519PublicKey) Type() string {
	return ED25519
}

// Bytes converts this key to its byte representation.
func (k *Ed25519PublicKey) Bytes() ([]byte, error) {
	return k.PubKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *Ed25519PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *Ed25519PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *Ed25519PublicKey) PublicKey() (Key, error) {
	return k, nil
}

// Ed25519PrivateKey represents the ed25519 private key
type Ed25519PrivateKey struct {
	PrivKey ed25519.PrivateKey
}

// Version returns the version of this key
func (k *Ed25519PrivateKey) Version() int {
	return ed25519V1
}

// Type returns the type of this key
func (k *Ed25519PrivateKey) Type() string {
	return ED25519
}

// Bytes converts this key to its byte representation.
func (k *Ed25519PrivateKey) Bytes() ([]byte, error) {
	return k.PrivKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *Ed25519PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *Ed25519PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *Ed25519PrivateKey) PublicKey() (Key, error) {
	pubKey, ok := k.PrivKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key type mismatch")
	}
	return &Ed25519PublicKey{pubKey}, nil
}

type ed25519KeyGenerator struct{}

// GenKey generates a key of ed25519 algorithm
func (kg *ed25519KeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	_, priKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed generating ED25519 key: %v", err)
	}
	return &Ed25519PrivateKey{
		PrivKey: priKey,
	}, nil
}

type ed25519Signer struct{}

// Sign signs digest using key k
func (ed *ed25519Signer) Sign(k Key, digest []byte, opts SignatureOpts) (signature []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("ED25519 signing error: %v", e)
		}
	}()

	priKeyBytes, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(ed25519.PrivateKey(priKeyBytes), digest), nil
}

type ed25519Verifier struct{}

// Verify verifies signature against key k and digest
func (ed *ed25519Verifier) Verify(k Key, digest, signature []byte, opts SignatureOpts) (valid bool, err error) {
	pubKeyBytes, err := k.Bytes()
	if err != nil {
		return false, err
	}
	valid = ed25519.Verify(ed25519.PublicKey(pubKeyBytes), digest, signature)
	return valid, nil
}
