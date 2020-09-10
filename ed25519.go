package cryptohub

import (
	"crypto/ed25519"
	"fmt"
)

// Ed25519PublicKey represents the ed25519 public key
type Ed25519PublicKey struct {
	pubKey ed25519.PublicKey
}

// Bytes converts this key to its byte representation.
func (k *Ed25519PublicKey) Bytes() ([]byte, error) {
	return k.pubKey, nil
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
	privKey ed25519.PrivateKey
}

// Bytes converts this key to its byte representation.
func (k *Ed25519PrivateKey) Bytes() ([]byte, error) {
	return k.privKey, nil
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
	pubKey, ok := k.privKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key type mismatch")
	}
	return &Ed25519PublicKey{pubKey}, nil
}

type ed25519KeyGenerator struct {}

// GenKey generates a key of ed25519 algorithm
func (kg *ed25519KeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	_, priKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed generating ED25519 key: %v", err)
	}
	return &Ed25519PrivateKey{
		privKey: priKey,
	}, nil
}

type ed25519Signer struct {}

// Sign signs digest using key k
func (ed *ed25519Signer) Sign(k Key, digest []byte) (signature []byte, err error) {
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

type ed25519Verifier struct {}

// Verify verifies signature against key k and digest
func (ed *ed25519Verifier) Verify(k Key, digest, signature []byte) (valid bool, err error) {
	pubKeyBytes, err := k.Bytes()
	if err != nil {
		return false, err
	}
	valid = ed25519.Verify(ed25519.PublicKey(pubKeyBytes), digest, signature)
	return valid, nil
}