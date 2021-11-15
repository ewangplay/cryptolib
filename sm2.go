package cryptolib

import (
	"crypto/rand"
	"fmt"

	"github.com/tjfoc/gmsm/pkcs12"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
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
	return x509.MarshalSm2PublicKey(k.PubKey)
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
	return pkcs12.MarshalECPrivateKey(k.PrivKey)
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

type sm2Signer struct{}

// Sign signs digest using key k
func (sm *sm2Signer) Sign(k Key, digest []byte, opts SignatureOpts) (signature []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("SM2 signing error: %v", e)
		}
	}()

	priKeyBytes, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	sm2PriKey, err := x509.ParseSm2PrivateKey(priKeyBytes)
	if err != nil {
		return nil, err
	}

	r, s, err := sm2.Sm2Sign(sm2PriKey, digest, nil, rand.Reader)
	if err != nil {
		return nil, err
	}
	signature, err = sm2.SignDigitToSignData(r, s)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type sm2Verifier struct{}

// Verify verifies signature against key k and digest
func (sm *sm2Verifier) Verify(k Key, digest, signature []byte, opts SignatureOpts) (valid bool, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("SM2 verifying signature error: %v", e)
		}
	}()

	pubKeyBytes, err := k.Bytes()
	if err != nil {
		return false, err
	}
	sm2PubKey, err := x509.ParseSm2PublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	r, s, err := sm2.SignDataToSignDigit(signature)
	if err != nil {
		return false, err
	}
	valid = sm2.Sm2Verify(sm2PubKey, digest, nil, r, s)
	return valid, nil
}
