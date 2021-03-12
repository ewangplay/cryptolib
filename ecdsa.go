package cryptolib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

const ecdsaV1 = 1

// EcdsaPublicKey represents the ecdsa public key
type EcdsaPublicKey struct {
	PubKey []byte
}

// Version returns the version of this key
func (k *EcdsaPublicKey) Version() int {
	return ecdsaV1
}

// Type returns the type of this key
func (k *EcdsaPublicKey) Type() string {
	return ECDSA
}

// Bytes converts this key to its byte representation.
func (k *EcdsaPublicKey) Bytes() ([]byte, error) {
	return k.PubKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *EcdsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *EcdsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *EcdsaPublicKey) PublicKey() (Key, error) {
	return k, nil
}

// EcdsaPrivateKey represents the ecdsa private key
type EcdsaPrivateKey struct {
	PrivKey []byte
}

// Version returns the version of this key
func (k *EcdsaPrivateKey) Version() int {
	return ecdsaV1
}

// Type returns the type of this key
func (k *EcdsaPrivateKey) Type() string {
	return ECDSA
}

// Bytes converts this key to its byte representation.
func (k *EcdsaPrivateKey) Bytes() ([]byte, error) {
	return k.PrivKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *EcdsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *EcdsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *EcdsaPrivateKey) PublicKey() (Key, error) {
	ecdsaPriKey, err := x509.ParseECPrivateKey(k.PrivKey)
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &EcdsaPublicKey{pubKeyBytes}, nil
}

type ecdsaKeyGenerator struct{}

// GenKey generates a key of ecdsa algorithm
func (kg *ecdsaKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	curve := elliptic.P256()
	if opts != nil {
		if opts.Algorithm() != ECDSA {
			return nil, fmt.Errorf("KeyGenOpts type invalid")
		}
		eccKeyGenOpts, ok := opts.(*ECDSAKeyGenOpts)
		if !ok {
			return nil, fmt.Errorf("KeyGenOpts type invalid")
		}
		if eccKeyGenOpts.Curve != nil {
			curve = eccKeyGenOpts.Curve
		}
	}

	priKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ECDSA key: %v", err)
	}
	priKeyBytes, err := x509.MarshalECPrivateKey(priKey)
	if err != nil {
		return nil, fmt.Errorf("failed generating ECDSA key: %v", err)
	}
	return &EcdsaPrivateKey{
		PrivKey: priKeyBytes,
	}, nil
}

type ecdsaSigner struct{}

// Sign signs digest using key k
func (ed *ecdsaSigner) Sign(k Key, digest []byte) (signature []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("ECDSA signing error: %v", e)
		}
	}()

	priKeyBytes, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	ecdsaPriKey, err := x509.ParseECPrivateKey(priKeyBytes)
	if err != nil {
		return nil, err
	}
	signature, err = ecdsa.SignASN1(rand.Reader, ecdsaPriKey, digest)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type ecdsaVerifier struct{}

// Verify verifies signature against key k and digest
func (ed *ecdsaVerifier) Verify(k Key, digest, signature []byte) (valid bool, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("ECDSA verifying signature error: %v", e)
		}
	}()

	pubKeyBytes, err := k.Bytes()
	if err != nil {
		return false, err
	}
	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}
	ecdsaPubKey := pubInterface.(*ecdsa.PublicKey)

	valid = ecdsa.VerifyASN1(ecdsaPubKey, digest, signature)
	return valid, nil
}
