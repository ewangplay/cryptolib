package cryptolib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

const (
	rsaV1          = 1
	rsaDefaultBits = 2048
)

// RsaPublicKey represents the rsa public key
type RsaPublicKey struct {
	PubKey []byte
}

// Version returns the version of this key
func (k *RsaPublicKey) Version() int {
	return rsaV1
}

// Type returns the type of this key
func (k *RsaPublicKey) Type() string {
	return RSA
}

// Bytes converts this key to its byte representation.
func (k *RsaPublicKey) Bytes() ([]byte, error) {
	return k.PubKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *RsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *RsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *RsaPublicKey) PublicKey() (Key, error) {
	return k, nil
}

// RsaPrivateKey represents the rsa private key
type RsaPrivateKey struct {
	PrivKey []byte
}

// Version returns the version of this key
func (k *RsaPrivateKey) Version() int {
	return rsaV1
}

// Type returns the type of this key
func (k *RsaPrivateKey) Type() string {
	return RSA
}

// Bytes converts this key to its byte representation.
func (k *RsaPrivateKey) Bytes() ([]byte, error) {
	return k.PrivKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *RsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *RsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *RsaPrivateKey) PublicKey() (Key, error) {
	rsaPriKey, err := x509.ParsePKCS1PrivateKey(k.PrivKey)
	if err != nil {
		return nil, err
	}
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&rsaPriKey.PublicKey)
	return &RsaPublicKey{pubKeyBytes}, nil
}

type rsaKeyGenerator struct{}

// GenKey generates a key of rsa algorithm
func (kg *rsaKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	bits := rsaDefaultBits
	keyGenOpts := opts.(*RSAKeyGenOpts)
	if keyGenOpts.Bits > 0 {
		bits = keyGenOpts.Bits
	}

	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed generating RSA key: %v", err)
	}
	priKeyBytes := x509.MarshalPKCS1PrivateKey(priKey)
	return &RsaPrivateKey{
		PrivKey: priKeyBytes,
	}, nil
}

type rsaSigner struct{}

// Sign signs digest using key k
func (rs *rsaSigner) Sign(k Key, digest []byte, opts SignOpts) (signature []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("RSA signing error: %v", e)
		}
	}()

	priKeyBytes, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	rsaPriKey, err := x509.ParsePKCS1PrivateKey(priKeyBytes)
	if err != nil {
		return nil, err
	}

	// Default schema is PSS
	schema := PSS
	// Default hash function is SHA256
	hash := crypto.SHA256
	if opts != nil {
		if opts.Algorithm() != RSA {
			return nil, fmt.Errorf("SignOpts type invalid: %v", opts)
		}

		signOpts, ok := opts.(*RSASignOpts)
		if !ok {
			return nil, fmt.Errorf("SignOpts type invalid: %v", opts)
		}

		// If opts.Schema is set, it overrides schema.
		if signOpts.Schema != "" {
			schema = signOpts.Schema
		}
		// If opts.Hash is set, it orverrides hash.
		if signOpts.Hash > 0 {
			hash = signOpts.Hash
		}

		if schema == PSS {
			signature, err = rsa.SignPSS(rand.Reader, rsaPriKey, hash, digest, nil)
			if err != nil {
				return nil, err
			}
		} else if schema == PKCS1V15 {
			signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPriKey, hash, digest)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("unsupported RSA signature schema")
		}
	} else {
		signature, err = rsa.SignPSS(rand.Reader, rsaPriKey, hash, digest, nil)
		if err != nil {
			return nil, err
		}
	}

	return signature, nil
}

type rsaVerifier struct{}

// Verify verifies signature against key k and digest
func (rs *rsaVerifier) Verify(k Key, digest, signature []byte, opts VerifyOpts) (valid bool, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("RSA verifying signature error: %v", e)
		}
	}()

	pubKeyBytes, err := k.Bytes()
	if err != nil {
		return false, err
	}
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	// Default schema is PSS
	schema := PSS
	// Sefault hash function is SHA256
	hash := crypto.SHA256
	if opts != nil {
		if opts.Algorithm() != RSA {
			return false, fmt.Errorf("VerifyOpts type invalid: %v", opts)
		}
		verifyOpts, ok := opts.(*RSAVerifyOpts)
		if !ok {
			return false, fmt.Errorf("VerifyOpts type invalid: %v", opts)
		}

		// If opts.Schema is set, it overrides schema.
		if verifyOpts.Schema != "" {
			schema = verifyOpts.Schema
		}
		// If opts.Hash is set, it orverrides hash.
		if verifyOpts.Hash > 0 {
			hash = verifyOpts.Hash
		}

		if schema == PSS {
			err = rsa.VerifyPSS(pubKey, hash, digest, signature, nil)
			if err == nil {
				valid = true
			}
		} else if schema == PKCS1V15 {
			err = rsa.VerifyPKCS1v15(pubKey, hash, digest, signature)
			if err == nil {
				valid = true
			}
		} else {
			return false, fmt.Errorf("unsupported RSA signature schema")
		}
	} else {
		err = rsa.VerifyPSS(pubKey, hash, digest, signature, nil)
		if err == nil {
			valid = true
		}
	}

	return valid, nil
}
