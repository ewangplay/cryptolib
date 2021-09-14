package cryptolib

import (
	"crypto"
	"crypto/elliptic"
)

const (
	// ED25519 signatures are elliptic-curve signatures,
	// carefully engineered at several levels of design
	// and implementation to achieve very high speeds
	// without compromising security.
	ED25519 = "ED25519"

	// ECDSA is the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
	ECDSA = "ECDSA"

	// RSA algorithm family.
	RSA = "RSA"

	// PKCS1V15 is the version 1 of RSA signature algorithm.
	PKCS1V15 = "PKCS1V15"

	// PSS is the version 2 of RSA signature algorithm, the Probabilistic Signature Scheme.
	PSS = "PSS"

	// SHA256 hash algorithm
	SHA256 = "SHA256"

	// SHA384 hash algorithm
	SHA384 = "SHA384"

	// SHA512 hash algorithm
	SHA512 = "SHA512"
)

// ED25519KeyGenOpts contains options for ED25519 key generation.
type ED25519KeyGenOpts struct {
}

// Algorithm returns the key generation algorithm identifier for ED25519.
func (opts *ED25519KeyGenOpts) Algorithm() string {
	return ED25519
}

// ECDSAKeyGenOpts contains options for ECDSA key generation.
type ECDSAKeyGenOpts struct {
	Curve elliptic.Curve
}

// Algorithm returns the key generation algorithm identifier for ECDSA.
func (opts *ECDSAKeyGenOpts) Algorithm() string {
	return ECDSA
}

// RSAKeyGenOpts contains options for RSA key generation.
type RSAKeyGenOpts struct {
	Bits int
}

// Algorithm returns the key generation algorithm identifier for RSA.
func (opts *RSAKeyGenOpts) Algorithm() string {
	return RSA
}

// SHA256Opts contains options relating to SHA-256.
type SHA256Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA256Opts) Algorithm() string {
	return SHA256
}

// SHA384Opts contains options relating to SHA-384.
type SHA384Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA384Opts) Algorithm() string {
	return SHA384
}

// SHA512Opts contains options relating to SHA-512.
type SHA512Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA512Opts) Algorithm() string {
	return SHA512
}

// RSASignOpts contains options relating to PSS signing algorithm.
type RSASignOpts struct {
	Schema string
	Hash   crypto.Hash
}

// Algorithm returns the RSA algorithm identifier (to be used).
func (opts *RSASignOpts) Algorithm() string {
	return RSA
}

// RSAVerifyOpts contains options relating to PKCS1V15 signing algorithm.
type RSAVerifyOpts struct {
	Schema string
	Hash   crypto.Hash
}

// Algorithm returns the RSA algorithm identifier (to be used).
func (opts *RSAVerifyOpts) Algorithm() string {
	return RSA
}
