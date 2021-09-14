package cryptolib

// Key represents a cryptographic key
type Key interface {
	// Version returns the version of this key
	Version() int

	// Type returns the type of this key
	Type() string

	// Bytes converts this key to its byte representation,
	// if this operation is allowed.
	Bytes() ([]byte, error)

	// Symmetric returns true if this key is a symmetric key,
	// false is this key is asymmetric
	Symmetric() bool

	// Private returns true if this key is a private key,
	// false otherwise.
	Private() bool

	// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
	// This method returns an error in symmetric key schemes.
	PublicKey() (Key, error)
}

// KeyGenOpts contains options for key-generation with a CSP.
type KeyGenOpts interface {
	// Algorithm returns the key generation algorithm identifier (to be used).
	Algorithm() string
}

// HashOpts contains options for hashing with a CSP.
type HashOpts interface {
	// Algorithm returns the hash algorithm identifier (to be used).
	Algorithm() string
}

// SignOpts contains options for signing with a CSP.
type SignOpts interface {
	// Algorithm returns the signing algorithm identifier (to be used).
	Algorithm() string
}

// VerifyOpts contains options for signature verifing with a CSP.
type VerifyOpts interface {
	// Algorithm returns the signature verifing algorithm identifier (to be used).
	Algorithm() string
}

// KeyGenerator is a interface that provides key generation algorithms
type KeyGenerator interface {
	// KeyGen generates a key using opts.
	KeyGen(opts KeyGenOpts) (k Key, err error)
}

// Signer is a interface that provides signing algorithms
type Signer interface {
	// Sign signs digest using key k.
	//
	// Note that when a signature of a hash of a larger message is needed,
	// the caller is responsible for hashing the larger message and passing
	// the hash (as digest).
	Sign(k Key, digest []byte, opts SignOpts) (signature []byte, err error)
}

// Verifier is a interface that provides verifying algorithms
type Verifier interface {
	// Verify verifies signature against key k and digest
	Verify(k Key, digest, signature []byte, opts VerifyOpts) (valid bool, err error)
}

// Hasher is a BCCSP-like interface that provides hash algorithms
type Hasher interface {

	// Hash hashes messages msg using options opts.
	Hash(msg []byte, opts HashOpts) (hash []byte, err error)
}

// CSP is the cryptographic service provider that offers
// the implementation of cryptographic standards and algorithms.
type CSP interface {

	// KeyGen generates a key using opts.
	KeyGen(opts KeyGenOpts) (k Key, err error)

	// Hash hashes messages msg using options opts.
	Hash(msg []byte, opts HashOpts) (hash []byte, err error)

	// Sign signs digest using key k.
	//
	// Note that when a signature of a hash of a larger message is needed,
	// the caller is responsible for hashing the larger message and passing
	// the hash (as digest).
	Sign(k Key, digest []byte, opts SignOpts) (signature []byte, err error)

	// Verify verifies signature against key k and digest
	Verify(k Key, digest, signature []byte, opts VerifyOpts) (valid bool, err error)
}
