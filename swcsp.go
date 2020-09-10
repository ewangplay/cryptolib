package cryptohub

import (
	"fmt"
	"reflect"
)

// SWCSP provides a software-based implementation of the CSP interface.
type SWCSP struct {
	KeyGenerators map[reflect.Type]KeyGenerator
	Signers       map[reflect.Type]Signer
	Verifiers     map[reflect.Type]Verifier
}

// NewSWCSP creates a SWCSP instance.
func NewSWCSP() (*SWCSP, error) {
	signers := make(map[reflect.Type]Signer)
	verifiers := make(map[reflect.Type]Verifier)
	keyGenerators := make(map[reflect.Type]KeyGenerator)

	csp := &SWCSP{
		KeyGenerators: keyGenerators,
		Signers:       signers,
		Verifiers:     verifiers,
	}

	err := initSWCSP(csp)
	if err != nil {
		return nil, err
	}

	return csp, nil
}

// KeyGen generates a key using opts.
func (csp *SWCSP) KeyGen(opts KeyGenOpts) (k Key, err error) {
	if opts == nil {
		return nil, fmt.Errorf("invalid opts parameter, it must not be nil")
	}

	keyGenerator, found := csp.KeyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, fmt.Errorf("unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, fmt.Errorf("failed generating key with opts [%v]: %v", opts, err)
	}

	return k, nil
}

// Sign signs digest using key k.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *SWCSP) Sign(k Key, digest []byte) (signature []byte, err error) {
	if k == nil {
		return nil, fmt.Errorf("invalid Key, it must not be nil")
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("invalid digest, cannot be empty")
	}

	keyType := reflect.TypeOf(k)
	signer, found := csp.Signers[keyType]
	if !found {
		return nil, fmt.Errorf("unsupported 'SignKey' provided [%s]", keyType)
	}

	signature, err = signer.Sign(k, digest)
	if err != nil {
		return nil, fmt.Errorf("failed signing: %v", err)
	}

	return
}

// Verify verifies signature against key k and digest
func (csp *SWCSP) Verify(k Key, digest, signature []byte) (valid bool, err error) {
	if k == nil {
		return false, fmt.Errorf("invalid Key, it must not be nil")
	}
	if len(digest) == 0 {
		return false, fmt.Errorf("invalid digest, cannot be empty")
	}
	if len(signature) == 0 {
		return false, fmt.Errorf("invalid signature, cannot be empty")
	}

	verifier, found := csp.Verifiers[reflect.TypeOf(k)]
	if !found {
		return false, fmt.Errorf("unsupported 'VerifyKey' provided [%v]", k)
	}

	valid, err = verifier.Verify(k, digest, signature)
	if err != nil {
		return false, fmt.Errorf("failed verifing: %v", err)
	}

	return
}

// AddWrapper binds the passed type to the passed wrapper.
// Notice that that wrapper must be an instance of one of the following interfaces:
// KeyGenerator, Signer, Verifier.
func (csp *SWCSP) AddWrapper(t reflect.Type, w interface{}) error {
	if t == nil {
		return fmt.Errorf("type cannot be nil")
	}
	if w == nil {
		return fmt.Errorf("wrapper cannot be nil")
	}

	switch dt := w.(type) {
	case KeyGenerator:
		csp.KeyGenerators[t] = dt
	case Signer:
		csp.Signers[t] = dt
	case Verifier:
		csp.Verifiers[t] = dt
	default:
		return fmt.Errorf("wrapper type not valid, must be on of: KeyGenerator, Signer, Verifier")
	}
	return nil
}

func initSWCSP(csp *SWCSP) error {
	// Set the key generators
	csp.AddWrapper(reflect.TypeOf(&ED25519KeyGenOpts{}), &ed25519KeyGenerator{})

	// Set the Signers
	csp.AddWrapper(reflect.TypeOf(&Ed25519PrivateKey{}), &ed25519Signer{})

	// Set the Verifiers
	csp.AddWrapper(reflect.TypeOf(&Ed25519PublicKey{}), &ed25519Verifier{})

	return nil
}
