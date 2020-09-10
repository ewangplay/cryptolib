package cryptohub

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestKeyGenWithOptsIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	_, err = csp.KeyGen(nil)
	if err == nil {
		t.Fatalf("KeyGen should be failed when opts is nil")
	}

	errShouldContain(t, err, "invalid opts parameter, it must not be nil")
}

type mockKeyGenOpts struct{}

func (m *mockKeyGenOpts) Algorithm() string {
	return "mock"
}

func TestKeyGenWithOptsTypeIsMismatch(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	_, err = csp.KeyGen(&mockKeyGenOpts{})
	if err == nil {
		t.Fatalf("KeyGen should be failed when opts type is mismatched")
	}

	errShouldContain(t, err, "unsupported 'KeyGenOpts' provided")
}

type mockKeyGenerator struct {
}

// GenKey generates a key of ed25519 algorithm
func (kg *mockKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	return nil, fmt.Errorf("internal exception")
}

func TestKeyGenFailed(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}
	csp.AddWrapper(reflect.TypeOf(&mockKeyGenOpts{}), &mockKeyGenerator{})

	_, err = csp.KeyGen(&mockKeyGenOpts{})
	if err == nil {
		t.Fatalf("KeyGen should be failed when occuring internal exception")
	}

	errShouldContain(t, err, "failed generating key with opts")
}

func TestKeyGenSucc(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	k, err := csp.KeyGen(&ED25519KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	typeOf := reflect.TypeOf(k)
	if typeOf != reflect.TypeOf(&Ed25519PrivateKey{}) {
		t.Fatalf("Key returned by KeyGen should be Ed25519PrivateKey type")
	}
}

func TestSignWithKeyIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	digest := []byte("hello,world")

	_, err = csp.Sign(nil, digest)
	if err == nil {
		t.Fatalf("Sign should be failed when key is nil")
	}

	errShouldContain(t, err, "invalid Key, it must not be nil")
}

func TestSignWithDigestIsEmpty(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	k, err := csp.KeyGen(&ED25519KeyGenOpts{})
	if err != nil {
		t.Fatalf("Key generating failed: %v", err)
	}

	digests := [][]byte{nil, []byte{}}
	for _, d := range digests {
		_, err = csp.Sign(k, d)
		if err == nil {
			t.Fatalf("Sign should be failed when digest is empty")
		}

		errShouldContain(t, err, "invalid digest, cannot be empty")
	}
}

type mockKey struct{}

// Bytes converts this key to its byte representation.
func (k *mockKey) Bytes() ([]byte, error) {
	return []byte("private key"), nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *mockKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *mockKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mockKey) PublicKey() (Key, error) {
	return k, nil
}

func TestSignWithKeyTypeMismatch(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	_, err = csp.Sign(&mockKey{}, []byte("hello,world"))
	if err == nil {
		t.Fatalf("Sign should be failed when key is mismatched")
	}

	errShouldContain(t, err, "unsupported 'SignKey' provided")
}

func errShouldContain(t *testing.T, err error, msg string) {
	if !strings.Contains(err.Error(), msg) {
		t.Fatalf("Error should contain '%s'", msg)
	}
}

type mockSigner struct{}

// Sign signs digest using key k
func (ed *mockSigner) Sign(k Key, digest []byte) (signature []byte, err error) {
	return nil, fmt.Errorf("internal exception")
}

func TestSignFailed(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}
	csp.AddWrapper(reflect.TypeOf(&mockKey{}), &mockSigner{})

	_, err = csp.Sign(&mockKey{}, []byte("hello,world"))
	if err == nil {
		t.Fatalf("Sign should be failed when occuring internal exception")
	}

	errShouldContain(t, err, "failed signing")
}

func TestSignSucc(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("New SWCSP failed: %v", err)
	}

	k, err := csp.KeyGen(&ED25519KeyGenOpts{})
	if err != nil {
		t.Fatalf("Key generating failed: %v", err)
	}

	_, err = csp.Sign(k, []byte("hello,world"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
}
