package cryptolib

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestKeyGenWithOptsIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
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
		t.Fatalf("NewSWCSP failed: %v", err)
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
		t.Fatalf("NewSWCSP failed: %v", err)
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
		t.Fatalf("NewSWCSP failed: %v", err)
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
		t.Fatalf("NewSWCSP failed: %v", err)
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
		t.Fatalf("NewSWCSP failed: %v", err)
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

type mockPrivateKey struct{}

// Version returns the version of this key
func (k *mockPrivateKey) Version() int {
	return ed25519V1
}

// Type returns the type of this key
func (k *mockPrivateKey) Type() string {
	return ED25519
}

// Bytes converts this key to its byte representation.
func (k *mockPrivateKey) Bytes() ([]byte, error) {
	return []byte("private key"), nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *mockPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *mockPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mockPrivateKey) PublicKey() (Key, error) {
	return &mockPublicKey{}, nil
}

func TestSignWithKeyTypeMismatch(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	_, err = csp.Sign(&mockPrivateKey{}, []byte("hello,world"))
	if err == nil {
		t.Fatalf("Sign should be failed when key type is mismatched")
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
func (m *mockSigner) Sign(k Key, digest []byte) (signature []byte, err error) {
	return nil, fmt.Errorf("internal exception")
}

func TestSignFailed(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}
	csp.AddWrapper(reflect.TypeOf(&mockPrivateKey{}), &mockSigner{})

	_, err = csp.Sign(&mockPrivateKey{}, []byte("hello,world"))
	if err == nil {
		t.Fatalf("Sign should be failed when occuring internal exception")
	}

	errShouldContain(t, err, "failed signing")
}

func TestSignSucc(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
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

func TestVerifyWithKeyIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	digest := []byte("hello,world")
	signature := []byte("signature value")

	_, err = csp.Verify(nil, digest, signature)
	if err == nil {
		t.Fatalf("Verify should be failed when key is nil")
	}

	errShouldContain(t, err, "invalid Key, it must not be nil")
}

func TestVerifyWithDigestIsEmpty(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	k, err := csp.KeyGen(&ED25519KeyGenOpts{})
	if err != nil {
		t.Fatalf("Key generating failed: %v", err)
	}
	pubKey, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Get public key failed: %v", err)
	}

	digests := [][]byte{nil, []byte{}}
	signature := []byte("signature value")
	for _, d := range digests {
		_, err = csp.Verify(pubKey, d, signature)
		if err == nil {
			t.Fatalf("Verify should be failed when digest is empty")
		}

		errShouldContain(t, err, "invalid digest, cannot be empty")
	}
}

func TestVerifyWithSignatureIsEmpty(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	k, err := csp.KeyGen(&ED25519KeyGenOpts{})
	if err != nil {
		t.Fatalf("Key generating failed: %v", err)
	}
	pubKey, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Get public key failed: %v", err)
	}

	digest := []byte("hello,world")
	signatures := [][]byte{nil, []byte{}}
	for _, s := range signatures {
		_, err = csp.Verify(pubKey, digest, s)
		if err == nil {
			t.Fatalf("Verify should be failed when signature is empty")
		}

		errShouldContain(t, err, "invalid signature, cannot be empty")
	}
}

func TestVerifyWithKeyTypeMismatch(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	digest := []byte("hello,world")
	signature := []byte("signature value")

	_, err = csp.Verify(&mockPublicKey{}, digest, signature)
	if err == nil {
		t.Fatalf("Verify should be failed when key type is mismatched")
	}

	errShouldContain(t, err, "unsupported 'VerifyKey' provided")
}

type mockPublicKey struct{}

// Version returns the version of this key
func (k *mockPublicKey) Version() int {
	return ed25519V1
}

// Type returns the type of this key
func (k *mockPublicKey) Type() string {
	return ED25519
}

// Bytes converts this key to its byte representation.
func (k *mockPublicKey) Bytes() ([]byte, error) {
	return []byte("public key"), nil
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *mockPublicKey) Symmetric() bool {
	return false
}

// Public returns true if this key is a private key,
// false otherwise.
func (k *mockPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mockPublicKey) PublicKey() (Key, error) {
	return k, nil
}

type mockVerifier struct{}

// Verify verifies signature against key k and digest
func (m *mockVerifier) Verify(k Key, digest, signature []byte) (valid bool, err error) {
	return false, fmt.Errorf("intertal exception")
}

func TestVerifyFailed(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}
	csp.AddWrapper(reflect.TypeOf(&mockPublicKey{}), &mockVerifier{})

	digest := []byte("hello,world")
	signature := []byte("signature value")

	_, err = csp.Verify(&mockPublicKey{}, digest, signature)
	if err == nil {
		t.Fatalf("Verify should be failed when key type is mismatched")
	}

	errShouldContain(t, err, "failed verifing")
}

func TestVerifySucc(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	k, err := csp.KeyGen(&ED25519KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	signature, err := csp.Sign(k, digest)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Get public key failed: %v", err)
	}

	valid, err := csp.Verify(pubKey, digest, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatalf("The signature should be validated")
	}
}

func TestAddWrapperWithTypeIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	err = csp.AddWrapper(nil, &mockSigner{})
	if err == nil {
		t.Fatalf("AddWrapper should be failed when the passed type is nil")
	}

	errShouldContain(t, err, "type cannot be nil")
}

func TestAddWrapperWithWrapperIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	err = csp.AddWrapper(reflect.TypeOf(&mockPrivateKey{}), nil)
	if err == nil {
		t.Fatalf("AddWrapper should be failed when the passed wrapper is nil")
	}

	errShouldContain(t, err, "wrapper cannot be nil")
}

func TestAddWrapperWithWrapperTypeMismatch(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	err = csp.AddWrapper(reflect.TypeOf(&mockPrivateKey{}), "InvalidWrapper")
	if err == nil {
		t.Fatalf("AddWrapper should be failed when the passed wrapper type is mismatched")
	}

	errShouldContain(t, err, "wrapper type not valid")
}

func TestAddWrapperSucc(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	typMockKeyGenOpts := reflect.TypeOf(&mockKeyGenOpts{})
	typMockPrivKey := reflect.TypeOf(&mockPrivateKey{})
	typMockPubKey := reflect.TypeOf(&mockPublicKey{})

	m := map[reflect.Type]interface{}{
		typMockKeyGenOpts: &mockKeyGenerator{},
		typMockPrivKey:    &mockSigner{},
		typMockPubKey:     &mockVerifier{},
	}

	for typ, wrapper := range m {
		err = csp.AddWrapper(typ, wrapper)
		if err != nil {
			t.Fatalf("AddWrapper failed: %v", err)
		}
	}

	_, found := csp.KeyGenerators[typMockKeyGenOpts]
	if !found {
		t.Fatalf("The mockKeyGenerator should be found")
	}

	_, found = csp.Signers[typMockPrivKey]
	if !found {
		t.Fatalf("The mockSigner should be found")
	}

	_, found = csp.Verifiers[typMockPubKey]
	if !found {
		t.Fatalf("The mockVerifier should be found")
	}
}

func TestHashWithMsgIsEmpty(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	_, err = csp.Hash(nil, &SHA256Opts{})
	if err == nil {
		t.Fatal("Hash should be failed when msg is nil")
	}

	errShouldContain(t, err, "msg must not be empty")
}

func TestHashWithOptsIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	msg := []byte("hello,world")
	_, err = csp.Hash(msg, nil)
	if err == nil {
		t.Fatal("Hash should be failed when opts is nil")
	}

	errShouldContain(t, err, "invalid opts. It must not be nil")
}

type mockHashOpts struct{}

func (m *mockHashOpts) Algorithm() string {
	return "mockHash"
}

func TestHashWithOptsTypeIsMismatch(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	msg := []byte("hello,world")
	_, err = csp.Hash(msg, &mockHashOpts{})
	if err == nil {
		t.Fatal("Hash should be failed when opts type is mismatched")
	}

	errShouldContain(t, err, "unsupported 'HashOpt' provided")
}

type mockHasher struct {
}

// Hash hashes messages msg using options opts.
func (mh *mockHasher) Hash(msg []byte, opts HashOpts) (digest []byte, err error) {
	return nil, fmt.Errorf("internal exception")
}

func TestHashFailed(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}
	csp.AddWrapper(reflect.TypeOf(&mockHashOpts{}), &mockHasher{})

	msg := []byte("hello,world")
	_, err = csp.Hash(msg, &mockHashOpts{})
	if err == nil {
		t.Fatal("Hash should be failed when occuring internal exception")
	}

	errShouldContain(t, err, "failed hashing with opts")
}

func TestHashSuccWithSha256(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SHA256Opts{})
	if err != nil {
		t.Fatalf("Hash failed %v", err)
	}

	fmt.Println("digest: ", hex.EncodeToString(digest))
}

func TestHashSuccWithSha384(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SHA384Opts{})
	if err != nil {
		t.Fatalf("Hash failed %v", err)
	}

	fmt.Println("digest: ", hex.EncodeToString(digest))
}

func TestHashSuccWithSha512(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SHA512Opts{})
	if err != nil {
		t.Fatalf("Hash failed %v", err)
	}

	fmt.Println("digest: ", hex.EncodeToString(digest))
}
