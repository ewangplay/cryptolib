package cryptolib

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
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

func TestSignWithKeyIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	digest := []byte("hello,world")

	_, err = csp.Sign(nil, digest, nil)
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

	digests := [][]byte{nil, {}}
	for _, d := range digests {
		_, err = csp.Sign(k, d, nil)
		if err == nil {
			t.Fatalf("Sign should be failed when digest is empty")
		}

		errShouldContain(t, err, "invalid digest, cannot be empty")
	}
}

type mockPrivateKey struct{}

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

	_, err = csp.Sign(&mockPrivateKey{}, []byte("hello,world"), nil)
	if err == nil {
		t.Fatalf("Sign should be failed when key type is mismatched")
	}

	errShouldContain(t, err, "unsupported 'SignatureKey' provided")
}

func errShouldContain(t *testing.T, err error, msg string) {
	if !strings.Contains(err.Error(), msg) {
		t.Fatalf("Error should contain '%s'", msg)
	}
}

type mockSigner struct{}

// Sign signs digest using key k
func (m *mockSigner) Sign(k Key, digest []byte, opts SignatureOpts) (signature []byte, err error) {
	return nil, fmt.Errorf("internal exception")
}

func TestSignFailed(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}
	csp.AddWrapper(reflect.TypeOf(&mockPrivateKey{}), &mockSigner{})

	_, err = csp.Sign(&mockPrivateKey{}, []byte("hello,world"), nil)
	if err == nil {
		t.Fatalf("Sign should be failed when occuring internal exception")
	}

	errShouldContain(t, err, "failed signing")
}

func TestVerifyWithKeyIsNil(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	digest := []byte("hello,world")
	signature := []byte("signature value")

	_, err = csp.Verify(nil, digest, signature, nil)
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

	digests := [][]byte{nil, {}}
	signature := []byte("signature value")
	for _, d := range digests {
		_, err = csp.Verify(pubKey, d, signature, nil)
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
	signatures := [][]byte{nil, {}}
	for _, s := range signatures {
		_, err = csp.Verify(pubKey, digest, s, nil)
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

	_, err = csp.Verify(&mockPublicKey{}, digest, signature, nil)
	if err == nil {
		t.Fatalf("Verify should be failed when key type is mismatched")
	}

	errShouldContain(t, err, "unsupported 'SignatureKey' provided")
}

type mockPublicKey struct{}

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
func (m *mockVerifier) Verify(k Key, digest, signature []byte, opts SignatureOpts) (valid bool, err error) {
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

	_, err = csp.Verify(&mockPublicKey{}, digest, signature, nil)
	if err == nil {
		t.Fatalf("Verify should be failed when key type is mismatched")
	}

	errShouldContain(t, err, "failed verifing")
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

func ExampleHash_sha256() {
	csp, err := NewSWCSP()
	if err != nil {
		fmt.Printf("NewSWCSP failed: %v\n", err)
		return
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SHA256Opts{})
	if err != nil {
		fmt.Printf("Hash failed %v\n", err)
		return
	}

	fmt.Println(hex.EncodeToString(digest))
	// Output:
	// 77df263f49123356d28a4a8715d25bf5b980beeeb503cab46ea61ac9f3320eda
}

func ExampleHash_sha384() {
	csp, err := NewSWCSP()
	if err != nil {
		fmt.Printf("NewSWCSP failed: %v\n", err)
		return
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SHA384Opts{})
	if err != nil {
		fmt.Printf("Hash failed %v\n", err)
		return
	}

	fmt.Println(hex.EncodeToString(digest))
	// Output:
	// 892987556fb42d19ab3ad8eb42ebaff1bc738a52f0f3c5728aa1285596a88395b59cb6b8c4e63e5b8ed5a79e1664526c
}

func ExampleHash_sha512() {
	csp, err := NewSWCSP()
	if err != nil {
		fmt.Printf("NewSWCSP failed: %v\n", err)
		return
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SHA512Opts{})
	if err != nil {
		fmt.Printf("Hash failed %v\n", err)
		return
	}

	fmt.Println(hex.EncodeToString(digest))
	// Output:
	// 2958f052052ce5c280fc1dcf97038c4f4bf36ca5bde0531567201b391d977db699c379b4d31c8b3dd75a407114104aecb84f8ca11cad67b33d865dd47a72dec3
}

func ExampleHash_sm3() {
	csp, err := NewSWCSP()
	if err != nil {
		fmt.Printf("NewSWCSP failed: %v\n", err)
		return
	}

	msg := []byte("hello,world")
	digest, err := csp.Hash(msg, &SM3Opts{})
	if err != nil {
		fmt.Printf("Hash failed %v\n", err)
		return
	}

	fmt.Println(hex.EncodeToString(digest))
	// Output:
	// 72456cdb868a49b85123d6093c15f31c75ac698c466d33d7dc312122f5887d3f
}

type signAndVerifyOpts struct {
	KeyGenOpsts KeyGenOpts
	HashOpts    HashOpts
	SignOpts    SignatureOpts
	VerifyOpts  SignatureOpts
}

var signatureOpts = []*signAndVerifyOpts{
	{
		KeyGenOpsts: &ED25519KeyGenOpts{},
		HashOpts:    nil,
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &ECDSAKeyGenOpts{},
		HashOpts:    nil,
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &ECDSAKeyGenOpts{Curve: elliptic.P224()},
		HashOpts:    nil,
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &ECDSAKeyGenOpts{Curve: elliptic.P256()},
		HashOpts:    nil,
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &ECDSAKeyGenOpts{Curve: elliptic.P384()},
		HashOpts:    nil,
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &ECDSAKeyGenOpts{Curve: elliptic.P521()},
		HashOpts:    nil,
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA256Opts{},
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 1024},
		HashOpts:    &SHA256Opts{},
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 2048},
		HashOpts:    &SHA256Opts{},
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 3072},
		HashOpts:    &SHA256Opts{},
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 4096},
		HashOpts:    &SHA256Opts{},
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA256Opts{},
		SignOpts:    &RSASignatureOpts{Schema: PSS, Hash: crypto.SHA256},
		VerifyOpts:  &RSASignatureOpts{Schema: PSS, Hash: crypto.SHA256},
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA384Opts{},
		SignOpts:    &RSASignatureOpts{Schema: PSS, Hash: crypto.SHA384},
		VerifyOpts:  &RSASignatureOpts{Schema: PSS, Hash: crypto.SHA384},
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA512Opts{},
		SignOpts:    &RSASignatureOpts{Schema: PSS, Hash: crypto.SHA512},
		VerifyOpts:  &RSASignatureOpts{Schema: PSS, Hash: crypto.SHA512},
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA256Opts{},
		SignOpts:    &RSASignatureOpts{Schema: PKCS1V15, Hash: crypto.SHA256},
		VerifyOpts:  &RSASignatureOpts{Schema: PKCS1V15, Hash: crypto.SHA256},
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA384Opts{},
		SignOpts:    &RSASignatureOpts{Schema: PKCS1V15, Hash: crypto.SHA384},
		VerifyOpts:  &RSASignatureOpts{Schema: PKCS1V15, Hash: crypto.SHA384},
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		HashOpts:    &SHA512Opts{},
		SignOpts:    &RSASignatureOpts{Schema: PKCS1V15, Hash: crypto.SHA512},
		VerifyOpts:  &RSASignatureOpts{Schema: PKCS1V15, Hash: crypto.SHA512},
	},
	{
		KeyGenOpsts: &SM2KeyGenOpts{},
		HashOpts:    &SHA256Opts{},
		SignOpts:    nil,
		VerifyOpts:  nil,
	},
}

func TestSignAndVerify(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	msg := []byte("hello,world")
	for _, opts := range signatureOpts {
		signAndVerify(t, csp, opts, msg)
	}
}

func signAndVerify(t *testing.T, csp CSP, opts *signAndVerifyOpts, msg []byte) {

	k, err := csp.KeyGen(opts.KeyGenOpsts)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	var digest []byte
	if opts.HashOpts != nil {
		digest, err = csp.Hash(msg, opts.HashOpts)
		if err != nil {
			t.Fatalf("Hash failed %v", err)
		}
	} else {
		digest = msg
	}

	signature, err := csp.Sign(k, digest, opts.SignOpts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Get public key failed: %v", err)
	}

	valid, err := csp.Verify(pubKey, digest, signature, opts.VerifyOpts)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatalf("The signature should be validated")
	}
}

type encryptAndDecryptOpts struct {
	KeyGenOpsts KeyGenOpts
	EcnryptOpts EnciphermentOpts
	DecryptOpts EnciphermentOpts
}

var encryptionOpts = []*encryptAndDecryptOpts{
	{
		KeyGenOpsts: &ECDSAKeyGenOpts{},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 1024},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 2048},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 3072},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{Bits: 4096},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		EcnryptOpts: &RSAEnciphermentOpts{Schema: OAEP, Hash: sha256.New224(), Label: "test01"},
		DecryptOpts: &RSAEnciphermentOpts{Schema: OAEP, Hash: sha256.New224(), Label: "test01"},
	},
	{
		KeyGenOpsts: &RSAKeyGenOpts{},
		EcnryptOpts: &RSAEnciphermentOpts{Schema: PKCS1V15, Hash: sha256.New()},
		DecryptOpts: &RSAEnciphermentOpts{Schema: PKCS1V15, Hash: sha256.New()},
	},
	{
		KeyGenOpsts: &SM2KeyGenOpts{},
		EcnryptOpts: nil,
		DecryptOpts: nil,
	},
	{
		KeyGenOpsts: &AESKeyGenOpts{},
		EcnryptOpts: &AESCBCPKCS7PaddingOpts{},
		DecryptOpts: &AESCBCPKCS7PaddingOpts{},
	},
	{
		KeyGenOpsts: &AESKeyGenOpts{},
		EcnryptOpts: &AESECBPKCS7PaddingOpts{},
		DecryptOpts: &AESECBPKCS7PaddingOpts{},
	},
	{
		KeyGenOpsts: &AESKeyGenOpts{},
		EcnryptOpts: &AESCFBModeOpts{},
		DecryptOpts: &AESCFBModeOpts{},
	},
	{
		KeyGenOpsts: &AESKeyGenOpts{},
		EcnryptOpts: &AESOFBModeOpts{},
		DecryptOpts: &AESOFBModeOpts{},
	},
	{
		KeyGenOpsts: &AESKeyGenOpts{},
		EcnryptOpts: &AESCTRModeOpts{},
		DecryptOpts: &AESCTRModeOpts{},
	},
	{
		KeyGenOpsts: &SM4KeyGenOpts{},
		EcnryptOpts: &SM4CBCPKCS7PaddingOpts{},
		DecryptOpts: &SM4CBCPKCS7PaddingOpts{},
	},
	{
		KeyGenOpsts: &SM4KeyGenOpts{},
		EcnryptOpts: &SM4ECBPKCS7PaddingOpts{},
		DecryptOpts: &SM4ECBPKCS7PaddingOpts{},
	},
	{
		KeyGenOpsts: &SM4KeyGenOpts{},
		EcnryptOpts: &SM4CFBModeOpts{},
		DecryptOpts: &SM4CFBModeOpts{},
	},
	{
		KeyGenOpsts: &SM4KeyGenOpts{},
		EcnryptOpts: &SM4OFBModeOpts{},
		DecryptOpts: &SM4OFBModeOpts{},
	},
	{
		KeyGenOpsts: &SM4KeyGenOpts{},
		EcnryptOpts: &SM4CTRModeOpts{},
		DecryptOpts: &SM4CTRModeOpts{},
	},
}

func TestEncryptAndDecrypt(t *testing.T) {
	csp, err := NewSWCSP()
	if err != nil {
		t.Fatalf("NewSWCSP failed: %v", err)
	}

	plaintext := []byte("this is a test string. hello,world.")
	for _, opts := range encryptionOpts {
		result := encryptAndDecrypt(t, csp, opts, plaintext)
		if bytes.Compare(plaintext, result) != 0 {
			t.Fatalf("The original text should be equal to the decrypted text")
		}
	}
}

func encryptAndDecrypt(t *testing.T, csp CSP, opts *encryptAndDecryptOpts, plaintext []byte) []byte {

	k, err := csp.KeyGen(opts.KeyGenOpsts)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	var pk Key
	if k.Symmetric() {
		pk = k
	} else {
		pk, err = k.PublicKey()
		if err != nil {
			t.Fatalf("Get public key failed: %v", err)
		}
	}

	cihpertext, err := csp.Encrypt(pk, plaintext, opts.EcnryptOpts)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := csp.Decrypt(k, cihpertext, opts.DecryptOpts)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	return result
}
