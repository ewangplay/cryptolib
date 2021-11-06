package cryptolib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestEcdsaKey(t *testing.T) {
	ecPriKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECDSA key failed: %v", err)
	}
	ecPriKeyBytes, err := x509.MarshalECPrivateKey(ecPriKey)
	if err != nil {
		t.Fatalf("Generate ECDSA key failed: %v", err)
	}
	privKey := &EcdsaPrivateKey{
		PrivKey: ecPriKeyBytes,
	}

	if privKey.Version() != ecdsaV1 {
		t.Fatalf("key version should be 1")
	}

	if privKey.Type() != ECDSA {
		t.Fatalf("key type should be %v", ECDSA)
	}

	privKeyBytes, _ := privKey.Bytes()
	if !bytes.Equal(privKeyBytes, ecPriKeyBytes) {
		t.Fatalf("Priavte key bytes mismatch")
	}

	if privKey.Symmetric() {
		t.Fatalf("privKey should not be symmetric key")
	}

	if !privKey.Private() {
		t.Fatalf("privKey should be private key")
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("Get the public key of privKey failed: %v", err)
	}

	if pubKey.Version() != ecdsaV1 {
		t.Fatalf("key version should be 1")
	}

	if pubKey.Type() != ECDSA {
		t.Fatalf("key type should be %v", ECDSA)
	}

	pubKeyBytes, _ := pubKey.Bytes()
	pubKeyBytesExpected, _ := x509.MarshalPKIXPublicKey(&ecPriKey.PublicKey)
	if !bytes.Equal(pubKeyBytes, pubKeyBytesExpected) {
		t.Fatalf("Public key bytes mismatch")
	}

	if pubKey.Symmetric() {
		t.Fatalf("pubKey should not be symmetric key")
	}

	if pubKey.Private() {
		t.Fatalf("pubKey should not be private key")
	}
}

func TestEcdsaKeyGenerator(t *testing.T) {
	kg := &ecdsaKeyGenerator{}

	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != ECDSA {
		t.Fatalf("k should be ECDSA key")
	}
	if k.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}

	opts := &ECDSAKeyGenOpts{Curve: elliptic.P384()}
	k, err = kg.KeyGen(opts)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != ECDSA {
		t.Fatalf("k should be ECDSA key")
	}
	if k.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}

}

func TestEcdsaSigner(t *testing.T) {
	kg := &ecdsaKeyGenerator{}
	signer := &ecdsaSigner{}

	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	_, err = signer.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
}

func TestEcdsaVerifier(t *testing.T) {
	kg := &ecdsaKeyGenerator{}
	signer := &ecdsaSigner{}
	verifier := &ecdsaVerifier{}

	privKey, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	signature, err := signer.Sign(privKey, digest, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey, _ := privKey.PublicKey()
	valid, err := verifier.Verify(pubKey, digest, signature, nil)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatalf("The signature should be validated")
	}
}
