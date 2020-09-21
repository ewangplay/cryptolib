package cryptohub

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestEd25519PrivateKey(t *testing.T) {
	edPubKey, edPriKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Generate ED25519 key failed: %v", err)
	}

	privKey := &Ed25519PrivateKey{
		PrivKey: edPriKey,
	}

	privKeyBytes, _ := privKey.Bytes()
	if !bytes.Equal(privKeyBytes, edPriKey) {
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

	pubKeyBytes, _ := pubKey.Bytes()
	if !bytes.Equal(pubKeyBytes, edPubKey) {
		t.Fatalf("Public key bytes mismatch")
	}

	if pubKey.Symmetric() {
		t.Fatalf("pubKey should not be symmetric key")
	}

	if pubKey.Private() {
		t.Fatalf("pubKey should not be private key")
	}
}

func TestEd25519PublicKey(t *testing.T) {
	edPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Generate ED25519 key failed: %v", err)
	}

	pubKey := &Ed25519PublicKey{
		PubKey: edPubKey,
	}

	pubKeyBytes, _ := pubKey.Bytes()
	if !bytes.Equal(pubKeyBytes, edPubKey) {
		t.Fatalf("Public key bytes mismatch")
	}

	if pubKey.Symmetric() {
		t.Fatalf("pubKey should not be symmetric key")
	}

	if pubKey.Private() {
		t.Fatalf("pubKey should not be private key")
	}
}

func TestEd25519KeyGenerator(t *testing.T) {
	kg := &ed25519KeyGenerator{}

	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	if k.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}

	if !k.Private() {
		t.Fatalf("k should be private key")
	}
}

func TestEd25519Signer(t *testing.T) {
	kg := &ed25519KeyGenerator{}
	signer := &ed25519Signer{}

	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	_, err = signer.Sign(k, digest)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
}

func TestEd25519Verifier(t *testing.T) {
	kg := &ed25519KeyGenerator{}
	signer := &ed25519Signer{}
	verifier := &ed25519Verifier{}

	privKey, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	signature, err := signer.Sign(privKey, digest)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey, _ := privKey.PublicKey()
	valid, err := verifier.Verify(pubKey, digest, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatalf("The signature should be validated")
	}
}
