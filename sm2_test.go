package cryptolib

import (
	"bytes"
	"testing"
)

func TestSm2KeyGenerator(t *testing.T) {
	kg := &sm2KeyGenerator{}
	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != SM2 {
		t.Fatalf("k should be SM2 key")
	}
	if k.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Get PublicKey failed: %v", err)
	}
	if pk.Type() != SM2 {
		t.Fatalf("k should be SM2 key")
	}
	if pk.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if pk.Private() {
		t.Fatalf("pk should not be private key")
	}
}

func TestSm2Signer(t *testing.T) {
	kg := &sm2KeyGenerator{}
	signer := &sm2Signer{}

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

func TestSm2Verifier(t *testing.T) {
	kg := &sm2KeyGenerator{}
	signer := &sm2Signer{}
	verifier := &sm2Verifier{}

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

func TestSm2Encrypter(t *testing.T) {
	kg := &sm2KeyGenerator{}
	encrypter := &sm2Encrypter{}

	k, err := kg.KeyGen(&SM2KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("hello, world")
	pubKey, _ := k.PublicKey()
	_, err = encrypter.Encrypt(pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("SM2 encrypting failed: %v", err)
	}
}

func TestSm2Decrypter(t *testing.T) {
	kg := &sm2KeyGenerator{}
	encrypter := &sm2Encrypter{}
	decrypter := &sm2Decrypter{}

	k, err := kg.KeyGen(&SM2KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("hello, world")
	pubKey, _ := k.PublicKey()
	cipher, err := encrypter.Encrypt(pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("SM2 encrypting failed: %v", err)
	}

	result, err := decrypter.Decrypt(k, cipher, nil)
	if err != nil {
		t.Fatalf("SM2 decrypting failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}
