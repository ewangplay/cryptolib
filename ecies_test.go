package cryptolib

import (
	"bytes"
	"testing"
)

func TestEciesEncrypter(t *testing.T) {
	kg := &ecdsaKeyGenerator{}
	encrypter := &eciesEncrypter{}

	privKey, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("hello, world")
	pubKey, _ := privKey.PublicKey()
	_, err = encrypter.Encrypt(pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("ECIES encrypting failed: %v", err)
	}
}

func TestEciesDecrypter(t *testing.T) {
	kg := &ecdsaKeyGenerator{}
	encrypter := &eciesEncrypter{}
	decrypter := &eciesDecrypter{}

	privKey, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("hello, world")
	pubKey, _ := privKey.PublicKey()
	cipher, err := encrypter.Encrypt(pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("ECIES encrypting failed: %v", err)
	}

	result, err := decrypter.Decrypt(privKey, cipher, nil)
	if err != nil {
		t.Fatalf("ECIES encrypting failed: %v", err)
	}

	if bytes.Compare(result, plaintext) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}
