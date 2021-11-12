package cryptolib

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestRsaKey(t *testing.T) {
	rsaPrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Generate RSA key failed: %v", err)
	}
	rsaPrKeyBytes := x509.MarshalPKCS1PrivateKey(rsaPrKey)
	privKey := &RsaPrivateKey{
		PrivKey: rsaPrKeyBytes,
	}

	if privKey.Type() != RSA {
		t.Fatalf("key type should be %v", RSA)
	}

	privKeyBytes, _ := privKey.Bytes()
	if !bytes.Equal(privKeyBytes, rsaPrKeyBytes) {
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

	if pubKey.Type() != RSA {
		t.Fatalf("key type should be %v", RSA)
	}

	pubKeyBytes, _ := pubKey.Bytes()
	pubKeyBytesExpected := x509.MarshalPKCS1PublicKey(&rsaPrKey.PublicKey)
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

func TestRsaKeyGen(t *testing.T) {
	kg := &rsaKeyGenerator{}
	k, err := kg.KeyGen(&RSAKeyGenOpts{Bits: 1024})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != RSA {
		t.Fatalf("k should be RSA key")
	}
	if k.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
}

func TestRsaEncrypter(t *testing.T) {
	kg := &rsaKeyGenerator{}
	encrypter := &rsaEncrypter{}

	k, err := kg.KeyGen(&RSAKeyGenOpts{Bits: 1024})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("hello, world")
	pubKey, _ := k.PublicKey()
	_, err = encrypter.Encrypt(pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("RSA encrypting failed: %v", err)
	}
}

func TestRsaDecrypter(t *testing.T) {
	kg := &rsaKeyGenerator{}
	encrypter := &rsaEncrypter{}
	decrypter := &rsaDecrypter{}

	k, err := kg.KeyGen(&RSAKeyGenOpts{Bits: 1024})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("hello, world")
	pubKey, _ := k.PublicKey()
	cipher, err := encrypter.Encrypt(pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("RSA encrypting failed: %v", err)
	}

	result, err := decrypter.Decrypt(k, cipher, nil)
	if err != nil {
		t.Fatalf("RSA decrypting failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}
