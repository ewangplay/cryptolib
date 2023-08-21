package cryptolib

import (
	"bytes"
	"testing"
)

func TestAesKeyGen(t *testing.T) {
	kg := &aesKeyGenerator{}
	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != AES {
		t.Fatalf("k should be AES key")
	}
	if !k.Symmetric() {
		t.Fatalf("k should be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
}

func TestAes24LenKeyGen(t *testing.T) {
	kg := &aesKeyGenerator{}
	k, err := kg.KeyGen(&AESKeyGenOpts{Len: 24})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != AES {
		t.Fatalf("k should be AES key")
	}
	if !k.Symmetric() {
		t.Fatalf("k should be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
}

func TestAes32LenKeyGen(t *testing.T) {
	kg := &aesKeyGenerator{}
	k, err := kg.KeyGen(&AESKeyGenOpts{Len: 32})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != AES {
		t.Fatalf("k should be AES key")
	}
	if !k.Symmetric() {
		t.Fatalf("k should be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
}

func TestAesEncrypter(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("this is a test string. hello,world.")
	_, err = et.Encrypt(k, plaintext, &AESCBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
}

func TestAesDecrypter(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESCBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := dt.Decrypt(k, ciphertext, &AESCBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}
