package cryptolib

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSm4KeyGen(t *testing.T) {
	kg := &sm4KeyGenerator{}
	k, err := kg.KeyGen(&SM4KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != SM4 {
		t.Fatalf("k should be SM4 key")
	}
	if !k.Symmetric() {
		t.Fatalf("k should be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
}

func TestSm4Encrypter(t *testing.T) {
	kg := &sm4KeyGenerator{}
	et := &sm4Encrypter{}

	k, err := kg.KeyGen(&SM4KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	key, _ := k.Bytes()
	fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, err := et.Encrypt(k, plaintext, &SM4CBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestSm4EncrypterWithIV(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	iv, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b00")
	plaintext := []byte("this is a test string. hello,world.")

	k := &sm4Key{key}
	et := &sm4Encrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &SM4CBCPKCS7PaddingOpts{IV: iv})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	// Output: cc8212ab1322a5d17ac9023ed0950b002d463a92dfe48a71072fb91bdcea2025c4a7b545f3184fed237e2cb552582cb3b9b31e2e889d0d31985801f2c08c65e8
}

func TestSm4EncrypterWithPRNG(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")

	k := &sm4Key{key}
	et := &sm4Encrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &SM4CBCPKCS7PaddingOpts{PRNG: rand.Reader})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestSm4Decrypter(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b002d463a92dfe48a71072fb91bdcea2025c4a7b545f3184fed237e2cb552582cb3b9b31e2e889d0d31985801f2c08c65e8")

	k := &sm4Key{key}
	dt := &sm4Decrypter{}

	result, err := dt.Decrypt(k, ciphertext, &SM4CBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func TestSm4(t *testing.T) {
	kg := &sm4KeyGenerator{}
	et := &sm4Encrypter{}
	dt := &sm4Decrypter{}

	k, err := kg.KeyGen(&SM4KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")
	ciphertext, err := et.Encrypt(k, plaintext, &SM4CBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := dt.Decrypt(k, ciphertext, &SM4CBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func BenchmarkSm4(t *testing.B) {
	kg := &sm4KeyGenerator{}
	et := &sm4Encrypter{}
	dt := &sm4Decrypter{}

	k, err := kg.KeyGen(&SM4KeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")

	for i := 0; i < t.N; i++ {
		ciphertext, err := et.Encrypt(k, plaintext, &SM4CBCPKCS7PaddingOpts{})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		result, err := dt.Decrypt(k, ciphertext, &SM4CBCPKCS7PaddingOpts{})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if bytes.Compare(plaintext, result) != 0 {
			t.Fatalf("The original text should be equal to the decrypted text")
		}
	}
}