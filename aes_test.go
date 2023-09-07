package cryptolib

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

func TestAesEncryptCBC(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	key, _ := k.Bytes()
	fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESCBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesEncryptCBCWithIV(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	iv, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b00")
	plaintext := []byte("this is a test string. hello,world.")

	k := &aesKey{key}
	et := &aesEncrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &AESCBCPKCS7PaddingOpts{IV: iv})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	// Output: cc8212ab1322a5d17ac9023ed0950b00fecdd4d7580726d0a97096d0ba816afecdda4a1cb54ab3d7c9b411d257eceaaa79f41ba7332c284eb10e1a5be96e9bac
}

func TestAesEncryptCBCWithPRNG(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")

	k := &aesKey{key}
	et := &aesEncrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &AESCBCPKCS7PaddingOpts{PRNG: rand.Reader})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesDecryptCBC(t *testing.T) {
	key, _ := hex.DecodeString("1098773a89fa8bb44075b5f961e4a065")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("c43e4f929fcaa97e67af1f3aa9c7b45623433616f22be4f781c47bbe5d11457f35538b6333eb90fdae3c03fece0669555dfc5d5d4db3aac652160fecf35230a5")

	k := &aesKey{key}
	dt := &aesDecrypter{}

	result, err := dt.Decrypt(k, ciphertext, &AESCBCPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func TestAesCBC(t *testing.T) {
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

func BenchmarkAesCBC(t *testing.B) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")

	for i := 0; i < t.N; i++ {
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
}

func TestAesEncryptECB(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	key, _ := k.Bytes()
	fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESECBPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesDecryptECB(t *testing.T) {
	key, _ := hex.DecodeString("97a362695e47e2e9c44278270f25f40f")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("e7139929c6746f2609b9ee6f458e976a59d23b1bd1aa3736b899a65cff207dbac53d0276b1acb01dbe2b1b8f728317d5")

	k := &aesKey{key}
	dt := &aesDecrypter{}

	result, err := dt.Decrypt(k, ciphertext, &AESECBPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func TestAesECB(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESECBPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := dt.Decrypt(k, ciphertext, &AESECBPKCS7PaddingOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func BenchmarkAesECB(t *testing.B) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")

	for i := 0; i < t.N; i++ {
		ciphertext, err := et.Encrypt(k, plaintext, &AESECBPKCS7PaddingOpts{})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		result, err := dt.Decrypt(k, ciphertext, &AESECBPKCS7PaddingOpts{})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if bytes.Compare(plaintext, result) != 0 {
			t.Fatalf("The original text should be equal to the decrypted text")
		}
	}
}

func TestAesEncryptCFB(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	key, _ := k.Bytes()
	fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESCFBModeOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesEncryptCFBWithIV(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	iv, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b00")
	plaintext := []byte("this is a test string. hello,world.")

	k := &aesKey{key}
	et := &aesEncrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &AESCFBModeOpts{IV: iv})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	// Output: cc8212ab1322a5d17ac9023ed0950b00e63198dc6740622867acde421e87e220caf99817a2bd49d2228f46b156f42180221874
}

func TestAesEncryptCFBWithPRNG(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")

	k := &aesKey{key}
	et := &aesEncrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &AESCFBModeOpts{PRNG: rand.Reader})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesDecryptCFB(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b00e63198dc6740622867acde421e87e220caf99817a2bd49d2228f46b156f42180221874")

	k := &aesKey{key}
	dt := &aesDecrypter{}

	result, err := dt.Decrypt(k, ciphertext, &AESCFBModeOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func TestAesCFB(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESCFBModeOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := dt.Decrypt(k, ciphertext, &AESCFBModeOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func BenchmarkAesCFB(t *testing.B) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")

	for i := 0; i < t.N; i++ {
		ciphertext, err := et.Encrypt(k, plaintext, &AESCFBModeOpts{})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		result, err := dt.Decrypt(k, ciphertext, &AESCFBModeOpts{})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if bytes.Compare(plaintext, result) != 0 {
			t.Fatalf("The original text should be equal to the decrypted text")
		}
	}
}

func TestAesEncryptOFB(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	key, _ := k.Bytes()
	fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESOFBModeOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesEncryptOFBWithIV(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	iv, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b00")
	plaintext := []byte("this is a test string. hello,world.")

	k := &aesKey{key}
	et := &aesEncrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &AESOFBModeOpts{IV: iv})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	// Output: cc8212ab1322a5d17ac9023ed0950b00e63198dc6740622867acde421e87e2200f1fe699392cc9564d5682e6184a3b83434fdc
}

func TestAesEncryptOFBWithPRNG(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")

	k := &aesKey{key}
	et := &aesEncrypter{}

	ciphertext, err := et.Encrypt(k, plaintext, &AESOFBModeOpts{PRNG: rand.Reader})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func TestAesDecryptOFB(t *testing.T) {
	key, _ := hex.DecodeString("189ddb371c528841e27fa6a9726dc214")
	plaintext := []byte("this is a test string. hello,world.")
	ciphertext, _ := hex.DecodeString("cc8212ab1322a5d17ac9023ed0950b00e63198dc6740622867acde421e87e2200f1fe699392cc9564d5682e6184a3b83434fdc")

	k := &aesKey{key}
	dt := &aesDecrypter{}

	result, err := dt.Decrypt(k, ciphertext, &AESOFBModeOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func TestAesOFB(t *testing.T) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")
	ciphertext, err := et.Encrypt(k, plaintext, &AESOFBModeOpts{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := dt.Decrypt(k, ciphertext, &AESOFBModeOpts{})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if bytes.Compare(plaintext, result) != 0 {
		t.Fatalf("The original text should be equal to the decrypted text")
	}
}

func BenchmarkAesOFB(t *testing.B) {
	kg := &aesKeyGenerator{}
	et := &aesEncrypter{}
	dt := &aesDecrypter{}

	k, err := kg.KeyGen(&AESKeyGenOpts{})
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	plaintext := []byte("when we are happy, we are always good, but when we are good, we are not always happy.")

	for i := 0; i < t.N; i++ {
		ciphertext, err := et.Encrypt(k, plaintext, &AESOFBModeOpts{})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		result, err := dt.Decrypt(k, ciphertext, &AESOFBModeOpts{})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if bytes.Compare(plaintext, result) != 0 {
			t.Fatalf("The original text should be equal to the decrypted text")
		}
	}
}
