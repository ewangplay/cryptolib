package cryptolib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	aesKeyDefaultLen = 16
)

type aesPrivateKey struct {
	privKey []byte
}

// Type returns the type of this key
func (k *aesPrivateKey) Type() string {
	return AES
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *aesPrivateKey) Bytes() (raw []byte, err error) {
	return k.privKey, nil
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *aesPrivateKey) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *aesPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *aesPrivateKey) PublicKey() (Key, error) {
	return nil, errors.New("Oh~, I'm a symmetric key.")
}

// getRandomBytes returns len random looking bytes
func getRandomBytes(len int) ([]byte, error) {
	if len <= 0 {
		return nil, errors.New("len must be larger than 0")
	}

	buf := make([]byte, len)
	n, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buf, nil
}

type aesKeyGenerator struct{}

// GenKey generates a key of aes algorithm
func (kg *aesKeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	len := aesKeyDefaultLen
	keyGenOpts := opts.(*AESKeyGenOpts)
	if keyGenOpts.Len > 0 {
		len = keyGenOpts.Len
	}

	key, err := getRandomBytes(len)
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", len, err)
	}

	return &aesPrivateKey{key}, nil
}

func pkcs7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func aesCBCEncrypt(key, s []byte) ([]byte, error) {
	return aesCBCEncryptWithRand(rand.Reader, key, s)
}

func aesCBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

func aesCBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	if len(IV) != aes.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	copy(ciphertext[:aes.BlockSize], IV)

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func AESCBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	tmp := pkcs7Padding(src)
	return aesCBCEncrypt(key, tmp)
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding using as prng the passed to the function
func AESCBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	tmp := pkcs7Padding(src)
	return aesCBCEncryptWithRand(prng, key, tmp)
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding, the IV used is the one passed to the function
func AESCBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	tmp := pkcs7Padding(src)
	return aesCBCEncryptWithIV(IV, key, tmp)
}

type aesEncrypter struct{}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesEncrypter) Encrypt(k Key, plaintext []byte, opts EnciphermentOpts) (ciphertext []byte, err error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return AESCBCPKCS7EncryptWithIV(o.IV, k.(*aesPrivateKey).privKey, plaintext)
		} else if o.PRNG != nil {
			// Encrypt with PRNG
			return AESCBCPKCS7EncryptWithRand(o.PRNG, k.(*aesPrivateKey).privKey, plaintext)
		}
		return AESCBCPKCS7Encrypt(k.(*aesPrivateKey).privKey, plaintext)
	default:
		return nil, fmt.Errorf("mode not recognized: %v", opts)
	}
}

func aesCBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

// AESCBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func AESCBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := aesCBCDecrypt(key, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

type aesDecrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesDecrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	switch opts.(type) {
	case *AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Decrypt(k.(*aesPrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("mode not recognized [%v]", opts)
	}
}
