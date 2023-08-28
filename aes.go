package cryptolib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	cc "github.com/ewangplay/crypto/cipher"
	"github.com/ewangplay/crypto/padding"
)

const (
	aesKeyDefaultLen = 16
)

type aesKey struct {
	key []byte
}

// Type returns the type of this key
func (k *aesKey) Type() string {
	return AES
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *aesKey) Bytes() (raw []byte, err error) {
	return k.key, nil
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *aesKey) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *aesKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *aesKey) PublicKey() (Key, error) {
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

	return &aesKey{key}, nil
}

// aesCBCEncrypt performs AES CBC encryption.
func aesCBCEncrypt(key, s []byte) ([]byte, error) {
	return aesCBCEncryptWithRand(rand.Reader, key, s)
}

// aesCBCEncryptWithRand performs AES CBC encryption using the passed prng.
func aesCBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return aesCBCEncryptWithIV(iv, key, s)
}

// aesCBCEncryptWithIV performs AES CBC encryption using the IV.
func aesCBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	// The IV's length must be equal to Block size.
	if len(IV) != aes.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(s))
	copy(ciphertext[:aes.BlockSize], IV)

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

// aesCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding.
func aesCBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(aes.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return aesCBCEncrypt(key, tmp)
}

// aesCBCPKCS7EncryptWithRand combines CBC encryption and PKCS7 padding using the passed prng.
func aesCBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(aes.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return aesCBCEncryptWithRand(prng, key, tmp)
}

// aesCBCPKCS7EncryptWithIV combines CBC encryption and PKCS7 padding using the passed IV.
func aesCBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(aes.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return aesCBCEncryptWithIV(IV, key, tmp)
}

// aesECBEncrypt performs AES ECB encryption.
func aesECBEncrypt(key, s []byte) ([]byte, error) {
	// ECB mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(s))

	mode := cc.NewECBEncrypter(block)
	mode.CryptBlocks(ciphertext, s)

	return ciphertext, nil
}

// aesECBPKCS7Encrypt combines ECB encryption and PKCS7 padding.
func aesECBPKCS7Encrypt(key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(aes.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return aesECBEncrypt(key, tmp)
}

type aesEncrypter struct{}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesEncrypter) Encrypt(k Key, plaintext []byte, opts EnciphermentOpts) (ciphertext []byte, err error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7PaddingOpts:
		// AES in CBC mode with PKCS7 padding
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return aesCBCPKCS7EncryptWithIV(o.IV, k.(*aesKey).key, plaintext)
		} else if o.PRNG != nil {
			// Encrypt with PRNG
			return aesCBCPKCS7EncryptWithRand(o.PRNG, k.(*aesKey).key, plaintext)
		}
		return aesCBCPKCS7Encrypt(k.(*aesKey).key, plaintext)

	case *AESECBPKCS7PaddingOpts:
		return aesECBPKCS7Encrypt(k.(*aesKey).key, plaintext)

	default:
		return nil, fmt.Errorf("mode not recognized: %v", opts)
	}
}

// aesCBCDecrypt performs SM4 CBC decryption.
func aesCBCDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(src, src)

	return src, nil
}

// aesCBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding.
func aesCBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := aesCBCDecrypt(key, src)
	if err != nil {
		return nil, err
	}

	// Then unpadding
	padding := padding.NewPkcs7Padding(aes.BlockSize)
	return padding.UnPad(pt)
}

// aesECBDecrypt performs SM4 ECB decryption.
func aesECBDecrypt(key, src []byte) ([]byte, error) {
	// ECB mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	mode := cc.NewECBDecrypter(block)
	mode.CryptBlocks(dst, src)

	return dst, nil
}

// aesECBPKCS7Decrypt combines ECB decryption and PKCS7 unpadding.
func aesECBPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := aesECBDecrypt(key, src)
	if err != nil {
		return nil, err
	}

	// Then unpadding
	padding := padding.NewPkcs7Padding(aes.BlockSize)
	return padding.UnPad(pt)
}

type aesDecrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesDecrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	switch opts.(type) {
	case *AESCBCPKCS7PaddingOpts:
		// AES in CBC mode with PKCS7 padding
		return aesCBCPKCS7Decrypt(k.(*aesKey).key, ciphertext)

	case *AESECBPKCS7PaddingOpts:
		// AES in ECB mode with PKCS7 padding
		return aesECBPKCS7Decrypt(k.(*aesKey).key, ciphertext)

	default:
		return nil, fmt.Errorf("mode not recognized [%v]", opts)
	}
}
