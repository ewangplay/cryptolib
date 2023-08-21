package cryptolib

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/ewangplay/crypto/padding"
	"github.com/ewangplay/crypto/sm4"
)

type sm4Key struct {
	key []byte
}

// Type returns the type of this key
func (k *sm4Key) Type() string {
	return SM4
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm4Key) Bytes() (raw []byte, err error) {
	return k.key, nil
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm4Key) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm4Key) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm4Key) PublicKey() (Key, error) {
	return nil, errors.New("Oh~, I'm a symmetric key.")
}

type sm4KeyGenerator struct{}

// GenKey generates a key of sm4 algorithm
func (kg *sm4KeyGenerator) KeyGen(opts KeyGenOpts) (Key, error) {
	len := sm4.BlockSize
	key, err := getRandomBytes(len)
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm4 %d key [%s]", len, err)
	}

	return &sm4Key{key}, nil
}

// sm4CBCEncrypt performs SM4 CBC encryption.
func sm4CBCEncrypt(key, src []byte) ([]byte, error) {
	return sm4CBCEncryptWithRand(rand.Reader, key, src)
}

// sm4CBCEncryptWithRand performs SM4 CBC encryption using the passed prng.
func sm4CBCEncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	iv := make([]byte, sm4.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return sm4CBCEncryptWithIV(iv, key, src)
}

// sm4CBCEncryptWithIV performs SM4 CBC encryption using the IV.
func sm4CBCEncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	// The IV's length must be equal to Block size.
	if len(IV) != sm4.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, sm4.BlockSize+len(src))
	copy(ciphertext[:sm4.BlockSize], IV)

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:], src)

	return ciphertext, nil
}

// sm4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding.
func sm4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return sm4CBCEncrypt(key, tmp)
}

// sm4CBCPKCS7EncryptWithRand combines CBC encryption and PKCS7 padding using the passed prng.
func sm4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return sm4CBCEncryptWithRand(prng, key, tmp)
}

// sm4CBCPKCS7EncryptWithIV combines CBC encryption and PKCS7 padding using the passed IV.
func sm4CBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return sm4CBCEncryptWithIV(IV, key, tmp)
}

type sm4Encrypter struct{}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *sm4Encrypter) Encrypt(k Key, plaintext []byte, opts EnciphermentOpts) (ciphertext []byte, err error) {
	switch o := opts.(type) {
	case *SM4CBCPKCS7PaddingOpts:
		// SM4 in CBC mode with PKCS7 padding
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return sm4CBCPKCS7EncryptWithIV(o.IV, k.(*sm4Key).key, plaintext)
		} else if o.PRNG != nil {
			// Encrypt with PRNG
			return sm4CBCPKCS7EncryptWithRand(o.PRNG, k.(*sm4Key).key, plaintext)
		}
		return sm4CBCPKCS7Encrypt(k.(*sm4Key).key, plaintext)
	default:
		return nil, fmt.Errorf("mode not recognized: %v", opts)
	}
}

// sm4CBCDecrypt performs SM4 CBC decryption.
func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < sm4.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(src, src)

	return src, nil
}

// sm4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding.
func sm4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := sm4CBCDecrypt(key, src)
	if err != nil {
		return nil, err
	}
	// Then unpadding
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	return padding.UnPad(pt)
}

type sm4Decrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *sm4Decrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	switch opts.(type) {
	case *SM4CBCPKCS7PaddingOpts:
		// SM4 in CBC mode with PKCS7 padding
		return sm4CBCPKCS7Decrypt(k.(*sm4Key).key, ciphertext)
	default:
		return nil, fmt.Errorf("mode not recognized [%v]", opts)
	}
}
