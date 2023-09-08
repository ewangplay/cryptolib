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

// aesCFBEncrypt performs AES CFB encryption.
func aesCFBEncrypt(key, s []byte) ([]byte, error) {
	return aesCFBEncryptWithRand(rand.Reader, key, s)
}

// aesCFBEncryptWithRand performs AES CFB encryption using the passed prng.
func aesCFBEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return aesCFBEncryptWithIV(iv, key, s)
}

// aesCFBEncryptWithIV performs AES CFB encryption using the IV.
func aesCFBEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
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

	stream := cipher.NewCFBEncrypter(block, IV)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

// aesOFBEncrypt performs AES OFB encryption.
func aesOFBEncrypt(key, s []byte) ([]byte, error) {
	return aesOFBEncryptWithRand(rand.Reader, key, s)
}

// aesOFBEncryptWithRand performs AES OFB encryption using the passed prng.
func aesOFBEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return aesOFBEncryptWithIV(iv, key, s)
}

// aesOFBEncryptWithIV performs AES OFB encryption using the IV.
func aesOFBEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
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

	stream := cipher.NewOFB(block, IV)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

// aesCTREncrypt performs AES CTR encryption.
func aesCTREncrypt(key, s []byte) ([]byte, error) {
	return aesCTREncryptWithRand(rand.Reader, key, s)
}

// aesCTREncryptWithRand performs AES CTR encryption using the passed prng.
func aesCTREncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return aesCTREncryptWithIV(iv, key, s)
}

// aesCTREncryptWithIV performs AES CTR encryption using the IV.
func aesCTREncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
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

	stream := cipher.NewCTR(block, IV)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

// aesGCMEncrypt performs AES GCM encryption.
func aesGCMEncrypt(key, plaintext, nonce, additionalData []byte) ([]byte, error) {
	// The Nonce's length must be equal to 12
	if len(nonce) != 12 {
		return nil, errors.New("Invalid nonce. It must have length 12 size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

type aesEncrypter struct{}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesEncrypter) Encrypt(k Key, plaintext []byte, opts EnciphermentOpts) (ciphertext []byte, err error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7PaddingOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return aesCBCPKCS7EncryptWithIV(o.IV, k.(*aesKey).key, plaintext)
		} else if o.PRNG != nil {
			return aesCBCPKCS7EncryptWithRand(o.PRNG, k.(*aesKey).key, plaintext)
		}
		return aesCBCPKCS7Encrypt(k.(*aesKey).key, plaintext)

	case *AESECBPKCS7PaddingOpts:
		return aesECBPKCS7Encrypt(k.(*aesKey).key, plaintext)

	case *AESCFBModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return aesCFBEncryptWithIV(o.IV, k.(*aesKey).key, plaintext)
		} else if o.PRNG != nil {
			return aesCFBEncryptWithRand(o.PRNG, k.(*aesKey).key, plaintext)
		}
		return aesCFBEncrypt(k.(*aesKey).key, plaintext)

	case *AESOFBModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return aesOFBEncryptWithIV(o.IV, k.(*aesKey).key, plaintext)
		} else if o.PRNG != nil {
			return aesOFBEncryptWithRand(o.PRNG, k.(*aesKey).key, plaintext)
		}
		return aesOFBEncrypt(k.(*aesKey).key, plaintext)

	case *AESCTRModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return aesCTREncryptWithIV(o.IV, k.(*aesKey).key, plaintext)
		} else if o.PRNG != nil {
			return aesCTREncryptWithRand(o.PRNG, k.(*aesKey).key, plaintext)
		}
		return aesCTREncrypt(k.(*aesKey).key, plaintext)

	case *AESGCMModeOpts:
		if len(o.Nonce) == 0 {
			return nil, errors.New("Invalid nonce. The nonce lenght must be 12 size.")
		}
		return aesGCMEncrypt(k.(*aesKey).key, plaintext, o.Nonce, o.AdditionalData)

	default:
		return nil, fmt.Errorf("mode not recognized: %v", opts)
	}
}

// aesCBCDecrypt performs AES CBC decryption.
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

// aesECBDecrypt performs AES ECB decryption.
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

// aesCFBDecrypt performs AES CFB decryption.
func aesCFBDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be larger size than the block size")
	}

	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(dst, src)

	return dst, nil
}

// aesOFBDecrypt performs AES OFB decryption.
func aesOFBDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be larger size than the block size")
	}

	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(dst, src)

	return dst, nil
}

// aesCTRDecrypt performs AES CTR decryption.
func aesCTRDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be larger size than the block size")
	}

	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)

	return dst, nil
}

// aesGCMDecrypt performs AES GCM decryption.
func aesGCMDecrypt(key, ciphertext, nonce, additionalData []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dst, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

type aesDecrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *aesDecrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7PaddingOpts:
		// AES in CBC mode with PKCS7 padding
		return aesCBCPKCS7Decrypt(k.(*aesKey).key, ciphertext)

	case *AESECBPKCS7PaddingOpts:
		// AES in ECB mode with PKCS7 padding
		return aesECBPKCS7Decrypt(k.(*aesKey).key, ciphertext)

	case *AESCFBModeOpts:
		// AES in CFB mode
		return aesCFBDecrypt(k.(*aesKey).key, ciphertext)

	case *AESOFBModeOpts:
		// AES in OFB mode
		return aesOFBDecrypt(k.(*aesKey).key, ciphertext)

	case *AESCTRModeOpts:
		// AES in CTR mode
		return aesCTRDecrypt(k.(*aesKey).key, ciphertext)

	case *AESGCMModeOpts:
		// AES in GCM mode
		if len(o.Nonce) == 0 {
			return nil, errors.New("Invalid nonce. The nonce lenght must be 12 size.")
		}
		return aesGCMDecrypt(k.(*aesKey).key, ciphertext, o.Nonce, o.AdditionalData)

	default:
		return nil, fmt.Errorf("mode not recognized [%v]", opts)
	}
}
