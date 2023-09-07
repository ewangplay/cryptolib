package cryptolib

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	cc "github.com/ewangplay/crypto/cipher"
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

// sm4ECBEncryptWithIV performs SM4 ECB encryption.
func sm4ECBEncrypt(key, src []byte) ([]byte, error) {
	// ECB mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	mode := cc.NewECBEncrypter(block)
	mode.CryptBlocks(dst, src)

	return dst, nil
}

// sm4ECBPKCS7Encrypt combines ECB encryption and PKCS7 padding.
func sm4ECBPKCS7Encrypt(key, src []byte) ([]byte, error) {
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	tmp, err := padding.Pad(src)
	if err != nil {
		return nil, err
	}
	return sm4ECBEncrypt(key, tmp)
}

// sm4CFBEncrypt performs SM4 CFB encryption.
func sm4CFBEncrypt(key, s []byte) ([]byte, error) {
	return sm4CFBEncryptWithRand(rand.Reader, key, s)
}

// sm4CFBEncryptWithRand performs SM4 CFB encryption using the passed prng.
func sm4CFBEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	iv := make([]byte, sm4.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return sm4CFBEncryptWithIV(iv, key, s)
}

// sm4CFBEncryptWithIV performs SM4 CFB encryption using the IV.
func sm4CFBEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
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
	ciphertext := make([]byte, sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize], IV)

	stream := cipher.NewCFBEncrypter(block, IV)
	stream.XORKeyStream(ciphertext[sm4.BlockSize:], s)

	return ciphertext, nil
}

// sm4OFBEncrypt performs SM4 OFB encryption.
func sm4OFBEncrypt(key, s []byte) ([]byte, error) {
	return sm4OFBEncryptWithRand(rand.Reader, key, s)
}

// sm4OFBEncryptWithRand performs SM4 OFB encryption using the passed prng.
func sm4OFBEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	iv := make([]byte, sm4.BlockSize)
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}
	return sm4OFBEncryptWithIV(iv, key, s)
}

// sm4OFBEncryptWithIV performs SM4 OFB encryption using the IV.
func sm4OFBEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
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
	ciphertext := make([]byte, sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize], IV)

	stream := cipher.NewOFB(block, IV)
	stream.XORKeyStream(ciphertext[sm4.BlockSize:], s)

	return ciphertext, nil
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

	case *SM4ECBPKCS7PaddingOpts:
		return sm4ECBPKCS7Encrypt(k.(*sm4Key).key, plaintext)

	case *SM4CFBModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return sm4CFBEncryptWithIV(o.IV, k.(*sm4Key).key, plaintext)
		} else if o.PRNG != nil {
			return sm4CFBEncryptWithRand(o.PRNG, k.(*sm4Key).key, plaintext)
		}
		return sm4CFBEncrypt(k.(*sm4Key).key, plaintext)

	case *SM4OFBModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return sm4OFBEncryptWithIV(o.IV, k.(*sm4Key).key, plaintext)
		} else if o.PRNG != nil {
			return sm4OFBEncryptWithRand(o.PRNG, k.(*sm4Key).key, plaintext)
		}
		return sm4OFBEncrypt(k.(*sm4Key).key, plaintext)

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

// sm4ECBDecrypt performs SM4 ECB decryption.
func sm4ECBDecrypt(key, src []byte) ([]byte, error) {
	// ECB mode always works in whole blocks.
	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))
	mode := cc.NewECBDecrypter(block)
	mode.CryptBlocks(dst, src)

	return dst, nil
}

// sm4ECBPKCS7Decrypt combines ECB decryption and PKCS7 unpadding.
func sm4ECBPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := sm4ECBDecrypt(key, src)
	if err != nil {
		return nil, err
	}
	// Then unpadding
	padding := padding.NewPkcs7Padding(sm4.BlockSize)
	return padding.UnPad(pt)
}

// sm4CFBDecrypt performs SM4 CFB decryption.
func sm4CFBDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < sm4.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be larger size than the block size")
	}

	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(dst, src)

	return dst, nil
}

// sm4OFBDecrypt performs SM4 OFB decryption.
func sm4OFBDecrypt(key, src []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(src) < sm4.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be larger size than the block size")
	}

	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(dst, src)

	return dst, nil
}

type sm4Decrypter struct{}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (en *sm4Decrypter) Decrypt(k Key, ciphertext []byte, opts EnciphermentOpts) (plaintext []byte, err error) {
	switch opts.(type) {
	case *SM4CBCPKCS7PaddingOpts:
		// SM4 in CBC mode with PKCS7 padding
		return sm4CBCPKCS7Decrypt(k.(*sm4Key).key, ciphertext)
	case *SM4ECBPKCS7PaddingOpts:
		// SM4 in ECB mode with PKCS7 padding
		return sm4ECBPKCS7Decrypt(k.(*sm4Key).key, ciphertext)
	case *SM4CFBModeOpts:
		// SM4 in CFB mode
		return sm4CFBDecrypt(k.(*sm4Key).key, ciphertext)
	case *SM4OFBModeOpts:
		// SM4 in OFB mode
		return sm4OFBDecrypt(k.(*sm4Key).key, ciphertext)
	default:
		return nil, fmt.Errorf("mode not recognized [%v]", opts)
	}
}
