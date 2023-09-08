package cryptolib

import (
	"crypto"
	"crypto/elliptic"
	"hash"
	"io"
)

const (
	// ED25519 signatures are elliptic-curve signatures,
	// carefully engineered at several levels of design
	// and implementation to achieve very high speeds
	// without compromising security.
	ED25519 = "ED25519"

	// ECDSA is the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.
	ECDSA = "ECDSA"

	// RSA algorithm family.
	RSA = "RSA"

	// PKCS1V15 is the version 1 of RSA signature algorithm.
	PKCS1V15 = "PKCS1V15"

	// PSS is the version 2 of RSA signature algorithm, the Probabilistic Signature Scheme.
	PSS = "PSS"

	// OAEP is the version 2 of RSA encipherment algorithm, the Optimal Asymmetric Encryption Paddinga Scheme.
	OAEP = "OAEP"

	// SHA256 hash algorithm
	SHA256 = "SHA256"

	// SHA384 hash algorithm
	SHA384 = "SHA384"

	// SHA512 hash algorithm
	SHA512 = "SHA512"

	// SM3 hash algorithm
	SM3 = "SM3"

	// AES Advanced Encryption Standard
	AES = "AES"

	// SM2 国密椭圆曲线算法
	SM2 = "SM2"

	// SM4 国密分组密码算法
	SM4 = "SM4"
)

// ED25519KeyGenOpts contains options for ED25519 key generation.
type ED25519KeyGenOpts struct {
}

// Algorithm returns the key generation algorithm identifier for ED25519.
func (opts *ED25519KeyGenOpts) Algorithm() string {
	return ED25519
}

// ECDSAKeyGenOpts contains options for ECDSA key generation.
// Curve can be elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521().
type ECDSAKeyGenOpts struct {
	Curve elliptic.Curve
}

// Algorithm returns the key generation algorithm identifier for ECDSA.
func (opts *ECDSAKeyGenOpts) Algorithm() string {
	return ECDSA
}

// RSAKeyGenOpts contains options for RSA key generation.
// Notice that Bits is the key length in bits, it can only be
// 1024 or 2048 or 3072 or 4096.
type RSAKeyGenOpts struct {
	Bits int
}

// Algorithm returns the key generation algorithm identifier for RSA.
func (opts *RSAKeyGenOpts) Algorithm() string {
	return RSA
}

// AESKeyGenOpts contains options for AES key generation.
// Notice that Len is the key length in bytes, it can only be
// 16(128 bits) or 24(192 bits) or 32(256 bits).
type AESKeyGenOpts struct {
	Len int
}

// Algorithm returns the key generation algorithm identifier for AES.
func (opts *AESKeyGenOpts) Algorithm() string {
	return AES
}

// SM2KeyGenOpts contains options for SM2 key generation.
type SM2KeyGenOpts struct {
}

// Algorithm returns the key generation algorithm identifier for SM2.
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// SM4KeyGenOpts contains options for SM4 key generation.
type SM4KeyGenOpts struct {
}

// Algorithm returns the key generation algorithm identifier for SM4.
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

// SHA256Opts contains options relating to SHA-256.
type SHA256Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA256Opts) Algorithm() string {
	return SHA256
}

// SHA384Opts contains options relating to SHA-384.
type SHA384Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA384Opts) Algorithm() string {
	return SHA384
}

// SHA512Opts contains options relating to SHA-512.
type SHA512Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHA512Opts) Algorithm() string {
	return SHA512
}

// SM3Opts contains options relating to SM3
type SM3Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SM3Opts) Algorithm() string {
	return SM3
}

// RSASignatureOpts contains options relating to PSS signing algorithm.
type RSASignatureOpts struct {
	// PKCS1V15 or PSS
	Schema string
	Hash   crypto.Hash
}

// Algorithm returns the RSA algorithm identifier (to be used).
func (opts *RSASignatureOpts) Algorithm() string {
	return RSA
}

// RSAEnciphermentOpts contains options relating to RSA encryption algorithm.
type RSAEnciphermentOpts struct {
	// PKCS1V15 or OAEP
	Schema string
	Hash   hash.Hash

	// The label parameter may contain arbitrary data that will not be encrypted,
	//  but which gives important context to the message. For example, if a given
	//  public key is used to encrypt two types of messages then distinct label
	//  values could be used to ensure that a ciphertext for one purpose cannot
	//  be used for another by an attacker. If not required it can be empty.
	Label string
}

// Algorithm returns the RSA algorithm identifier (to be used).
func (opts *RSAEnciphermentOpts) Algorithm() string {
	return RSA
}

// AESCBCPKCS7PaddingOpts contains options for AES encryption in CBC mode
// with PKCS7 padding.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type AESCBCPKCS7PaddingOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the AES algorithm identifier (to be used).
func (opts *AESCBCPKCS7PaddingOpts) Algorithm() string {
	return AES
}

// AESECBPKCS7PaddingOpts contains options for AES encryption in ECB mode
// with PKCS7 padding.
type AESECBPKCS7PaddingOpts struct{}

// Algorithm returns the AES algorithm identifier (to be used).
func (opts *AESECBPKCS7PaddingOpts) Algorithm() string {
	return AES
}

// AESCFBModeOpts contains options for AES encryption in CFB mode.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type AESCFBModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the AES algorithm identifier (to be used).
func (opts *AESCFBModeOpts) Algorithm() string {
	return AES
}

// AESOFBModeOpts contains options for AES encryption in OFB mode.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type AESOFBModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the AES algorithm identifier (to be used).
func (opts *AESOFBModeOpts) Algorithm() string {
	return AES
}

// AESCTRModeOpts contains options for AES encryption in CTR mode.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type AESCTRModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the AES algorithm identifier (to be used).
func (opts *AESCTRModeOpts) Algorithm() string {
	return AES
}

// SM4CBCPKCS7PaddingOpts contains options for SM4 encryption in CBC mode
// with PKCS7 padding.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type SM4CBCPKCS7PaddingOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the SM4 algorithm identifier (to be used).
func (opts *SM4CBCPKCS7PaddingOpts) Algorithm() string {
	return SM4
}

// SM4ECBPKCS7PaddingOpts contains options for SM4 encryption in ECB mode
// with PKCS7 padding.
type SM4ECBPKCS7PaddingOpts struct{}

// Algorithm returns the SM4 algorithm identifier (to be used).
func (opts *SM4ECBPKCS7PaddingOpts) Algorithm() string {
	return SM4
}

// SM4CFBModeOpts contains options for SM4 encryption in CFB mode.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type SM4CFBModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the SM4 algorithm identifier (to be used).
func (opts *SM4CFBModeOpts) Algorithm() string {
	return SM4
}

// SM4OFBModeOpts contains options for SM4 encryption in OFB mode.
//  1. Both IV and PRNG can be nil. In that case, the implementation
//     is supposed to sample the IV using a cryptographic secure PRNG.
//  2. Either IV or PRNG can be different from nil.
type SM4OFBModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

// Algorithm returns the SM4 algorithm identifier (to be used).
func (opts *SM4OFBModeOpts) Algorithm() string {
	return SM4
}
