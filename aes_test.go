package cryptolib

import "testing"

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
