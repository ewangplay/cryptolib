package cryptolib

import "testing"

func TestSm2KeyGen(t *testing.T) {
	kg := &sm2KeyGenerator{}
	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	if k.Type() != SM2 {
		t.Fatalf("k should be SM2 key")
	}
	if k.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if !k.Private() {
		t.Fatalf("k should be private key")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Get PublicKey failed: %v", err)
	}
	if pk.Type() != SM2 {
		t.Fatalf("k should be SM2 key")
	}
	if pk.Symmetric() {
		t.Fatalf("k should not be symmetric key")
	}
	if pk.Private() {
		t.Fatalf("pk should not be private key")
	}
}
