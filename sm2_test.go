package cryptolib

import "testing"

func TestSm2KeyGenerator(t *testing.T) {
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

func TestSm2Signer(t *testing.T) {
	kg := &sm2KeyGenerator{}
	signer := &sm2Signer{}

	k, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	_, err = signer.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
}

func TestSm2Verifier(t *testing.T) {
	kg := &sm2KeyGenerator{}
	signer := &sm2Signer{}
	verifier := &sm2Verifier{}

	privKey, err := kg.KeyGen(nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	digest := []byte("hello,world")
	signature, err := signer.Sign(privKey, digest, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey, _ := privKey.PublicKey()
	valid, err := verifier.Verify(pubKey, digest, signature, nil)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatalf("The signature should be validated")
	}
}
