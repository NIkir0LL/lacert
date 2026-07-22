package crypto

import "testing"

func TestEd25519RoundTrip(t *testing.T) {
	id, err := GenerateIdentity(SigEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if id.Algorithm.String() != "Ed25519" {
		t.Fatalf("имя алгоритма: %s", id.Algorithm)
	}
	pub, err := id.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Fatalf("размер открытого ключа %d, ожидалось 32", len(pub))
	}
	msg := []byte("проверка целостности прошивки")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("размер подписи %d, ожидалось 64", len(sig))
	}
	ok, err := VerifySignature(SigEd25519, pub, msg, sig)
	if err != nil || !ok {
		t.Fatal("подпись не прошла проверку")
	}
	// подделка сообщения должна отвергаться
	ok, _ = VerifySignature(SigEd25519, pub, []byte("подменённое"), sig)
	if ok {
		t.Fatal("подделка принята — ошибка")
	}
}
