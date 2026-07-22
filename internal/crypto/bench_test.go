package crypto

import "testing"

func BenchmarkGenerateKEMKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKEMKeyPair(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	kp, err := GenerateKEMKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Encapsulate(kp.Pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	kp, err := GenerateKEMKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	ct, _, err := Encapsulate(kp.Pub)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decapsulate(kp.Priv, ct); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignECDSAP256(b *testing.B) {
	id, err := GenerateIdentity(SigECDSAP256)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark-confirmation-value-32-bytes-long-xx")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := id.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignSLHDSA(b *testing.B) {
	id, err := GenerateIdentity(SigSLHDSA)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark-confirmation-value-32-bytes-long-xx")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := id.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyECDSAP256(b *testing.B) {
	id, err := GenerateIdentity(SigECDSAP256)
	if err != nil {
		b.Fatal(err)
	}
	pub, _ := id.PublicKeyBytes()
	msg := []byte("benchmark-confirmation-value-32-bytes-long-xx")
	sig, err := id.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifySignature(SigECDSAP256, pub, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySLHDSA(b *testing.B) {
	id, err := GenerateIdentity(SigSLHDSA)
	if err != nil {
		b.Fatal(err)
	}
	pub, _ := id.PublicKeyBytes()
	msg := []byte("benchmark-confirmation-value-32-bytes-long-xx")
	sig, err := id.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifySignature(SigSLHDSA, pub, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFullHandshakeECDSA измеряет время ПОЛНОГО рукопожатия (Msg1+Msg2+Msg3+Finalize)
// с ECDSA P-256 как identity-алгоритмом — это то, что описано как основной
// вариант в UML-диаграмме работы.
func BenchmarkFullHandshakeECDSA(b *testing.B) {
	benchmarkFullHandshake(b, SigECDSAP256)
}

// BenchmarkFullHandshakeSLHDSA — то же самое, но с SLH-DSA вместо ECDSA —
// вариант алгоритма LACERT, описанный как "убрать матричные операции из
// критического пути". Сравнение с предыдущим бенчмарком прямо показывает
// цену этой замены в данном прототипе.
func BenchmarkFullHandshakeSLHDSA(b *testing.B) {
	benchmarkFullHandshake(b, SigSLHDSA)
}

func benchmarkFullHandshake(b *testing.B, alg SigAlgorithm) {
	devIdentity, err := GenerateIdentity(alg)
	if err != nil {
		b.Fatal(err)
	}
	devIdentityPub, err := devIdentity.PublicKeyBytes()
	if err != nil {
		b.Fatal(err)
	}
	devKEM, err := GenerateKEMKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg1, err := NewHandshakeMsg1("bench-device", devIdentityPub)
		if err != nil {
			b.Fatal(err)
		}
		msg2, gwSecret, err := BuildMsg2(devKEM.Pub)
		if err != nil {
			b.Fatal(err)
		}
		msg3, _, err := BuildMsg3(devKEM.Priv, devIdentity, msg1, msg2)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := FinalizeHandshake(devIdentityPub, alg, msg1, msg2, msg3, gwSecret); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRotationStep измеряет время одной ротации ключа (инициатор + ответчик).
func BenchmarkRotationStep(b *testing.B) {
	devKEM, err := GenerateKEMKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	session, err := NewSession(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	peerSession, err := NewSession(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, err := InitiateRotation(peerSession, devKEM.Pub)
		if err != nil {
			b.Fatal(err)
		}
		if err := RespondToRotation(session, devKEM.Priv, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptPacket(b *testing.B) {
	var key [32]byte
	plaintext := make([]byte, MaxPayloadSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := EncryptPacket(key, uint32(i), plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Ed25519 ────────────────────────────────────────────────────────────────
// Добавлено по результатам замеров на микроконтроллере: ECDSA P-256 оказалась
// самой дорогой операцией протокола на ESP32-S3 (~173 мс), дороже постквантовой
// декапсуляции ML-KEM. Ed25519 проверяется как более быстрая замена.

func BenchmarkSignEd25519(b *testing.B) {
	id, err := GenerateIdentity(SigEd25519)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark-confirmation-value-32-bytes-long-xx")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := id.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEd25519(b *testing.B) {
	id, err := GenerateIdentity(SigEd25519)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark-confirmation-value-32-bytes-long-xx")
	sig, err := id.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	pub, err := id.PublicKeyBytes()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := VerifySignature(SigEd25519, pub, msg, sig)
		if err != nil || !ok {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkGenerateIdentityEd25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateIdentity(SigEd25519); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateIdentityECDSAP256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateIdentity(SigECDSAP256); err != nil {
			b.Fatal(err)
		}
	}
}
