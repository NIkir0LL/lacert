package wire

import (
	"testing"

	"lacert/internal/crypto"
)

// Тот же опыт, что выявил уязвимость, но на уровне кадров: посторонний знает
// номер шага (подсмотрел в проходящем кадре), но не знает сеансового ключа.
//
// До добавления метки подтверждение состояло из восьми байт номера
// шага, и такой вброс проходил: шлюз применял ротацию, устройство нет, ключи
// расходились и устройство отзывалось.
func TestForgedAckIsRejectedWithoutSessionKey(t *testing.T) {
	sessionKey := testKey(0x11)
	const observedIteration = 5

	// Всё, что есть у постороннего: номер шага. Ключа у него нет.
	forged := make([]byte, 8, 8+crypto.ControlTagSize)
	forged[7] = observedIteration
	// Метку он поставить не может, поэтому пробует наугад.
	forged = append(forged, make([]byte, crypto.ControlTagSize)...)

	if _, err := DecodeRotationAck(forged, sessionKey); err == nil {
		t.Fatal("вброшенное подтверждение принято — защита не работает")
	}

	// А настоящее устройство, знающее ключ, подтверждение отправит.
	real := EncodeRotationAck(&crypto.RotationAck{Iteration: observedIteration}, sessionKey)
	got, err := DecodeRotationAck(real, sessionKey)
	if err != nil {
		t.Fatalf("настоящее подтверждение должно приниматься: %v", err)
	}
	if got.Iteration != observedIteration {
		t.Errorf("номер шага исказился: %d", got.Iteration)
	}
}
