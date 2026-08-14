package wire

import (
	"bytes"
	"math/rand"
	"testing"

	"lacert/internal/crypto"
)

func testKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// Кадр, собранный одним ключом, должен разбираться тем же ключом.
func TestRotationFramesRoundTrip(t *testing.T) {
	key := testKey(0x42)

	msg := &crypto.RotationMsgV2{Iteration: 7, KEMCiphertext: []byte("шифротекст обмена")}
	got, err := DecodeRotationV2(EncodeRotationV2(msg, key), key)
	if err != nil {
		t.Fatalf("разбор кадра ротации: %v", err)
	}
	if got.Iteration != msg.Iteration || !bytes.Equal(got.KEMCiphertext, msg.KEMCiphertext) {
		t.Errorf("кадр ротации исказился: %+v против %+v", got, msg)
	}

	ack := &crypto.RotationAck{Iteration: 7}
	gotAck, err := DecodeRotationAck(EncodeRotationAck(ack, key), key)
	if err != nil {
		t.Fatalf("разбор подтверждения: %v", err)
	}
	if gotAck.Iteration != ack.Iteration {
		t.Errorf("номер шага исказился: %d против %d", gotAck.Iteration, ack.Iteration)
	}
}

// Главное, ради чего метка добавлена: кадр от того, кто не знает сеансового
// ключа, должен отвергаться. Прежде вброшенное подтверждение шлюз принимал,
// применял ротацию, и ключи расходились с устройством.
func TestControlFramesRejectWrongKey(t *testing.T) {
	real := testKey(0x42)
	attacker := testKey(0x99)

	ack := EncodeRotationAck(&crypto.RotationAck{Iteration: 3}, attacker)
	if _, err := DecodeRotationAck(ack, real); err == nil {
		t.Error("подтверждение с чужим ключом должно отвергаться")
	}

	rot := EncodeRotationV2(&crypto.RotationMsgV2{Iteration: 3, KEMCiphertext: []byte("ct")}, attacker)
	if _, err := DecodeRotationV2(rot, real); err == nil {
		t.Error("кадр ротации с чужим ключом должен отвергаться")
	}
}

// Кадр без метки — это кадр прежней версии протокола. Он должен отвергаться,
// а не разбираться как есть.
func TestControlFramesRejectMissingTag(t *testing.T) {
	key := testKey(0x42)

	// Так выглядело подтверждение до добавления метки: восемь байт
	// номера шага и ничего больше.
	oldStyle := []byte{0, 0, 0, 0, 0, 0, 0, 3}
	if _, err := DecodeRotationAck(oldStyle, key); err == nil {
		t.Error("подтверждение без метки должно отвергаться")
	}
}

// Подмена содержимого при сохранённой метке должна отвергаться.
func TestControlTagCoversBody(t *testing.T) {
	key := testKey(0x42)
	frame := EncodeRotationAck(&crypto.RotationAck{Iteration: 5}, key)

	tampered := append([]byte(nil), frame...)
	tampered[7] = 6 // номер шага 5 → 6, метка прежняя

	if _, err := DecodeRotationAck(tampered, key); err == nil {
		t.Error("подмена номера шага должна отвергаться")
	}
}

// Метку от одного типа кадра нельзя переставить на другой: в неё входит тип.
func TestControlTagBoundToFrameType(t *testing.T) {
	key := testKey(0x42)
	const iteration = 4

	body := []byte{0, 0, 0, 0, 0, 0, 0, iteration}
	// Метка, посчитанная как для подтверждения, приставлена к кадру ротации.
	wrongTag := crypto.ComputeControlTag(key, TypeRotationAck, iteration, body)

	if err := crypto.VerifyControlTag(key, TypeRotationV2, iteration, body, wrongTag); err == nil {
		t.Error("метка от одного типа кадра не должна подходить другому")
	}
}

// Метку от одного шага ротации нельзя переставить на другой.
func TestControlTagBoundToIteration(t *testing.T) {
	key := testKey(0x42)
	body := []byte("одинаковое содержимое")

	tag := crypto.ComputeControlTag(key, TypeRotationAck, 1, body)
	if err := crypto.VerifyControlTag(key, TypeRotationAck, 2, body, tag); err == nil {
		t.Error("метка от одного шага не должна подходить другому")
	}
}

// Метка неверной длины отвергается, а не приводит к обращению за границу
// среза.
func TestControlTagRejectsWrongSize(t *testing.T) {
	key := testKey(0x42)
	body := []byte("тело")
	full := crypto.ComputeControlTag(key, TypeRotationAck, 1, body)

	for name, tag := range map[string][]byte{
		"пустая":   {},
		"короткая": full[:crypto.ControlTagSize-1],
		"длинная":  append(append([]byte(nil), full...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if err := crypto.VerifyControlTag(key, TypeRotationAck, 1, body, tag); err == nil {
				t.Error("метка неверной длины должна отвергаться")
			}
		})
	}
}

// Разбор служебного кадра не должен падать ни на каком входе.
//
// Кадр приходит из сети, и обращение за границу среза уронило бы шлюз целиком
// вместе со всеми подключёнными устройствами. Проверка длины стоит до
// обращения к данным, и этот тест следит, чтобы так и осталось.
func TestDecodeControlFramesNeverPanics(t *testing.T) {
	key := make([]byte, 32)
	r := rand.New(rand.NewSource(1))

	for i := 0; i < 20000; i++ {
		buf := make([]byte, r.Intn(80))
		r.Read(buf)

		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("паника при разборе %d байт: %v", len(buf), p)
				}
			}()
			_, _ = DecodeRotationAck(buf, key)
			_, _ = DecodeRotationV2(buf, key)
		}()
	}
}
