package wire

import (
	"bytes"
	"testing"
)

// Разборщики провода принимают байты от сети, то есть от кого угодно, и не
// имеют права падать ни на каком входе. Аудит 24.09.2026 прогнал через них
// 2,4 миллиона случайных входов без единой паники, этот тест закрепляет
// результат: локально go test гоняет только затравки, а в CI короткий
// фазз-прогон ищет новые входы.
func FuzzDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 3, 'a', 'b', 'c'})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{1}, 100)...))
	key := bytes.Repeat([]byte{7}, 32)
	f.Fuzz(func(_ *testing.T, p []byte) {
		_, _ = DecodeMsg1(p)
		_, _ = DecodeMsg2(p)
		_, _ = DecodeMsg3(p)
		_, _ = DecodeRotationV2(p, key)
		_, _ = DecodeRotationAck(p, key)
		_, _, _ = DecodeData(p)
		_, _ = DecodeFirmwareChallenge(p)
		_, _ = DecodeFirmwareResponse(p)
		_, _, _ = ReadFrame(bytes.NewReader(p))
	})
}
