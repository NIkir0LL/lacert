package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Эталонные значения, сверенные с реализацией прошивки на C.
//
// Метка вычисляется на двух языках независимо, и разойдись они хоть в одном
// байте — устройства перестали бы подключаться, а причину пришлось бы искать
// на плате. Поэтому значения зафиксированы здесь: если кто-то изменит порядок
// частей, разделитель или длину метки в одной из реализаций, тест это поймает.
//
// Как получены: та же логика собрана отдельной программой на C с настоящим
// BLAKE3 версии 1.5.4 и запущена на тех же входных данных.
func TestControlTagMatchesFirmwareReference(t *testing.T) {
	cases := []struct {
		name      string
		key       byte // значение, которым заполняется ключ; 0 означает 0x42
		frameType byte
		iteration uint64
		body      []byte
		want      string
	}{
		{
			name:      "подтверждение ротации, шаг 7",
			frameType: 10, // TypeRotationAck
			iteration: 7,
			body:      []byte{0, 0, 0, 0, 0, 0, 0, 7},
			want:      "c43fdfa42fee126a030554e1c5349d87",
		},
		{
			// Краевой случай: пустое тело и нулевой шаг. Проверяет, что ни
			// одна из реализаций не добавляет от себя лишних байт.
			name:      "пустое тело, нулевой шаг, ключ из нулей",
			key:       0x00,
			frameType: 9,
			iteration: 0,
			body:      []byte{},
			want:      "d486a42af4333f37ef29f70325bd5e2d",
		},
		{
			// Предельный номер шага: проверяет запись восьми байт в сетевом
			// порядке на обеих сторонах.
			name:      "предельный номер шага",
			key:       0xff,
			frameType: 10,
			iteration: 18446744073709551615,
			body:      []byte("x"),
			want:      "ef528085402527d56a642df793a932cc",
		},
		{
			// Тело длиннее блока BLAKE3: проверяет, что многоблочная обработка
			// совпадает. У прошивки своя сборка библиотеки, и разойтись они
			// могли бы именно здесь.
			name:      "тело длиннее блока",
			key:       0x42,
			frameType: 9,
			iteration: 1,
			body:      bytes.Repeat([]byte{0xAB}, 1600),
			want:      "d1b3e6144ac83787129f2acd36825217",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fill := c.key
			if c.name == "подтверждение ротации, шаг 7" {
				fill = 0x42
			}
			key := bytes.Repeat([]byte{fill}, 32)
			got := hex.EncodeToString(ComputeControlTag(key, c.frameType, c.iteration, c.body))
			if got != c.want {
				t.Errorf("метка разошлась с реализацией прошивки:\n  получено %s\n  ожидалось %s", got, c.want)
			}
		})
	}
}

// Длина метки должна оставаться прежней: она задана и в прошивке отдельной
// константой, и рассинхрон приведёт к отказу разбора кадров.
func TestControlTagSize(t *testing.T) {
	key := make([]byte, 32)
	tag := ComputeControlTag(key, 10, 1, []byte("тело"))
	if len(tag) != ControlTagSize {
		t.Fatalf("длина метки %d, ожидалась %d", len(tag), ControlTagSize)
	}
	if ControlTagSize != 16 {
		t.Errorf("длина метки изменилась на %d — нужно править и прошивку (LACERT_CONTROL_TAG_SIZE)", ControlTagSize)
	}
}

// Разные входные данные должны давать разные метки.
func TestControlTagDistinguishesInputs(t *testing.T) {
	key := make([]byte, 32)
	base := ComputeControlTag(key, 10, 1, []byte("тело"))

	variants := map[string][]byte{
		"другой тип кадра": ComputeControlTag(key, 9, 1, []byte("тело")),
		"другой шаг":       ComputeControlTag(key, 10, 2, []byte("тело")),
		"другое тело":      ComputeControlTag(key, 10, 1, []byte("иное")),
		"другой ключ":      ComputeControlTag(bytes.Repeat([]byte{1}, 32), 10, 1, []byte("тело")),
	}
	for name, v := range variants {
		if bytes.Equal(base, v) {
			t.Errorf("%s: метка совпала, хотя входные данные различаются", name)
		}
	}
}

// Проверка должна отвергать метку неверной длины, а не обращаться за границу.
func TestVerifyControlTagRejectsBadLength(t *testing.T) {
	key := make([]byte, 32)
	body := []byte("тело")
	full := ComputeControlTag(key, 10, 1, body)

	for name, tag := range map[string][]byte{
		"пустая":   {},
		"короткая": full[:ControlTagSize-1],
		"длинная":  append(append([]byte(nil), full...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyControlTag(key, 10, 1, body, tag); err == nil {
				t.Error("метка неверной длины должна отвергаться")
			}
		})
	}
}
