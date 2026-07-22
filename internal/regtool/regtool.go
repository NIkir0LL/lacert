// Package regtool эмулирует процесс офлайн-регистрации устройства, описанный
// в работе: устройство выводит через Serial-порт DeviceID, публичные ключи,
// хеш текущей прошивки и контрольную сумму; администратор физически считывает
// эту строку и вносит её в шлюз (через консольную утилиту или веб-форму).
// Тот факт, что контрольную сумму можно получить только подключившись к
// устройству физически, исключает удалённую регистрацию поддельных устройств.
//
// Важно: устройство передаёт только ХЕШ прошивки, а не сам её образ — точно
// так же, как при последующих периодических проверках целостности
// (internal/crypto/firmware.go). Гонять весь бинарник прошивки по любому
// каналу (Serial, REST, веб-форма) было бы и нереалистично для embedded
// устройства, и не нужно: для регистрации эталонного значения достаточно
// 32 байт хеша.
//
// В данном симуляторе "Serial-порт" — это просто структура в памяти,
// возвращаемая методом устройства; при переносе на реальное железо эта же
// логика будет работать почти без изменений, только данные будут реально
// идти через UART.
package regtool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/zeebo/blake3"
)

// SerialOutput — то, что в реальной системе устройство печатает в Serial-порт
// сразу после "Подготовки" (активации Secure Boot, генерации ключей в efuse).
type SerialOutput struct {
	DeviceID     string
	IdentityPub  []byte
	KEMPub       []byte
	FirmwareHash [sha256.Size]byte
	Checksum     string // 8 символов, как и описано в работе
}

// String форматирует вывод так, как он реально выглядел бы в Serial-терминале
// устройства — администратор копирует ЭТУ строку целиком и переносит её в
// шлюз (см. Parse). Поля идут в виде "Key=значение", без пробелов внутри
// значений, что позволяет надёжно разбирать строку обратно.
func (s SerialOutput) String() string {
	return fmt.Sprintf("DeviceID=%s IdentityPub=%s KEMPub=%s FirmwareHash=%s Checksum=%s",
		s.DeviceID,
		hex.EncodeToString(s.IdentityPub),
		hex.EncodeToString(s.KEMPub),
		hex.EncodeToString(s.FirmwareHash[:]),
		s.Checksum,
	)
}

var serialFieldRe = regexp.MustCompile(`(\w+)=(\S+)`)

// Parse разбирает строку, напечатанную устройством через Serial-порт (формат
// см. String), обратно в SerialOutput. Используется веб-формой регистрации:
// администратор может вставить всю строку целиком одним действием вместо
// того, чтобы переносить четыре значения по отдельности.
func Parse(line string) (SerialOutput, error) {
	fields := map[string]string{}
	for _, m := range serialFieldRe.FindAllStringSubmatch(line, -1) {
		fields[m[1]] = m[2]
	}

	deviceID, ok := fields["DeviceID"]
	if !ok || deviceID == "" {
		return SerialOutput{}, fmt.Errorf("строка не содержит DeviceID")
	}
	identityPub, err := hexField(fields, "IdentityPub")
	if err != nil {
		return SerialOutput{}, err
	}
	kemPub, err := hexField(fields, "KEMPub")
	if err != nil {
		return SerialOutput{}, err
	}
	firmwareHashBytes, err := hexField(fields, "FirmwareHash")
	if err != nil {
		return SerialOutput{}, err
	}
	if len(firmwareHashBytes) != sha256.Size {
		return SerialOutput{}, fmt.Errorf("FirmwareHash должен быть %d байт, получено %d", sha256.Size, len(firmwareHashBytes))
	}
	checksum, ok := fields["Checksum"]
	if !ok || checksum == "" {
		return SerialOutput{}, fmt.Errorf("строка не содержит Checksum")
	}

	var firmwareHash [sha256.Size]byte
	copy(firmwareHash[:], firmwareHashBytes)

	return SerialOutput{
		DeviceID:     deviceID,
		IdentityPub:  identityPub,
		KEMPub:       kemPub,
		FirmwareHash: firmwareHash,
		Checksum:     checksum,
	}, nil
}

func hexField(fields map[string]string, key string) ([]byte, error) {
	v, ok := fields[key]
	if !ok || v == "" {
		return nil, fmt.Errorf("строка не содержит %s", key)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s: неверный hex: %w", key, err)
	}
	return b, nil
}

// ComputeChecksum вычисляет короткую контрольную сумму над всеми
// идентификационными данными устройства, включая хеш прошивки. В тексте
// работы это названо HMAC; здесь это устроено как детерминированный
// BLAKE3-чексум — то есть он не секретен и не заменяет подпись, а служит
// исключительно для защиты от опечаток/подмены при ручном переносе данных
// администратором с экрана терминала в шлюз. Подлинность самого устройства
// проверяется позже отдельно, на шаге "Начальное рукопожатие", через подпись
// efuse-ключом.
func ComputeChecksum(deviceID string, identityPub, kemPub, firmwareHash []byte) string {
	h := blake3.New()
	h.Write([]byte(deviceID))
	h.Write(identityPub)
	h.Write(kemPub)
	h.Write(firmwareHash)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:8]
}

// BuildSerialOutput — вызывается на стороне устройства сразу после генерации
// ключей и вычисления хеша текущей прошивки (см. internal/device.NewDevice),
// эмулируя вывод через Serial-порт.
func BuildSerialOutput(deviceID string, identityPub, kemPub []byte, firmwareHash [sha256.Size]byte) SerialOutput {
	return SerialOutput{
		DeviceID:     deviceID,
		IdentityPub:  identityPub,
		KEMPub:       kemPub,
		FirmwareHash: firmwareHash,
		Checksum:     ComputeChecksum(deviceID, identityPub, kemPub, firmwareHash[:]),
	}
}

// VerifyChecksum — вызывается на стороне администратора/шлюза при вводе
// данных, считанных с Serial-порта, чтобы убедиться, что данные были
// перенесены без ошибок.
func VerifyChecksum(out SerialOutput) bool {
	expected := ComputeChecksum(out.DeviceID, out.IdentityPub, out.KEMPub, out.FirmwareHash[:])
	return expected == out.Checksum
}
