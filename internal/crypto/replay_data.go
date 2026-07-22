package crypto

import (
	"encoding/binary"
	"errors"
)

// Защита пакетов данных от повторного воспроизведения (replay).
//
// Проблема. ReplayGuard (replay.go) закрывает только рукопожатие: он помнит
// nonce из Msg1. Для пакетов TypeData никакой проверки не было — принимающая
// сторона просто расшифровывала пакет текущим ключом. ChaCha20-Poly1305
// гарантирует, что пакет не подделан, но НЕ говорит, что он не был получен
// ранее: записанный из сети пакет телеметрии расшифровывался повторно сколько
// угодно раз и каждый раз ложился в хранилище как свежее показание. Для
// системы, которая по показаниям датчиков принимает решения (расход топлива,
// давление, ток), это подмена данных без единого испорченного байта.
//
// Решение. Nonce пакета уникален в рамках ключа по построению (см. aead.go:
// 8 случайных байт || uint32 BE seq). Значит, достаточно помнить nonce'ы,
// уже принятые под ТЕКУЩИМ ключом, и отвергать повторы. Ротация ключа
// очищает набор: под новым ключом старые nonce'ы всё равно не расшифруются,
// поэтому хранить их дальше незачем.
//
// Важно, что это исправление не трогает формат кадра: прошивке ESP32 и
// эмулятору менять ничего не нужно, проверка целиком на принимающей стороне.
//
// Ограничение памяти. В штатной работе набор не превышает
// RotationPacketLimit (300) записей — ротация обнуляет его. Но если ротация
// перестала проходить (сеть, зависший собеседник), набор рос бы неограниченно,
// поэтому его размер ограничен maxSeenNonces: при переполнении вытесняются
// самые старые записи. Окно всё равно многократно перекрывает нормальный
// объём трафика под одним ключом.
const maxSeenNonces = 4096

// ErrDataReplay возвращается, когда пакет с таким nonce уже принимался под
// текущим сеансовым ключом.
var ErrDataReplay = errors.New("replay detected: data packet nonce already seen for current key")

// nonceID — компактное представление 12-байтового nonce как ключа карты
// (массив, а не срез, чтобы быть сравнимым типом и не аллоцировать).
type nonceID [12]byte

// CheckDataNonce проверяет, что пакет с таким nonce ещё не принимался под
// текущим ключом, и запоминает его. Вызывается принимающей стороной ДО того,
// как расшифрованные данные попадут в хранилище/прикладную систему.
//
// Возвращает ErrDataReplay для повтора. Nonce неверной длины отвергается как
// некорректный кадр — расшифровка такого пакета всё равно не прошла бы.
func (s *Session) CheckDataNonce(nonce []byte) error {
	if len(nonce) != 12 {
		return errors.New("invalid nonce size for replay check")
	}
	var id nonceID
	copy(id[:], nonce)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session is closed")
	}
	if s.seenNonces == nil {
		s.seenNonces = make(map[nonceID]struct{}, 64)
	}
	if _, ok := s.seenNonces[id]; ok {
		return ErrDataReplay
	}

	// Вытеснение самых старых записей при переполнении окна. Порядок
	// поступления хранится отдельным срезом: карта его не сохраняет.
	if len(s.seenOrder) >= maxSeenNonces {
		drop := len(s.seenOrder) - maxSeenNonces + 1
		for _, old := range s.seenOrder[:drop] {
			delete(s.seenNonces, old)
		}
		s.seenOrder = append(s.seenOrder[:0], s.seenOrder[drop:]...)
	}

	s.seenNonces[id] = struct{}{}
	s.seenOrder = append(s.seenOrder, id)
	return nil
}

// resetSeenNoncesLocked очищает окно принятых nonce'ов. Вызывается под уже
// захваченным s.mu при каждой смене ключа: под новым Ki старые пакеты не
// расшифруются, так что помнить их больше не нужно.
func (s *Session) resetSeenNoncesLocked() {
	s.seenNonces = nil
	s.seenOrder = s.seenOrder[:0]
}

// SeenNonceCount возвращает размер окна принятых nonce'ов — для тестов и
// диагностики (сколько пакетов принято под текущим ключом).
func (s *Session) SeenNonceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seenNonces)
}

// SeqFromNonce извлекает номер пакета из nonce (младшие 4 байта, BE) —
// вспомогательная функция для журналирования и диагностики.
func SeqFromNonce(nonce []byte) (uint32, bool) {
	if len(nonce) != 12 {
		return 0, false
	}
	return binary.BigEndian.Uint32(nonce[8:]), true
}
