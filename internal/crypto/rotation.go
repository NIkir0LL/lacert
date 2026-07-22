package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// RotationMsg — единственное сообщение, которым обменивается сторона,
// инициирующая ротацию, со своим собеседником. В отличие от рукопожатия,
// здесь не нужен ответный шаг подтверждения: инициатор уже знает Mi
// (результат собственной инкапсуляции) и сразу обновляет сессию; получатель
// узнаёт Mi через декапсуляцию и тоже сразу обновляет сессию. Обе стороны
// приходят к одинаковому Ki+1, потому что используют одно и то же Ki и одно
// и то же Mi (см. session.go: Rotate).
type RotationMsg struct {
	KEMCiphertext []byte // 1568 байт, инкапсулировано под KEM-pubkey получателя
}

// InitiateRotation вызывается стороной, которая обнаружила (через
// Session.NeedsRotation), что наступило время ротации — каждые 300 секунд
// или 300 пакетов, что раньше. peerKEMPub — публичный ключ ML-KEM-1024
// собеседника (известен из БД устройств / из конфигурации устройства,
// прописанной при офлайн-регистрации). Инициатор сразу же ротирует свою
// сессию и возвращает сообщение для отправки собеседнику.
func InitiateRotation(session *Session, peerKEMPub *mlkem1024.PublicKey) (*RotationMsg, error) {
	ct, mi, err := Encapsulate(peerKEMPub)
	if err != nil {
		return nil, fmt.Errorf("encapsulate for rotation: %w", err)
	}
	defer zeroize(mi)

	if err := session.Rotate(mi); err != nil {
		return nil, fmt.Errorf("rotate session (initiator side): %w", err)
	}
	return &RotationMsg{KEMCiphertext: ct}, nil
}

// RespondToRotation вызывается стороной, получившей RotationMsg от
// собеседника. myKEMPriv — собственный приватный ключ ML-KEM-1024 этой
// стороны (в реальной системе хранится в efuse/защищённой области и
// программно не читается).
func RespondToRotation(session *Session, myKEMPriv *mlkem1024.PrivateKey, msg *RotationMsg) error {
	mi, err := Decapsulate(myKEMPriv, msg.KEMCiphertext)
	if err != nil {
		return fmt.Errorf("decapsulate rotation message: %w", err)
	}
	defer zeroize(mi)

	if err := session.Rotate(mi); err != nil {
		return fmt.Errorf("rotate session (responder side): %w", err)
	}
	return nil
}
