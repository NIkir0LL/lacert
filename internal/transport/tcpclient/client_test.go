package tcpclient

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/wire"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestDevice(t *testing.T, id string) *device.Device {
	t.Helper()
	dev, err := device.NewDevice(id, crypto.SigECDSAP256, []byte("firmware-v1"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	return dev
}

// TestDialUnreachableAddressFails: подключение к несуществующему адресу должно
// возвращать ошибку, а не паниковать/зависать.
func TestDialUnreachableAddressFails(t *testing.T) {
	dev := newTestDevice(t, "dev-unreach")
	// Порт 1 на localhost почти наверняка закрыт.
	if _, err := Dial("127.0.0.1:1", dev, quietLogger()); err == nil {
		t.Fatal("expected dial to a closed port to fail")
	}
}

// TestDialHandshakeRejectedByGateway: если «шлюз» сразу отвечает сообщением
// об ошибке вместо Msg2, Dial должен вернуть ошибку (устройство не в реестре).
func TestDialHandshakeRejectedByGateway(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Мини-«шлюз»: читает Msg1 и отвечает TypeError.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := wire.ReadFrame(conn); err != nil {
			return
		}
		_ = wire.WriteFrame(conn, wire.TypeError, wire.EncodeErrorMsg("unknown device"))
	}()

	dev := newTestDevice(t, "dev-rejected")
	if _, err := Dial(ln.Addr().String(), dev, quietLogger()); err == nil {
		t.Fatal("expected handshake to fail when gateway returns an error")
	}
}

// TestDialUnexpectedMessageType: если вместо Msg2 приходит неожиданный тип
// сообщения, Dial должен аккуратно вернуть ошибку.
func TestDialUnexpectedMessageType(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := wire.ReadFrame(conn); err != nil {
			return
		}
		// Отвечаем типом данных вместо Msg2 — протокольная ошибка.
		_ = wire.WriteFrame(conn, wire.TypeData, []byte("garbage"))
	}()

	dev := newTestDevice(t, "dev-badtype")
	if _, err := Dial(ln.Addr().String(), dev, quietLogger()); err == nil {
		t.Fatal("expected error on unexpected message type during handshake")
	}
}

// TestSendDataAfterCloseFails: запись в закрытое соединение должна возвращать
// ошибку, а не паниковать.
func TestSendDataAfterClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// «Шлюз», доводящий рукопожатие до конца, чтобы Dial успешно вернулся.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Полное рукопожатие с настоящей крипто-логикой.
		mt, payload, err := wire.ReadFrame(conn)
		if err != nil || mt != wire.TypeHandshakeMsg1 {
			return
		}
		msg1, err := wire.DecodeMsg1(payload)
		if err != nil {
			return
		}
		_ = msg1
		// Нам нужен KEM-pub устройства; в этом мини-сервере его нет, поэтому
		// просто закрываем — цель теста ниже не в рукопожатии, а в Close().
		time.Sleep(50 * time.Millisecond)
	}()

	// Здесь Dial, скорее всего, не завершится успехом (мини-сервер не шлёт
	// корректный Msg2), поэтому проверяем поведение Close() на клиенте,
	// созданном напрямую, без полного рукопожатия.
	dev := newTestDevice(t, "dev-close")
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &Client{Dev: dev, Logger: quietLogger(), conn: conn}
	if err := c.Close(); err != nil {
		t.Fatalf("close should succeed: %v", err)
	}
	// После закрытия отправка данных завершается ошибкой (нет сессии и/или
	// соединение закрыто) — главное, без паники.
	if err := c.SendData([]byte("x")); err == nil {
		t.Fatal("expected SendData to fail after close")
	}
}
