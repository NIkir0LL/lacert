// cmd/stresstest — «живой» стресс-тест защитных механизмов против РАБОТАЮЩЕГО
// шлюза (cmd/gatewayd) по реальной сети. В отличие от юнит-теста
// TestStressAllDefenseMechanisms (который гоняет шлюз в памяти), этот
// инструмент подключается к поднятому шлюзу по TCP, регистрирует пять
// устройств через REST и воспроизводит на каждом свой сценарий сбоя, после
// чего читает метрики шлюза до и после — чтобы наглядно показать, что счётчики
// защиты изменились правильно. Метрики также видно вживую на вкладке
// «метрики» веб-дашборда.
//
// Запуск (шлюз должен быть уже запущен):
//
//	LACERT_GATEWAY_HTTP=http://localhost:8080 \
//	LACERT_GATEWAY_TCP=localhost:7700 \
//	LACERT_ADMIN_TOKEN=... \
//	go run ./cmd/stresstest
//
// Сценарии:
//
//	D1 — периодические сбои ротации (2 подряд, ниже порога бана): устройство
//	     не отвечает на ротацию шлюза; счётчик rotations_failed растёт, но
//	     устройство НЕ отзывается.
//	D2 — replay-атака: повтор записанного Msg1 (replays_blocked).
//	D3 — рукопожатие с испорченной подписью Msg3 (handshakes_rejected).
//	D4 — ответ на проверку прошивки с опозданием (challenge устарел,
//	     firmware_checks_rejected).
//	D5 — устройство проходит проверку прошивки, затем «перепрошивается» и
//	     проваливает следующую -> отзыв (firmware_checks_failed + devices_revoked).
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/emulator"
	"lacert/internal/wire"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

func main() {
	httpBase := getenv("LACERT_GATEWAY_HTTP", "http://localhost:8080")
	tcpAddr := getenv("LACERT_GATEWAY_TCP", "localhost:7700")
	adminToken := os.Getenv("LACERT_ADMIN_TOKEN")

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	fmt.Println("=== LACERT: живой стресс-тест защитных механизмов ===")
	fmt.Printf("Шлюз HTTP: %s | TCP: %s\n\n", httpBase, tcpAddr)

	gwKEM, err := emulator.FetchGatewayKEMPublicKey(httpBase)
	if err != nil {
		fmt.Printf("ОШИБКА: не удалось получить ключ шлюза (%v).\nШлюз запущен? Проверьте LACERT_GATEWAY_HTTP.\n", err)
		os.Exit(1)
	}

	before, err := fetchMetrics(httpBase, adminToken)
	if err != nil {
		fmt.Printf("ОШИБКА: не удалось прочитать метрики: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Метрики ДО:")
	printMetrics(before)
	fmt.Println()

	rt := &runner{httpBase: httpBase, tcpAddr: tcpAddr, adminToken: adminToken, gwKEM: gwKEM, logger: logger,
		runID: fmt.Sprintf("%d", time.Now().Unix())}
	defer rt.closeAll()

	// Держим соединения открытыми, пока планировщик шлюза не отработает
	// ротацию и проверки прошивки на подключённых устройствах.
	rt.scenarioD1FlakyRotation()
	rt.scenarioD2Replay()
	rt.scenarioD3BadHandshake()
	rt.scenarioD4StaleFirmware()
	rt.scenarioD5FirmwareThenTamper()

	// Фаза наблюдения: даём планировщику время инициировать ротацию (по
	// таймеру) и проверки прошивки. Длительность настраивается через
	// LACERT_STRESS_WAIT (по умолчанию 25с). Для быстрого прохождения запускайте
	// шлюз в демо-режиме: LACERT_ROTATION_INTERVAL, LACERT_FIRMWARE_INTERVAL.
	waitDur := 25 * time.Second
	if v := os.Getenv("LACERT_STRESS_WAIT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			waitDur = d
		}
	}
	fmt.Printf("\nФаза наблюдения: ждём %s, пока планировщик шлюза отработает ротацию и проверки прошивки…\n", waitDur)
	deadline := time.Now().Add(waitDur)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		m, err := fetchMetrics(httpBase, adminToken)
		if err == nil {
			fmt.Printf("  [%s] ротаций: ок=%d провал=%d | прошивка: passed=%d failed=%d rejected=%d | отозвано=%d\n",
				time.Now().Format("15:04:05"),
				m.RotationsSucceeded, m.RotationsFailed,
				m.FirmwareChecksPassed, m.FirmwareChecksFailed, m.FirmwareChecksRejected,
				m.DevicesRevoked)
		}
	}

	after, err := fetchMetrics(httpBase, adminToken)
	if err != nil {
		fmt.Printf("ОШИБКА: не удалось прочитать метрики после: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nМетрики ПОСЛЕ:")
	printMetrics(after)

	fmt.Println("\n=== ИЗМЕНЕНИЯ (после - до) ===")
	printDelta("рукопожатий завершено", before.HandshakesCompleted, after.HandshakesCompleted)
	printDelta("рукопожатий отклонено ", before.HandshakesRejected, after.HandshakesRejected)
	printDelta("replay отбито         ", before.ReplaysBlocked, after.ReplaysBlocked)
	printDelta("ротаций успешно       ", before.RotationsSucceeded, after.RotationsSucceeded)
	printDelta("ротаций провалено     ", before.RotationsFailed, after.RotationsFailed)
	printDelta("прошивка пройдено     ", before.FirmwareChecksPassed, after.FirmwareChecksPassed)
	printDelta("прошивка провалено    ", before.FirmwareChecksFailed, after.FirmwareChecksFailed)
	printDelta("прошивка отклонено    ", before.FirmwareChecksRejected, after.FirmwareChecksRejected)
	printDelta("устройств отозвано    ", before.DevicesRevoked, after.DevicesRevoked)

	fmt.Println("\nГотово. Откройте вкладку «метрики» на дашборде, чтобы увидеть те же значения.")
}

type runner struct {
	httpBase   string
	tcpAddr    string
	adminToken string
	gwKEM      *mlkem1024.PublicKey
	logger     *slog.Logger

	// runID — уникальный суффикс прогона (метка времени), добавляемый к ID
	// всех устройств, чтобы повторные запуски не конфликтовали с уже
	// зарегистрированными устройствами в базе шлюза.
	runID string

	// conns — открытые соединения, которые нужно держать живыми в течение фазы
	// наблюдения (чтобы планировщик шлюза успел отработать ротацию/прошивку),
	// и закрыть в самом конце.
	conns []*rawConn
}

// keep регистрирует соединение, чтобы оно не закрывалось до конца прогона.
func (r *runner) keep(rc *rawConn) { r.conns = append(r.conns, rc) }

// closeAll закрывает все удержанные соединения.
func (r *runner) closeAll() {
	for _, rc := range r.conns {
		rc.close()
	}
}

// newDevice создаёт и регистрирует устройство на живом шлюзе. К
// идентификатору добавляется уникальный суффикс прогона (метка времени),
// чтобы повторные запуски инструмента не упирались в «устройство уже
// зарегистрировано» (ошибка 400) — ведь шлюз с PostgreSQL сохраняет
// зарегистрированные устройства между запусками.
func (r *runner) newDevice(id string) (*device.Device, error) {
	uniqueID := fmt.Sprintf("%s-%s", id, r.runID)
	dev, err := device.NewDevice(uniqueID, crypto.SigECDSAP256, []byte("firmware-"+uniqueID))
	if err != nil {
		return nil, err
	}
	dev.SetGatewayKEMPublicKey(r.gwKEM)
	if err := emulator.RegisterDeviceViaREST(r.httpBase, dev, r.adminToken); err != nil {
		return nil, fmt.Errorf("регистрация: %w", err)
	}
	return dev, nil
}

// rawConn — низкоуровневое соединение с ручной отправкой кадров, чтобы
// воспроизводить атаки (replay, порча подписи), недоступные высокоуровневому
// клиенту.
type rawConn struct {
	conn net.Conn
	dev  *device.Device
}

func (r *runner) connectRaw(dev *device.Device) (*rawConn, error) {
	conn, err := net.DialTimeout("tcp", r.tcpAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &rawConn{conn: conn, dev: dev}, nil
}

// handshake проводит нормальное рукопожатие и оставляет соединение открытым.
func (rc *rawConn) handshake() error {
	msg1, err := rc.dev.StartHandshake()
	if err != nil {
		return err
	}
	if err := wire.WriteFrame(rc.conn, wire.TypeHandshakeMsg1, wire.EncodeMsg1(msg1)); err != nil {
		return err
	}
	mt, payload, err := wire.ReadFrame(rc.conn)
	if err != nil {
		return err
	}
	if mt != wire.TypeHandshakeMsg2 {
		return fmt.Errorf("ожидался Msg2, получен тип %d", mt)
	}
	msg2, err := wire.DecodeMsg2(payload)
	if err != nil {
		return err
	}
	msg3, err := rc.dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		return err
	}
	return wire.WriteFrame(rc.conn, wire.TypeHandshakeMsg3, wire.EncodeMsg3(msg3))
}

func (rc *rawConn) close() {
	if rc.conn != nil {
		_ = rc.conn.Close()
	}
}

// --- Сценарии ---

func (r *runner) scenarioD1FlakyRotation() {
	fmt.Println("D1: периодические сбои ротации (2 подряд, ниже порога бана)…")
	dev, err := r.newDevice("stress-live-d1-flaky")
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	rc, err := r.connectRaw(dev)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	r.keep(rc)
	if err := rc.handshake(); err != nil {
		fmt.Printf("   пропуск (рукопожатие): %v\n", err)
		return
	}
	// Запускаем фоновое чтение кадров (данные/ошибки), чтобы соединение жило.
	go drainFrames(rc)
	// Отправляем немного данных, затем НЕ отвечаем на ротации шлюза: планировщик
	// инициирует ротацию, ACK не приходит, попытки откатываются по тайм-ауту.
	// (Реальный тайм-аут ACK — RotationAckTimeout; здесь мы лишь читаем входящие
	// кадры и игнорируем ротацию, чтобы шлюз зафиксировал провал.)
	for i := 0; i < 3; i++ {
		nonce, ct, err := dev.SendData([]byte(fmt.Sprintf("d1-packet-%d", i)))
		if err == nil {
			_ = wire.WriteFrame(rc.conn, wire.TypeData, wire.EncodeData(nonce, ct))
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Println("   отправлены данные; ротации шлюза останутся без ответа (провалы посчитаются планировщиком)")
}

func (r *runner) scenarioD2Replay() {
	fmt.Println("D2: replay-атака на рукопожатие…")
	dev, err := r.newDevice("stress-live-d2-replay")
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	rc, err := r.connectRaw(dev)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	defer rc.close()
	msg1, err := dev.StartHandshake()
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	frame := wire.EncodeMsg1(msg1)
	// Первый Msg1 — легитимный.
	_ = wire.WriteFrame(rc.conn, wire.TypeHandshakeMsg1, frame)
	_, _, _ = wire.ReadFrame(rc.conn) // Msg2 (игнорируем)
	// Повторяем тот же Msg1 несколько раз — replay.
	for i := 0; i < 3; i++ {
		conn2, err := net.DialTimeout("tcp", r.tcpAddr, 5*time.Second)
		if err != nil {
			continue
		}
		_ = wire.WriteFrame(conn2, wire.TypeHandshakeMsg1, frame)
		// Шлюз должен ответить ошибкой replay; читаем и закрываем.
		_, _, _ = wire.ReadFrame(conn2)
		_ = conn2.Close()
	}
	fmt.Println("   повтор Msg1 отправлен 3 раза — шлюз должен отбить их как replay")
}

func (r *runner) scenarioD3BadHandshake() {
	fmt.Println("D3: рукопожатие с испорченной подписью…")
	dev, err := r.newDevice("stress-live-d3-badsig")
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	rc, err := r.connectRaw(dev)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	defer rc.close()
	msg1, err := dev.StartHandshake()
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	_ = wire.WriteFrame(rc.conn, wire.TypeHandshakeMsg1, wire.EncodeMsg1(msg1))
	mt, payload, err := wire.ReadFrame(rc.conn)
	if err != nil || mt != wire.TypeHandshakeMsg2 {
		fmt.Printf("   пропуск: не получен Msg2\n")
		return
	}
	msg2, err := wire.DecodeMsg2(payload)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	msg3, err := dev.CompleteHandshake(msg1, msg2)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	// Портим подпись.
	if len(msg3.Signature) > 0 {
		msg3.Signature[0] ^= 0xFF
	}
	_ = wire.WriteFrame(rc.conn, wire.TypeHandshakeMsg3, wire.EncodeMsg3(msg3))
	_, _, _ = wire.ReadFrame(rc.conn) // ожидаем ошибку
	fmt.Println("   Msg3 с битой подписью отправлен — шлюз должен отклонить рукопожатие")
}

func (r *runner) scenarioD4StaleFirmware() {
	fmt.Println("D4: ответ на проверку прошивки с опозданием (challenge устареет)…")
	dev, err := r.newDevice("stress-live-d4-stale-fw")
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	rc, err := r.connectRaw(dev)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	r.keep(rc)
	if err := rc.handshake(); err != nil {
		fmt.Printf("   пропуск (рукопожатие): %v\n", err)
		return
	}
	fmt.Println("   устройство подключено; на challenge шлюза оно ответит слишком поздно")
	fmt.Println("   (шлюз шлёт firmware-challenge по расписанию; ответ за пределами окна валидности будет отклонён)")
	// Мы намеренно НЕ отвечаем на challenge вовремя: читаем кадры и, встретив
	// challenge, отвечаем с задержкой больше окна валидности.
	go func() {
		for {
			mt, payload, err := wire.ReadFrame(rc.conn)
			if err != nil {
				return
			}
			if mt == wire.TypeFirmwareChallenge {
				ch, err := wire.DecodeFirmwareChallenge(payload)
				if err != nil {
					continue
				}
				// Отвечаем НАМЕРЕННО ПОЗЖЕ окна валидности challenge, чтобы шлюз
				// отклонил ответ как устаревший (firmware_checks_rejected).
				// Задержка должна превышать LACERT_FIRMWARE_VALIDITY шлюза.
				// Настраивается через LACERT_STRESS_D4_DELAY (по умолчанию 20с —
				// с запасом над типичным окном валидности 15с). Если у вас окно
				// больше — увеличьте задержку соответственно.
				time.Sleep(d4Delay())
				resp, err := dev.RespondFirmwareChallenge(ch)
				if err != nil {
					return
				}
				_ = wire.WriteFrame(rc.conn, wire.TypeFirmwareResponse, wire.EncodeFirmwareResponse(resp))
				return
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
}

func (r *runner) scenarioD5FirmwareThenTamper() {
	fmt.Println("D5: проходит проверку прошивки, затем подмена -> отзыв…")
	dev, err := r.newDevice("stress-live-d5-tamper")
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	rc, err := r.connectRaw(dev)
	if err != nil {
		fmt.Printf("   пропуск: %v\n", err)
		return
	}
	r.keep(rc)
	if err := rc.handshake(); err != nil {
		fmt.Printf("   пропуск (рукопожатие): %v\n", err)
		return
	}
	// Первую проверку проходим честно, затем «перепрошиваемся» и следующую
	// проваливаем.
	tampered := false
	go func() {
		for {
			mt, payload, err := wire.ReadFrame(rc.conn)
			if err != nil {
				return
			}
			if mt == wire.TypeFirmwareChallenge {
				ch, err := wire.DecodeFirmwareChallenge(payload)
				if err != nil {
					continue
				}
				if tampered {
					dev.TamperFirmware([]byte("-live-rootkit"))
				}
				resp, err := dev.RespondFirmwareChallenge(ch)
				if err != nil {
					return
				}
				_ = wire.WriteFrame(rc.conn, wire.TypeFirmwareResponse, wire.EncodeFirmwareResponse(resp))
				tampered = true // следующую проверку заваливаем
			}
		}
	}()
	fmt.Println("   устройство ответит на первую проверку честно, затем «перепрошьётся» и провалит следующую")
	time.Sleep(500 * time.Millisecond)
}

// --- метрики через REST ---

type metrics struct {
	HandshakesCompleted    uint64 `json:"handshakes_completed"`
	HandshakesRejected     uint64 `json:"handshakes_rejected"`
	ReplaysBlocked         uint64 `json:"replays_blocked"`
	RotationsSucceeded     uint64 `json:"rotations_succeeded"`
	RotationsFailed        uint64 `json:"rotations_failed"`
	FirmwareChecksPassed   uint64 `json:"firmware_checks_passed"`
	FirmwareChecksFailed   uint64 `json:"firmware_checks_failed"`
	FirmwareChecksRejected uint64 `json:"firmware_checks_rejected"`
	DevicesRevoked         uint64 `json:"devices_revoked"`
}

func fetchMetrics(httpBase, adminToken string) (metrics, error) {
	var m metrics
	req, err := http.NewRequest(http.MethodGet, httpBase+"/api/v1/metrics", nil)
	if err != nil {
		return m, err
	}
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return m, fmt.Errorf("status %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&m)
	return m, err
}

func printMetrics(m metrics) {
	fmt.Printf("  рукопожатий: завершено=%d отклонено=%d | replay отбито=%d\n",
		m.HandshakesCompleted, m.HandshakesRejected, m.ReplaysBlocked)
	fmt.Printf("  ротаций: успешно=%d провалено=%d\n", m.RotationsSucceeded, m.RotationsFailed)
	fmt.Printf("  прошивка: пройдено=%d провалено=%d отклонено=%d | устройств отозвано=%d\n",
		m.FirmwareChecksPassed, m.FirmwareChecksFailed, m.FirmwareChecksRejected, m.DevicesRevoked)
}

func printDelta(label string, before, after uint64) {
	delta := int64(after) - int64(before)
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	fmt.Printf("  %s: %d -> %d (%s%d)\n", label, before, after, sign, delta)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// d4Delay — насколько поздно устройство D4 отвечает на firmware-challenge.
// Должно превышать LACERT_FIRMWARE_VALIDITY шлюза, чтобы ответ был отклонён как
// устаревший. Настраивается через LACERT_STRESS_D4_DELAY (по умолчанию 20с).
func d4Delay() time.Duration {
	if v := os.Getenv("LACERT_STRESS_D4_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 20 * time.Second
}

// drainFrames читает и отбрасывает входящие кадры (данные/ошибки/ротацию),
// чтобы соединение оставалось живым, а ротации шлюза для D1 оставались без
// ACK (устройство их игнорирует — это и есть моделируемый сбой).
func drainFrames(rc *rawConn) {
	for {
		if _, _, err := wire.ReadFrame(rc.conn); err != nil {
			return
		}
	}
}
