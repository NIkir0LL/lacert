// cmd/demo прогоняет полный жизненный цикл протокола LACERT: офлайн-
// регистрацию, начальное постквантовое рукопожатие, передачу данных с
// ротацией ключа по числу пакетов и по инициативе шлюза, и проверку
// целостности прошивки — включая сценарий с её подменой и последующим
// отзывом устройства. Это прямая программная трассировка UML-диаграммы
// последовательностей из текста работы.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	section("0. Инициализация шлюза")
	gw, err := gateway.New()
	must(err)
	gwKEMPubBytes, err := gw.GatewayKEMPublicKey().MarshalBinary()
	must(err)
	logger.Info("шлюз создан", "gateway_kem_pub_len", len(gwKEMPubBytes))

	section("1. Подготовка устройства (efuse: ECDSA P-256 + ML-KEM-1024)")
	firmwareV1 := []byte("LACERT-firmware-v1.0.0-stub-binary-content")
	dev, err := device.NewDevice("xiao-esp32c6-0001", crypto.SigECDSAP256, firmwareV1)
	must(err)
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	logger.Info("устройство подготовлено", "device_id", dev.ID)

	section("1.1. Офлайн-регистрация (вывод через Serial + перенос администратором)")
	serial, err := dev.SerialRegistrationOutput()
	must(err)
	fmt.Printf("  [Serial-порт устройства] -> %s\n", serial.String())
	must(gw.RegisterDevice(serial, crypto.SigECDSAP256))
	logger.Info("устройство зарегистрировано на шлюзе", "device_id", dev.ID)

	section("2. Начальное постквантовое рукопожатие (Noise_XX + ML-KEM-1024)")
	t0 := time.Now()
	msg1, err := dev.StartHandshake()
	must(err)
	fmt.Printf("  Msg1 (устройство -> шлюз): DeviceID=%s, Nonce=%x...\n", msg1.DeviceID, msg1.Nonce[:8])

	msg2, err := gw.HandleMsg1(msg1)
	must(err)
	fmt.Printf("  Msg2 (шлюз -> устройство): Kyber-шифротекст, %d байт\n", len(msg2.KEMCiphertext))

	msg3, err := dev.CompleteHandshake(msg1, msg2)
	must(err)
	fmt.Printf("  Msg3 (устройство -> шлюз): подпись подтверждения, %d байт\n", len(msg3.Signature))

	must(gw.HandleMsg3(dev.ID, msg3))
	logger.Info("рукопожатие завершено успешно", "elapsed", time.Since(t0), "session_established", dev.HasSession())

	section("3. Передача данных и непрерывная ротация ключей")
	for i := 1; i <= 5; i++ {
		payload := []byte(fmt.Sprintf("temperature=23.%d;humidity=4%d", i, i))
		nonce, ct, err := dev.SendData(payload)
		must(err)
		plain, err := gw.HandleData(dev.ID, nonce, ct)
		must(err)
		fmt.Printf("  Пакет #%d: устройство -> шлюз: %q (расшифровано шлюзом: %q)\n", i, payload, plain)
	}

	fmt.Println("  Имитация достижения лимита 300 пакетов под текущим ключом...")
	for dev.SessionStats().PacketCount < crypto.RotationPacketLimit {
		_, ct, err := dev.SendData([]byte("tick"))
		must(err)
		_ = ct
	}
	fmt.Printf("  Счётчик пакетов: %d/%d -> устройство решает, что пора ротировать ключ\n",
		dev.SessionStats().PacketCount, crypto.RotationPacketLimit)

	t1 := time.Now()
	rotMsg, err := dev.InitiateRotation()
	must(err)
	must(gw.HandleRotationFromDevice(dev.ID, rotMsg))
	fmt.Printf("  Ротация выполнена за %v. Ki+1 = BLAKE3(Ki || Mi || \"rotate_v1\"); счётчик сброшен в %d\n",
		time.Since(t1), dev.SessionStats().PacketCount)

	fmt.Println("  Канал продолжает работать без разрыва соединения, под новым ключом:")
	payload := []byte("post-rotation-sensor-data")
	nonce, ct, err := dev.SendData(payload)
	must(err)
	plain, err := gw.HandleData(dev.ID, nonce, ct)
	must(err)
	fmt.Printf("  Пакет после ротации: устройство -> шлюз: %q (расшифровано: %q)\n", payload, plain)

	section("3.1. Ротация по инициативе шлюза (например, по собственному таймеру)")
	gwRotMsg, err := gw.InitiateRotationToDevice(dev.ID)
	must(err)
	must(dev.HandleRotationFromGateway(gwRotMsg))
	fmt.Printf("  Ротация, инициированная шлюзом, выполнена. Ротаций всего: %d\n", dev.SessionStats().RotationCount)

	section("4. Проверка целостности прошивки — устройство ЧЕСТНОЕ (прошивка не менялась)")
	challenge, err := gw.IssueFirmwareChallenge(dev.ID)
	must(err)
	fmt.Printf("  Challenge от шлюза: %d байт\n", len(challenge))
	resp, err := dev.RespondFirmwareChallenge(challenge)
	must(err)
	result, err := gw.VerifyFirmwareCheck(dev.ID, resp)
	must(err)
	fmt.Printf("  Результат проверки: подпись=%v, хеш совпадает=%v -> устройство доверено=%v\n",
		result.SignatureValid, result.HashMatches, result.OK())

	section("5. Атака: несанкционированная подмена прошивки -> обнаружение и отзыв устройства")
	dev.TamperFirmware([]byte("-injected-malicious-code"))
	fmt.Println("  Устройство 'перепрошито' злоумышленником (прошивка изменена без переоформления в системе)")

	challenge2, err := gw.IssueFirmwareChallenge(dev.ID)
	must(err)
	resp2, err := dev.RespondFirmwareChallenge(challenge2)
	must(err)
	result2, err := gw.VerifyFirmwareCheck(dev.ID, resp2)
	must(err)
	fmt.Printf("  Результат проверки: подпись=%v, хеш совпадает=%v -> устройство доверено=%v\n",
		result2.SignatureValid, result2.HashMatches, result2.OK())

	if !result2.OK() {
		_, getErr := gw.Store.Get(dev.ID)
		fmt.Printf("  Устройство исключено из доверенной сети. Статус в реестре шлюза: %v\n", getErr)
	}

	section("Итог")
	fmt.Println("  Полный жизненный цикл LACERT воспроизведён программно:")
	fmt.Println("  офлайн-регистрация -> постквантовое рукопожатие -> передача данных ->")
	fmt.Println("  непрерывная ротация ключей (по пакетам и по таймеру) -> проверка целостности ->")
	fmt.Println("  обнаружение компрометации и отзыв устройства.")
}

func section(title string) {
	fmt.Println()
	fmt.Println("=== " + title + " ===")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}
