package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
	"lacert/internal/store"
	"lacert/internal/transport/tcpclient"
	"lacert/internal/transport/tcpserver"
)

func newTestServer(t *testing.T) (*Server, *gateway.Gateway) {
	t.Helper()
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return New(gw, Options{}), gw
}

func TestRegisterAndGetDevice(t *testing.T) {
	srv, gw := newTestServer(t)

	dev, err := device.NewDevice("api-esp32-001", crypto.SigECDSAP256, []byte("firmware-v1"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}

	reqBody, _ := json.Marshal(registerDeviceRequest{
		DeviceID:        serial.DeviceID,
		IdentityPubHex:  hex.EncodeToString(serial.IdentityPub),
		KEMPubHex:       hex.EncodeToString(serial.KEMPub),
		FirmwareHashHex: hex.EncodeToString(serial.FirmwareHash[:]),
		Checksum:        serial.Checksum,
		SigAlgorithm:    "ecdsa-p256",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d, body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/devices/api-esp32-001", nil)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("get device: expected 200, got %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var got deviceResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DeviceID != "api-esp32-001" || got.Revoked {
		t.Fatalf("unexpected device response: %+v", got)
	}
}

// TestRegisterViaSerialLine проверяет основной сценарий для веб-формы:
// администратор вставляет ОДНУ строку, напечатанную устройством через
// Serial-порт, целиком — без необходимости переносить четыре значения по
// отдельности.
func TestRegisterViaSerialLine(t *testing.T) {
	srv, gw := newTestServer(t)

	dev, err := device.NewDevice("api-esp32-serialline", crypto.SigECDSAP256, []byte("firmware-v1"))
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("serial output: %v", err)
	}

	reqBody, _ := json.Marshal(registerDeviceRequest{
		SerialLine:   serial.String(), // именно то, что админ скопировал бы из терминала
		SigAlgorithm: "ecdsa-p256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register via serial_line: expected 201, got %d, body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/devices/api-esp32-serialline", nil)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("get device: expected 200, got %d", rec2.Code)
	}
}

func TestRegisterRejectsBadChecksum(t *testing.T) {
	srv, gw := newTestServer(t)
	dev, _ := device.NewDevice("api-esp32-002", crypto.SigECDSAP256, []byte("fw"))
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := dev.SerialRegistrationOutput()

	reqBody, _ := json.Marshal(registerDeviceRequest{
		DeviceID:        serial.DeviceID,
		IdentityPubHex:  hex.EncodeToString(serial.IdentityPub),
		KEMPubHex:       hex.EncodeToString(serial.KEMPub),
		FirmwareHashHex: hex.EncodeToString(serial.FirmwareHash[:]),
		Checksum:        "deadbeef", // неверная контрольная сумма
		SigAlgorithm:    "ecdsa-p256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad checksum, got %d", rec.Code)
	}
}

func TestListAndRevokeDevice(t *testing.T) {
	srv, gw := newTestServer(t)
	dev, _ := device.NewDevice("api-esp32-003", crypto.SigECDSAP256, []byte("fw"))
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := dev.SerialRegistrationOutput()
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("register: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}
	var list []deviceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 device, got %d", len(list))
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/devices/api-esp32-003/revoke", bytes.NewReader([]byte(`{"reason":"manual test"}`)))
	revokeRec := httptest.NewRecorder()
	srv.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", revokeRec.Code)
	}

	got, err := gw.Store.Get("api-esp32-003")
	_ = got
	if err == nil {
		t.Fatal("expected device to be revoked after REST call")
	}
}

func TestTelemetryEndpointFiltersByDeviceAndTime(t *testing.T) {
	srv, gw := newTestServer(t)

	// Фиксированная метка в UTC, а не time.Now(): time.Now() несёт локальную
	// зону и монотонную составляющую, которую Format(RFC3339) отбрасывает.
	// В ненулевом часовом поясе это сдвигало границу фильтра since, и тест
	// падал на всех машинах, кроме UTC. Сам эндпоинт при этом корректен —
	// проблема была только в тестовых данных.
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		err := gw.Store.RecordTelemetry(store.TelemetryReading{
			DeviceID:   "tel-dev-1",
			RawPayload: "temperature=" + string(rune('0'+i)),
			Parsed:     map[string]float64{"temperature": float64(20 + i)},
			ReceivedAt: base.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("seed telemetry %d: %v", i, err)
		}
	}
	if err := gw.Store.RecordTelemetry(store.TelemetryReading{DeviceID: "tel-dev-2", RawPayload: "x=1", ReceivedAt: base}); err != nil {
		t.Fatalf("seed telemetry dev-2: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/telemetry?device_id=tel-dev-1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rec.Code, rec.Body.String())
	}
	var readings []store.TelemetryReading
	if err := json.Unmarshal(rec.Body.Bytes(), &readings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(readings) != 3 {
		t.Fatalf("expected 3 readings for tel-dev-1, got %d", len(readings))
	}

	sinceParam := base.Add(90 * time.Second).Format(time.RFC3339)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/telemetry?device_id=tel-dev-1&since="+sinceParam, nil)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	var filtered []store.TelemetryReading
	if err := json.Unmarshal(rec2.Body.Bytes(), &filtered); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 reading after %s, got %d", sinceParam, len(filtered))
	}

	// Без device_id — данные со всех устройств.
	reqAll := httptest.NewRequest(http.MethodGet, "/api/v1/telemetry", nil)
	recAll := httptest.NewRecorder()
	srv.ServeHTTP(recAll, reqAll)
	var all []store.TelemetryReading
	if err := json.Unmarshal(recAll.Body.Bytes(), &all); err != nil {
		t.Fatalf("unmarshal all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 readings across all devices, got %d", len(all))
	}
}

func TestTelemetryEndpointClampsExcessiveLimit(t *testing.T) {
	srv, gw := newTestServer(t)

	for i := 0; i < 3; i++ {
		if err := gw.Store.RecordTelemetry(store.TelemetryReading{
			DeviceID: "clamp-dev", RawPayload: "x=1", ReceivedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed telemetry: %v", err)
		}
	}

	// Явно завышенный limit не должен приводить к ошибке — он должен
	// молча клэмпиться к разумному потолку (maxTelemetryLimit), а не
	// передаваться в хранилище как есть.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/telemetry?device_id=clamp-dev&limit=999999999", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for oversized limit (should be clamped, not rejected), got %d, body=%s", rec.Code, rec.Body.String())
	}
	var readings []store.TelemetryReading
	if err := json.Unmarshal(rec.Body.Bytes(), &readings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(readings) != 3 {
		t.Fatalf("expected all 3 seeded readings back, got %d", len(readings))
	}
}

func TestTelemetryEndpointRejectsBadRangeParam(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/telemetry?range=not-a-duration", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid range, got %d", rec.Code)
	}
}

func TestRotationsEndpoint(t *testing.T) {
	srv, gw := newTestServer(t)

	must := func(err error) {
		if err != nil {
			t.Fatalf("log rotation: %v", err)
		}
	}
	must(gw.Store.LogRotation(store.RotationLogEntry{DeviceID: "rot-dev-1", Initiator: "device", Success: true, RotationCount: 1}))
	must(gw.Store.LogRotation(store.RotationLogEntry{DeviceID: "rot-dev-1", Initiator: "gateway", Success: false, ErrorText: "boom", RotationCount: 2}))
	must(gw.Store.LogRotation(store.RotationLogEntry{DeviceID: "rot-dev-2", Initiator: "device", Success: true, RotationCount: 1}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rotations?device_id=rot-dev-1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var entries []store.RotationLogEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for rot-dev-1, got %d", len(entries))
	}

	reqAll := httptest.NewRequest(http.MethodGet, "/api/v1/rotations", nil)
	recAll := httptest.NewRecorder()
	srv.ServeHTTP(recAll, reqAll)
	var all []store.RotationLogEntry
	if err := json.Unmarshal(recAll.Body.Bytes(), &all); err != nil {
		t.Fatalf("unmarshal all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries across all devices, got %d", len(all))
	}
}

func TestTelemetryAndRotationsRequireAuthWhenTokenConfigured(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := New(gw, Options{AdminToken: "secret"})

	for _, path := range []string{"/api/v1/telemetry", "/api/v1/rotations"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401 without token, got %d", path, rec.Code)
		}
	}
}

func TestDeviceResponseIncludesLastTelemetry(t *testing.T) {
	srv, gw := newTestServer(t)

	dev, _ := device.NewDevice("tel-summary-device", crypto.SigECDSAP256, []byte("fw"))
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := dev.SerialRegistrationOutput()
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := gw.Store.RecordTelemetry(store.TelemetryReading{
		DeviceID:   "tel-summary-device",
		RawPayload: "temperature=22.5",
		Parsed:     map[string]float64{"temperature": 22.5},
		ReceivedAt: time.Now(),
	}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/tel-summary-device", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var got deviceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.LastTelemetry == nil {
		t.Fatal("expected last_telemetry to be populated")
	}
	if got.LastTelemetry.Parsed["temperature"] != 22.5 {
		t.Fatalf("expected temperature=22.5, got %v", got.LastTelemetry.Parsed)
	}
}

func TestHealthz(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAdminAuthRequiredWhenTokenConfigured(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := New(gw, Options{AdminToken: "super-secret-token"})
	if srv.AuthMode() != "bearer-token" {
		t.Fatalf("expected bearer-token auth mode, got %q", srv.AuthMode())
	}

	// Без токена — отказ.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	// С неверным токеном — отказ.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req2.Header.Set("Authorization", "Bearer wrong-token")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", rec2.Code)
	}

	// С верным токеном — успех.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req3.Header.Set("Authorization", "Bearer super-secret-token")
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d, body=%s", rec3.Code, rec3.Body.String())
	}

	// /healthz и /api/v1/gateway остаются открытыми даже при включённой
	// аутентификации: первый нужен liveness-пробам, второй — устройствам,
	// которые забирают оттуда публичный ключ шлюза до всякой авторизации.
	for _, path := range []string{"/healthz", "/api/v1/gateway"} {
		openReq := httptest.NewRequest(http.MethodGet, path, nil)
		openRec := httptest.NewRecorder()
		srv.ServeHTTP(openRec, openReq)
		if openRec.Code != http.StatusOK {
			t.Fatalf("%s должен оставаться открытым, получено %d", path, openRec.Code)
		}
	}
}

// Метрики раскрывают эксплуатационную картину шлюза (сколько устройств,
// рукопожатий, провалов проверки прошивки), поэтому при включённой
// аутентификации они не должны отдаваться без токена.
func TestMetricsRequireAuth(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := New(gw, Options{AdminToken: "super-secret-token"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("метрики без токена: ожидался 401, получено %d", rec.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	authReq.Header.Set("Authorization", "Bearer super-secret-token")
	authRec := httptest.NewRecorder()
	srv.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("метрики с токеном: ожидался 200, получено %d", authRec.Code)
	}
}

// /api/v1/gateway обязан работать без токена (устройству нужен публичный ключ
// шлюза до рукопожатия), но служебные поля должен отдавать только
// авторизованному запросу.
func TestGatewayInfoHidesOperationalFieldsWithoutAuth(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	gw.LogSessionKeys = true
	srv := New(gw, Options{AdminToken: "super-secret-token"})

	decode := func(t *testing.T, token string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ожидался 200, получено %d", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("разбор ответа: %v", err)
		}
		return body
	}

	anon := decode(t, "")
	if anon["kem_pub_hex"] == "" || anon["kem_pub_hex"] == nil {
		t.Error("публичный ключ шлюза должен отдаваться без токена")
	}
	if _, leaked := anon["log_session_keys"]; leaked {
		t.Error("log_session_keys не должен раскрываться без токена")
	}

	authed := decode(t, "super-secret-token")
	if got, ok := authed["log_session_keys"].(bool); !ok || !got {
		t.Errorf("с токеном ожидалось log_session_keys=true, получено %v", authed["log_session_keys"])
	}

	// Неверный токен приравнивается к анонимному запросу: ключ отдаём,
	// служебные поля — нет.
	wrong := decode(t, "wrong-token")
	if _, leaked := wrong["log_session_keys"]; leaked {
		t.Error("log_session_keys не должен раскрываться по неверному токену")
	}
}

// По умолчанию кросс-доменные запросы не разрешаются: дашборд отдаётся с того
// же origin, а раньше пустой список origin означал "*", то есть любой сайт мог
// обращаться к API шлюза из браузера пользователя.
func TestCORSClosedByDefault(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("без настройки origin заголовок CORS не должен выставляться, получено %q", got)
	}

	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	allowed := New(gw, Options{AllowedOrigins: []string{"https://ops.example"}})
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/gateway", nil)
	req2.Header.Set("Origin", "https://ops.example")
	rec2 := httptest.NewRecorder()
	allowed.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "https://ops.example" {
		t.Errorf("разрешённый origin должен отражаться в ответе, получено %q", got)
	}
}

func TestAdminAuthDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	if srv.AuthMode() != "disabled" {
		t.Fatalf("expected auth disabled by default, got %q", srv.AuthMode())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without token when auth disabled, got %d", rec.Code)
	}
}

func TestDeviceResponseReflectsOnlineStatusFromTCPServer(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	tcpSrv := tcpserver.New(gw, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := New(gw, Options{TCPStatus: tcpSrv})

	dev, _ := device.NewDevice("api-esp32-online", crypto.SigECDSAP256, []byte("fw"))
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, _ := dev.SerialRegistrationOutput()
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Без активного TCP-соединения устройство должно быть offline.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/api-esp32-online", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var got deviceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Online {
		t.Fatal("expected device to be reported offline with no active TCP connection")
	}

	// Поднимаем настоящее TCP-соединение и проверяем, что статус становится online.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { _ = tcpSrv.Serve(ln) }()

	client, err := tcpclient.Dial(ln.Addr().String(), dev, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	go client.Listen() //nolint:errcheck

	deadline := time.Now().Add(2 * time.Second)
	for {
		req2 := httptest.NewRequest(http.MethodGet, "/api/v1/devices/api-esp32-online", nil)
		rec2 := httptest.NewRecorder()
		srv.ServeHTTP(rec2, req2)
		var got2 deviceResponse
		_ = json.Unmarshal(rec2.Body.Bytes(), &got2)
		if got2.Online {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("device never reported online after establishing TCP connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Разбор имени схемы (parseSigAlgorithm) и его формирование
// (crypto.SigAlgorithm.APIName) заданы в разных пакетах и могут разойтись при
// правке одного без другого. Именно такое расхождение уже приводило к ошибке:
// эмулятор писал имя вручную, устройство регистрировалось под чужой схемой и
// не могло завершить рукопожатие. Тест замыкает круг: имя, полученное из
// алгоритма, обязано разбираться обратно в тот же алгоритм.
func TestSigAlgorithmNameRoundTrip(t *testing.T) {
	for _, alg := range []crypto.SigAlgorithm{crypto.SigECDSAP256, crypto.SigSLHDSA} {
		name := alg.APIName()
		if name == "" {
			t.Fatalf("%v: APIName пустое — схема не имеет имени для REST", alg)
		}
		got, err := parseSigAlgorithm(name)
		if err != nil {
			t.Fatalf("%v: имя %q не разбирается обратно: %v", alg, name, err)
		}
		if got != alg {
			t.Fatalf("%v: имя %q разобралось как %v", alg, name, got)
		}
	}

	// Ed25519 намеренно не имеет имени и не принимается REST API: схема
	// сохранена в ядре только как инструмент сравнительных измерений.
	if n := crypto.SigEd25519.APIName(); n != "" {
		t.Fatalf("Ed25519 не должен иметь имени для REST, получено %q", n)
	}
	if _, err := parseSigAlgorithm("ed25519"); err == nil {
		t.Fatal("REST API не должен принимать ed25519")
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	srv, _ := newTestServer(t)

	// Заголовки должны стоять на всех ответах, включая публичные эндпоинты.
	for _, path := range []string{"/healthz", "/api/v1/gateway", "/api/v1/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		want := map[string]string{
			"X-Content-Type-Options":  "nosniff",
			"X-Frame-Options":         "DENY",
			"Referrer-Policy":         "no-referrer",
			"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
		}
		for h, exp := range want {
			if got := rec.Header().Get(h); got != exp {
				t.Errorf("%s: заголовок %s = %q, ожидалось %q", path, h, got, exp)
			}
		}
	}
}
