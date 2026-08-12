package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
)

// enrolBody собирает тело запроса регистрации для устройства.
func enrolBody(t *testing.T, gw *gateway.Gateway, id string, firmware []byte) []byte {
	t.Helper()
	dev, err := device.NewDevice(id, crypto.SigECDSAP256, firmware)
	if err != nil {
		t.Fatalf("создание устройства: %v", err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatalf("вывод для регистрации: %v", err)
	}
	body, _ := json.Marshal(registerDeviceRequest{
		DeviceID:        serial.DeviceID,
		IdentityPubHex:  hex.EncodeToString(serial.IdentityPub),
		KEMPubHex:       hex.EncodeToString(serial.KEMPub),
		FirmwareHashHex: hex.EncodeToString(serial.FirmwareHash[:]),
		Checksum:        serial.Checksum,
		SigAlgorithm:    "ecdsa-p256",
	})
	return body
}

func do(t *testing.T, srv *Server, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	return rec
}

// Перерегистрация через интерфейс заменяет ключи и отвечает кодом успеха.
func TestReregisterDeviceEndpoint(t *testing.T) {
	srv, gw := newTestServer(t)
	firmware := []byte("прошивка")

	if rec := do(t, srv, http.MethodPost, "/api/v1/devices",
		enrolBody(t, gw, "api-reenroll", firmware)); rec.Code != http.StatusCreated {
		t.Fatalf("регистрация: ожидался 201, получен %d: %s", rec.Code, rec.Body.String())
	}
	before, _ := gw.Store.Get("api-reenroll")

	// Повторная регистрация тем же путём по-прежнему отвергается.
	if rec := do(t, srv, http.MethodPost, "/api/v1/devices",
		enrolBody(t, gw, "api-reenroll", firmware)); rec.Code == http.StatusCreated {
		t.Error("повторная регистрация через POST не должна проходить")
	}

	rec := do(t, srv, http.MethodPut, "/api/v1/devices/api-reenroll",
		enrolBody(t, gw, "api-reenroll", firmware))
	if rec.Code != http.StatusOK {
		t.Fatalf("перерегистрация: ожидался 200, получен %d: %s", rec.Code, rec.Body.String())
	}

	after, _ := gw.Store.Get("api-reenroll")
	if bytes.Equal(before.IdentityPub, after.IdentityPub) {
		t.Error("ключ подписи должен был смениться")
	}
}

// Несовпадение идентификатора в пути и в теле отвергается. Молча брать
// значение из тела значило бы, что обращение по одному адресу меняет ключи у
// другого устройства, а брать из пути нельзя: контрольная сумма считается в
// том числе по идентификатору и после подмены перестанет сходиться.
func TestReregisterRejectsIdentifierMismatch(t *testing.T) {
	srv, gw := newTestServer(t)
	firmware := []byte("прошивка")

	for _, id := range []string{"api-victim", "api-target"} {
		if rec := do(t, srv, http.MethodPost, "/api/v1/devices",
			enrolBody(t, gw, id, firmware)); rec.Code != http.StatusCreated {
			t.Fatalf("регистрация %s: %d", id, rec.Code)
		}
	}
	victimBefore, _ := gw.Store.Get("api-victim")

	// В теле одно устройство, в пути другое.
	body := enrolBody(t, gw, "api-victim", firmware)
	rec := do(t, srv, http.MethodPut, "/api/v1/devices/api-target", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("несовпадение идентификаторов должно отвергаться, получен %d: %s",
			rec.Code, rec.Body.String())
	}

	victimAfter, _ := gw.Store.Get("api-victim")
	if !bytes.Equal(victimBefore.IdentityPub, victimAfter.IdentityPub) {
		t.Error("ключи устройства из тела запроса меняться не должны")
	}
	targetAfter, _ := gw.Store.Get("api-target")
	if !bytes.Equal(targetAfter.IdentityPub, targetAfter.IdentityPub) {
		t.Error("ключи устройства из пути тоже меняться не должны")
	}
}

// Перерегистрация несуществующего устройства даёт код отсутствия, а не общий
// отказ: оператору важно отличить опечатку в идентификаторе от испорченных
// данных.
func TestReregisterUnknownReturnsNotFound(t *testing.T) {
	srv, gw := newTestServer(t)
	rec := do(t, srv, http.MethodPut, "/api/v1/devices/api-nonexistent",
		enrolBody(t, gw, "api-nonexistent", []byte("прошивка")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получен %d: %s", rec.Code, rec.Body.String())
	}
}

// Удаление убирает запись и освобождает идентификатор.
func TestDeleteDeviceEndpoint(t *testing.T) {
	srv, gw := newTestServer(t)
	firmware := []byte("прошивка")

	if rec := do(t, srv, http.MethodPost, "/api/v1/devices",
		enrolBody(t, gw, "api-todelete", firmware)); rec.Code != http.StatusCreated {
		t.Fatalf("регистрация: %d", rec.Code)
	}

	rec := do(t, srv, http.MethodDelete, "/api/v1/devices/api-todelete", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("удаление: ожидался 204, получен %d: %s", rec.Code, rec.Body.String())
	}

	if rec := do(t, srv, http.MethodGet, "/api/v1/devices/api-todelete", nil); rec.Code != http.StatusNotFound {
		t.Errorf("после удаления устройство не должно находиться, получен %d", rec.Code)
	}
	// Идентификатор снова свободен.
	if rec := do(t, srv, http.MethodPost, "/api/v1/devices",
		enrolBody(t, gw, "api-todelete", firmware)); rec.Code != http.StatusCreated {
		t.Errorf("после удаления регистрация должна проходить, получен %d", rec.Code)
	}
}

// Удаление несуществующего устройства даёт код отсутствия.
func TestDeleteUnknownReturnsNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, http.MethodDelete, "/api/v1/devices/api-never-existed", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получен %d: %s", rec.Code, rec.Body.String())
	}
}

// Отозванное устройство удалять можно: именно так оператор освобождает
// идентификатор, когда возвращать плату в строй всё же нужно.
func TestDeleteRevokedDeviceWorks(t *testing.T) {
	srv, gw := newTestServer(t)
	firmware := []byte("прошивка")

	if rec := do(t, srv, http.MethodPost, "/api/v1/devices",
		enrolBody(t, gw, "api-revoked-del", firmware)); rec.Code != http.StatusCreated {
		t.Fatalf("регистрация: %d", rec.Code)
	}
	if err := gw.RevokeDevice("api-revoked-del", "проверка"); err != nil {
		t.Fatalf("отзыв: %v", err)
	}

	if rec := do(t, srv, http.MethodDelete, "/api/v1/devices/api-revoked-del", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("удаление отозванного: ожидался 204, получен %d: %s", rec.Code, rec.Body.String())
	}
}

// Новые действия должны быть закрыты авторизацией наравне с остальными:
// перерегистрация подменяет ключи, удаление стирает историю.
func TestLifecycleEndpointsRequireAuth(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatalf("создание шлюза: %v", err)
	}
	srv := New(gw, Options{AdminToken: "секрет"})

	for _, c := range []struct {
		method, path string
	}{
		{http.MethodPut, "/api/v1/devices/any"},
		{http.MethodDelete, "/api/v1/devices/any"},
	} {
		rec := do(t, srv, c.method, c.path, []byte("{}"))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s без токена: ожидался 401, получен %d", c.method, c.path, rec.Code)
		}
	}
}
