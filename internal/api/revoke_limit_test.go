package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lacert/internal/crypto"
	"lacert/internal/device"
	"lacert/internal/gateway"
)

// До 1.4.11 отзыв принимал тело и причину любого размера. Причина на 5 МБ
// ложилась в запись устройства целиком, после чего каждое обновление панели
// тянуло её в списке устройств. Тесты ниже закрепляют пределы и заодно то,
// что обычный отзыв и отзыв без тела работают как раньше.

func revokeTestServer(t *testing.T) (*Server, *gateway.Gateway) {
	t.Helper()
	gw, err := gateway.New()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := device.NewDevice("revoke-limit-001", crypto.SigECDSAP256, []byte("fw"))
	if err != nil {
		t.Fatal(err)
	}
	dev.SetGatewayKEMPublicKey(gw.GatewayKEMPublicKey())
	serial, err := dev.SerialRegistrationOutput()
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.RegisterDevice(serial, crypto.SigECDSAP256); err != nil {
		t.Fatal(err)
	}
	return New(gw, Options{}), gw
}

func revoke(srv *Server, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/revoke-limit-001/revoke", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestRevokeRejectsOversizedBody(t *testing.T) {
	srv, gw := revokeTestServer(t)
	body, _ := json.Marshal(map[string]string{"reason": strings.Repeat("x", 5<<20)})
	if rec := revoke(srv, body); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("тело на 5 МБ: ожидался 413, получен %d", rec.Code)
	}
	d, err := gw.Store.Get("revoke-limit-001")
	if err != nil {
		t.Fatal(err)
	}
	if d.Revoked {
		t.Fatal("отзыв выполнился, хотя тело отвергнуто")
	}
}

func TestRevokeRejectsOverlongReason(t *testing.T) {
	srv, gw := revokeTestServer(t)
	// 257 знаков кириллицей — больше предела по знакам, но меньше предела тела
	// в байтах, чтобы проверялся именно предел причины.
	body, _ := json.Marshal(map[string]string{"reason": strings.Repeat("я", maxRevokeReasonRunes+1)})
	if rec := revoke(srv, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("причина длиннее предела: ожидался 400, получен %d", rec.Code)
	}
	if d, _ := gw.Store.Get("revoke-limit-001"); d.Revoked {
		t.Fatal("отзыв выполнился, хотя причина длиннее предела")
	}
}

func TestRevokeAcceptsReasonAtLimitAndEmptyBody(t *testing.T) {
	srv, gw := revokeTestServer(t)
	reason := strings.Repeat("я", maxRevokeReasonRunes)
	body, _ := json.Marshal(map[string]string{"reason": reason})
	if rec := revoke(srv, body); rec.Code != http.StatusNoContent {
		t.Fatalf("причина ровно на пределе: ожидался 204, получен %d", rec.Code)
	}
	d, _ := gw.Store.Get("revoke-limit-001")
	if !d.Revoked || d.RevokedReason != reason {
		t.Fatalf("причина на пределе не сохранилась целиком: revoked=%v, длина %d", d.Revoked, len([]rune(d.RevokedReason)))
	}

	srv2, gw2 := revokeTestServer(t)
	if rec := revoke(srv2, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("отзыв без тела: ожидался 204, получен %d", rec.Code)
	}
	if d, _ := gw2.Store.Get("revoke-limit-001"); !d.Revoked || d.RevokedReason == "" {
		t.Fatal("отзыв без тела должен пройти с причиной по умолчанию")
	}
}

func TestRevokeRejectsMalformedJSON(t *testing.T) {
	srv, gw := revokeTestServer(t)
	if rec := revoke(srv, []byte(`{"reason": `)); rec.Code != http.StatusBadRequest {
		t.Fatalf("испорченный JSON: ожидался 400, получен %d", rec.Code)
	}
	if d, _ := gw.Store.Get("revoke-limit-001"); d.Revoked {
		t.Fatal("отзыв выполнился на испорченном JSON")
	}
}
