package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lacert/internal/gateway"
)

// После десяти неверных токенов подряд с одного адреса одиннадцатая попытка
// получает 429 с заголовком Retry-After, и даже верный токен с того же адреса
// в этом окне не проходит. Другой адрес лимит не задевает.
func TestAdminAuthLimitsFailedAttemptsPerAddress(t *testing.T) {
	gw, err := gateway.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := New(gw, Options{AdminToken: "right-token"})

	do := func(addr, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rotations", nil)
		req.RemoteAddr = addr
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.Router.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < authFailLimit; i++ {
		if rec := do("10.0.0.7:5000", "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("попытка %d: ожидался 401, получен %d", i+1, rec.Code)
		}
	}
	rec := do("10.0.0.7:5001", "wrong")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("после %d неудач ожидался 429, получен %d", authFailLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("нет заголовка Retry-After")
	}
	if rec := do("10.0.0.7:5002", "right-token"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("верный токен в окне блокировки должен получать 429, получен %d", rec.Code)
	}
	if rec := do("10.0.0.8:5000", "right-token"); rec.Code != http.StatusOK {
		t.Fatalf("другой адрес не должен быть заблокирован, получен %d", rec.Code)
	}
}

// Окно истекает — адрес снова может пробовать, а протухшие записи чистятся.
func TestAuthLimiterWindowExpires(t *testing.T) {
	l := newAuthLimiter(3, time.Minute)
	start := time.Now()
	for i := 0; i < 3; i++ {
		l.fail("a", start)
	}
	if _, blocked := l.blocked("a", start.Add(30*time.Second)); !blocked {
		t.Fatal("внутри окна адрес должен быть заблокирован")
	}
	if wait, _ := l.blocked("a", start.Add(30*time.Second)); wait <= 0 || wait > time.Minute {
		t.Fatalf("странное время ожидания %v", wait)
	}
	if _, blocked := l.blocked("a", start.Add(time.Minute)); blocked {
		t.Fatal("после окна адрес должен быть свободен")
	}
	l.fail("b", start)
	l.fail("c", start.Add(2*time.Minute))
	if _, ok := l.fails["b"]; ok {
		t.Fatal("протухшая запись b не вычищена")
	}
}
