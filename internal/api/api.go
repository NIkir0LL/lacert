// Package api реализует REST API шлюза — интерфейс для администрирования
// (консольная утилита офлайн-регистрации обращается сюда) и для
// корпоративной информационной системы (просмотр статуса устройств и
// журнала событий). Сам защищённый канал с устройствами (рукопожатие,
// данные, ротация) идёт по отдельному TCP-протоколу LACERT
// (internal/transport/tcpserver) — REST API его не заменяет, а дополняет
// слоем управления и наблюдаемости.
package api

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/gateway"
	"lacert/internal/regtool"
	"lacert/internal/store"
	"lacert/internal/transport/tcpserver"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// Options — настройки REST API, важные для развёртывания за веб-страницей:
// CORS (браузер будет ходить с другого origin) и аутентификация админских
// эндпоинтов (регистрация/отзыв устройств не должны быть открыты всем).
type Options struct {
	// TCPStatus — ссылка на TCP-сервер шлюза, чтобы GET /devices/{id} мог
	// сообщить, online ли устройство прямо сейчас. Может быть nil (например,
	// в тестах, где TCP-сервер не поднят) — тогда поле online просто не
	// возвращается.
	TCPStatus *tcpserver.Server

	// AdminToken — если задан, все мутирующие и просматривающие админские
	// эндпоинты (/api/v1/devices*) требуют заголовок
	// "Authorization: Bearer <AdminToken>". Если пусто — аутентификация
	// выключена (подходит для локальной разработки, НЕ для прода).
	AdminToken string

	// AllowedOrigins — список разрешённых CORS-origin для браузерных
	// запросов с веб-страницы регистрации. Если пусто, CORS-заголовки не
	// выставляются вовсе: встроенный дашборд отдаётся с того же origin, что и
	// API, и в кросс-доменных разрешениях не нуждается, а сторонние страницы
	// по умолчанию доступа не получают. Чтобы разрешить конкретные внешние
	// origin, перечислите их явно (LACERT_CORS_ORIGINS). Значение "*"
	// по-прежнему допустимо, но задаётся только осознанно.
	AllowedOrigins []string
}

// Server — HTTP-обработчик REST API шлюза.
type Server struct {
	GW     *gateway.Gateway
	TCPSrv *tcpserver.Server
	Router chi.Router
	// adminToken хранится, чтобы обработчики могли проверить авторизацию сами,
	// а не только через middleware. Это нужно эндпоинту /api/v1/gateway: он
	// обязан оставаться открытым (устройства берут оттуда публичный ключ шлюза
	// до всякой авторизации), но часть полей ответа выдаёт только по токену.
	adminToken string
	authMode   string // "disabled" | "bearer-token" — для логирования при старте
}

// New создаёт REST API поверх уже настроенного gateway.Gateway.
func New(gw *gateway.Gateway, opts Options) *Server {
	s := &Server{GW: gw, TCPSrv: opts.TCPStatus, adminToken: opts.AdminToken}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(securityHeaders)
	// CORS включаем только если origin перечислены явно. Пустой список —
	// значит кросс-доменный доступ не нужен: дашборд живёт на том же origin.
	// Раньше пустой список означал "*", то есть любой сайт в браузере
	// пользователя мог обращаться к API шлюза.
	if len(opts.AllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins: opts.AllowedOrigins,
			// PUT и DELETE нужны для перерегистрации и удаления устройства.
			// Без них браузер отклонил бы такой запрос ещё до отправки, и
			// кросс-доменный дашборд не смог бы этими действиями
			// воспользоваться.
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Content-Type", "Authorization"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// /api/v1/gateway остаётся без обязательной авторизации намеренно: с него
	// устройство (прошивка ESP32, отладочный клиент, эмулятор) забирает
	// публичный ML-KEM-ключ шлюза перед первым рукопожатием, когда никакого
	// токена у него нет. Открыт только сам публичный ключ — служебные поля
	// обработчик отдаёт лишь авторизованному запросу.
	r.Get("/api/v1/gateway", s.getGatewayInfo)

	r.Route("/api/v1", func(r chi.Router) {
		if opts.AdminToken != "" {
			r.Use(adminAuth(opts.AdminToken))
			s.authMode = "bearer-token"
		} else {
			s.authMode = "disabled"
		}
		r.Route("/devices", func(r chi.Router) {
			r.Get("/", s.listDevices)
			r.Post("/", s.registerDevice)
			r.Get("/{deviceID}", s.getDevice)
			r.Get("/{deviceID}/events", s.getDeviceEvents)
			r.Put("/{deviceID}", s.reregisterDevice)
			r.Delete("/{deviceID}", s.deleteDevice)
			r.Post("/{deviceID}/revoke", s.revokeDevice)
		})
		r.Get("/telemetry", s.getTelemetry)
		r.Get("/rotations", s.getRotations)
		r.Get("/firmware-checks", s.getFirmwareChecks)
		// Метрики — эксплуатационные данные (сколько устройств, рукопожатий,
		// отказов проверки прошивки). Открытыми они дают наблюдателю картину
		// работы шлюза, поэтому идут под той же авторизацией, что и остальная
		// админская часть. Потребители (дашборд, stresstest) токен передают.
		r.Get("/metrics", s.getMetrics)
	})

	s.Router = r
	return s
}

// AuthMode сообщает, включена ли аутентификация админских эндпоинтов —
// используется при старте cmd/gatewayd, чтобы явно предупредить, если
// сервис поднимается без токена (например, по ошибке в проде).
func (s *Server) AuthMode() string { return s.authMode }

// securityHeaders добавляет базовые защитные HTTP-заголовки ко всем ответам.
// Это defense-in-depth: разметка дашборда уже экранирует данные (escapeHTML),
// но заголовки не дают браузеру угадывать MIME-тип (nosniff), встраивать
// интерфейс в чужой iframe (clickjacking) и течь реферером на внешние сайты.
// CSP намеренно консервативна: ресурсы только со своего origin, что
// согласуется с тем, что дашборд не подключает сторонние скрипты и стили.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// adminAuth — простая bearer-token аутентификация для админских эндпоинтов.
// Намеренно простая (один статический токен, не JWT/OAuth): достаточно для
// "веб-страницы регистрации устройств в изолированной корпоративной сети",
// которая ставится перед REST API, не более того. Сравнение токена — за
// константное время, чтобы не давать атакующему канал для тайминг-атаки на
// угадывание токена побайтово.
func adminAuth(expectedToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(authHeader, "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
				writeError(w, http.StatusUnauthorized, errUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

var errUnauthorized = httpError("unauthorized: missing or invalid Authorization: Bearer <token>")

type httpError string

func (e httpError) Error() string { return string(e) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Router.ServeHTTP(w, r)
}

// --- DTO ---

// registerDeviceRequest — тело запроса для POST /api/v1/devices. Поддерживает
// два равноценных способа передать данные, считанные администратором с
// Serial-порта устройства:
//   - SerialLine: вся строка целиком, как её печатает устройство (см.
//     regtool.SerialOutput.String) — самый простой путь для веб-формы:
//     администратор вставляет одну строку, остальное разбирается само.
//   - Отдельные поля (DeviceID/IdentityPubHex/KEMPubHex/FirmwareHashHex/
//     Checksum) — для программных клиентов (например, internal/emulator)
//     или ручного ввода по полям.
//
// FirmwareHashHex — это ХЕШ прошивки (32 байта, hex), а не сама прошивка:
// устройство никогда не передаёт образ прошивки целиком ни на регистрации,
// ни при последующих проверках целостности (см. internal/crypto/firmware.go).
type registerDeviceRequest struct {
	SerialLine string `json:"serial_line,omitempty"`

	DeviceID        string `json:"device_id,omitempty"`
	IdentityPubHex  string `json:"identity_pub_hex,omitempty"`
	KEMPubHex       string `json:"kem_pub_hex,omitempty"`
	FirmwareHashHex string `json:"firmware_hash_hex,omitempty"`
	Checksum        string `json:"checksum,omitempty"`

	SigAlgorithm string `json:"sig_algorithm"` // "ecdsa-p256" (по умолчанию) | "slh-dsa"
}

func (req registerDeviceRequest) toSerialOutput() (regtool.SerialOutput, error) {
	if req.SerialLine != "" {
		return regtool.Parse(req.SerialLine)
	}

	identityPub, err := hex.DecodeString(req.IdentityPubHex)
	if err != nil {
		return regtool.SerialOutput{}, fmt.Errorf("identity_pub_hex: %w", err)
	}
	kemPub, err := hex.DecodeString(req.KEMPubHex)
	if err != nil {
		return regtool.SerialOutput{}, fmt.Errorf("kem_pub_hex: %w", err)
	}
	firmwareHashBytes, err := hex.DecodeString(req.FirmwareHashHex)
	if err != nil {
		return regtool.SerialOutput{}, fmt.Errorf("firmware_hash_hex: %w", err)
	}
	if len(firmwareHashBytes) != crypto.FirmwareHashSize {
		return regtool.SerialOutput{}, fmt.Errorf("firmware_hash_hex: ожидается %d байт, получено %d", crypto.FirmwareHashSize, len(firmwareHashBytes))
	}
	var firmwareHash [crypto.FirmwareHashSize]byte
	copy(firmwareHash[:], firmwareHashBytes)

	return regtool.SerialOutput{
		DeviceID:     req.DeviceID,
		IdentityPub:  identityPub,
		KEMPub:       kemPub,
		FirmwareHash: firmwareHash,
		Checksum:     req.Checksum,
	}, nil
}

type telemetrySummary struct {
	RawPayload string             `json:"raw_payload"`
	Parsed     map[string]float64 `json:"parsed,omitempty"`
	ReceivedAt string             `json:"received_at"`
}

type deviceResponse struct {
	DeviceID      string            `json:"device_id"`
	SigAlgorithm  string            `json:"sig_algorithm"`
	Revoked       bool              `json:"revoked"`
	RevokedReason string            `json:"revoked_reason,omitempty"`
	CreatedAt     string            `json:"created_at"`
	Online        bool              `json:"online"`
	RemoteAddr    string            `json:"remote_addr,omitempty"`
	LastSeen      *string           `json:"last_seen,omitempty"`
	LastTelemetry *telemetrySummary `json:"last_telemetry,omitempty"`
}

// toDeviceResponse собирает ответ по одному устройству, запрашивая его последнюю
// телеметрию отдельно. Для списка устройств используйте toDeviceResponseWith:
// иначе на каждое устройство уйдёт свой запрос к БД (N+1).
func (s *Server) toDeviceResponse(rec *store.DeviceRecord) deviceResponse {
	var latest *store.TelemetryReading
	if l, err := s.GW.Store.LatestTelemetry(rec.DeviceID); err == nil {
		latest = l
	}
	return s.toDeviceResponseWith(rec, latest)
}

// toDeviceResponseWith — та же сборка, но с уже полученной телеметрией.
func (s *Server) toDeviceResponseWith(rec *store.DeviceRecord, latest *store.TelemetryReading) deviceResponse {
	resp := deviceResponse{
		DeviceID:      rec.DeviceID,
		SigAlgorithm:  rec.SigAlgorithm.String(),
		Revoked:       rec.Revoked,
		RevokedReason: rec.RevokedReason,
		CreatedAt:     rec.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if s.TCPSrv != nil {
		if status, ok := s.TCPSrv.Status(rec.DeviceID); ok {
			resp.Online = status.Online
			resp.RemoteAddr = status.RemoteAddr
			lastSeen := status.LastSeen.Format("2006-01-02T15:04:05Z07:00")
			resp.LastSeen = &lastSeen
		}
	}
	if latest != nil {
		resp.LastTelemetry = &telemetrySummary{
			RawPayload: latest.RawPayload,
			Parsed:     latest.Parsed,
			ReceivedAt: latest.ReceivedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	return resp
}

// parseSigAlgorithm разбирает значение поля sig_algorithm при регистрации.
//
// Пустое значение допускается ради совместимости: устройства, не указывающие
// алгоритм, получают основной вариант протокола. Незнакомое значение — ошибка,
// а не молчаливый переход к значению по умолчанию: опечатка вроде "ecdsa-p265"
// иначе прошла бы регистрацию незамеченной, а расхождение проявилось бы только
// при первом рукопожатии, когда причину установить уже труднее.
//
// Ed25519 поддерживается ядром (см. internal/crypto) как инструмент
// сравнительных измерений, но устройством не используется и потому здесь не
// принимается: объявлять возможность, которой ни одна прошивка не располагает,
// значило бы вводить в заблуждение.
func parseSigAlgorithm(s string) (crypto.SigAlgorithm, error) {
	switch s {
	case "", "ecdsa-p256":
		return crypto.SigECDSAP256, nil
	case "slh-dsa":
		return crypto.SigSLHDSA, nil
	default:
		return 0, fmt.Errorf("неизвестная схема подписи %q: допустимы \"ecdsa-p256\" и \"slh-dsa\"", s)
	}
}

// --- handlers ---

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	recs, err := s.GW.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Последние показания всех устройств берём ОДНИМ запросом. Раньше здесь
	// вызывался LatestTelemetry на каждое устройство: при 500 устройствах это
	// 500 запросов к базе на одно открытие дашборда (N+1), и ответ занимал
	// сотни миллисекунд.
	latestAll, err := s.GW.Store.LatestTelemetryAll()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]deviceResponse, 0, len(recs))
	for i := range recs {
		var latest *store.TelemetryReading
		if t, ok := latestAll[recs[i].DeviceID]; ok {
			latest = &t
		}
		out = append(out, s.toDeviceResponseWith(&recs[i], latest))
	}
	writeJSON(w, http.StatusOK, out)
}

// registerDevice — REST-эквивалент консольной утилиты офлайн-регистрации:
// администратор переносит данные, считанные с Serial-порта устройства, в
// этот эндпоинт. Контрольная сумма проверяется так же, как и в
// internal/regtool, чтобы исключить опечатки при ручном переносе.
// reregisterDevice заменяет ключи уже зарегистрированного устройства.
//
// Отдельный метод, а не повторный POST: создание и замена — разные действия с
// разными последствиями, и путать их опасно. Повторный POST по-прежнему
// отвергается, поэтому случайно затереть ключи работающего устройства
// нельзя — для этого нужно обратиться именно сюда.
func (s *Server) reregisterDevice(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)

	var req registerDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Идентификатор в пути и в теле должен совпадать. Подменять одно другим
	// нельзя: контрольная сумма считается в том числе по идентификатору, и
	// после подмены перестала бы сходиться. А молча брать значение из тела
	// значило бы, что обращение по одному адресу меняет ключи у другого
	// устройства.
	if pathID := chi.URLParam(r, "deviceID"); pathID != req.DeviceID {
		writeError(w, http.StatusBadRequest,
			fmt.Errorf("device_id in body (%q) does not match the one in path (%q)",
				req.DeviceID, pathID))
		return
	}

	serial, err := req.toSerialOutput()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sigAlg, err := parseSigAlgorithm(req.SigAlgorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.GW.ReregisterDevice(serial, sigAlg); err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// deleteDevice полностью убирает устройство из реестра вместе с историей.
//
// Не путать с отзывом: отозванное устройство остаётся видно оператору вместе
// с причиной, удалённое исчезает бесследно.
func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	if err := s.GW.DeleteDevice(deviceID); err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	// Ограничение размера тела: самая большая легитимная регистрация — это
	// KEM-ключ (1568 байт) в hex плюс подпись и служебные поля, то есть
	// единицы килобайт. Без ограничения json.Decode читал бы поток любой
	// длины в память, и один запрос мог бы исчерпать её.
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)

	var req registerDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	serial, err := req.toSerialOutput()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	sigAlg, err := parseSigAlgorithm(req.SigAlgorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.GW.RegisterDevice(serial, sigAlg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	rec, err := s.GW.Store.Get(deviceID)
	// errors.Is, а не ==: реализации хранилища вправе обернуть ошибку
	// (fmt.Errorf с %w), и тогда прямое сравнение перестало бы узнавать
	// «устройство отозвано» — отозванное устройство пропадало бы из
	// веб-интерфейса с 404 вместо того, чтобы показываться со статусом.
	if err != nil && !errors.Is(err, store.ErrDeviceRevoked) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, s.toDeviceResponse(rec))
}

func (s *Server) getDeviceEvents(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	events, err := s.GW.Store.RecentEvents(deviceID, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // reason опционален
	if req.Reason == "" {
		req.Reason = "отозвано вручную через REST API"
	}
	// Gateway.RevokeDevice (не просто Store.Revoke напрямую) — он также
	// завершает активную криптографическую сессию устройства в памяти
	// шлюза. Затем, если устройство сейчас online, разрываем сам TCP-сокол:
	// без этого уже подключённое устройство продолжило бы нормально слать
	// данные и ротировать ключи вплоть до естественного обрыва соединения,
	// несмотря на отзыв — отзыв был бы эффективен только для устройств,
	// которые ещё не подключились или уже отключились.
	if err := s.GW.RevokeDevice(deviceID, req.Reason); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if s.TCPSrv != nil {
		s.TCPSrv.Disconnect(deviceID, "device revoked: "+req.Reason)
	}
	w.WriteHeader(http.StatusNoContent)
}

// getGatewayInfo — публичный ключ ML-KEM-1024 шлюза, нужен устройству при
// провижининге, чтобы оно могло самостоятельно инициировать ротацию ключа
// (инкапсулируя секрет под этим ключом — см. internal/crypto/rotation.go).
// log_session_keys сообщает фронтенду, включён ли тестовый режим, в котором
// журнал ротаций содержит полные значения ключей (см. Gateway.LogSessionKeys) —
// веб-интерфейс показывает по этому флагу явное предупреждение.
// getGatewayInfo отдаёт публичный ML-KEM-ключ шлюза — его запрашивает
// устройство перед первым рукопожатием, поэтому эндпоинт доступен без токена.
// Ключ публичный по определению, скрывать его нечего.
//
// Остальные поля — служебные и раскрывают режим работы шлюза, поэтому идут
// только авторизованному запросу. В частности log_session_keys показывает,
// пишет ли шлюз сеансовые ключи в журнал: для наблюдателя это подсказка, где
// искать ключи, и знать её посторонним незачем.
func (s *Server) getGatewayInfo(w http.ResponseWriter, r *http.Request) {
	pubBytes := s.GW.KEM.PublicKeyBytes()
	resp := map[string]any{
		"kem_pub_hex": hex.EncodeToString(pubBytes),
	}
	if s.requestAuthorized(r) {
		resp["log_session_keys"] = s.GW.LogSessionKeys
	}
	writeJSON(w, http.StatusOK, resp)
}

// requestAuthorized сообщает, вправе ли запрос видеть служебные поля.
// Если токен на шлюзе не настроен, аутентификация выключена целиком и скрывать
// поля не от кого — тогда доступ считается разрешённым, чтобы локальная
// разработка и дашборд без токена работали как раньше.
func (s *Server) requestAuthorized(r *http.Request) bool {
	if s.adminToken == "" {
		return true
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) == 1
}

// getMetrics — агрегированные счётчики шлюза для дашборда: сколько рукопожатий
// завершено/отклонено, ротаций удалось/провалилось, проверок прошивки прошло/
// провалено/отклонено, отбито replay и отозвано устройств. Даёт мгновенную
// сводку без обхода всего журнала событий.
func (s *Server) getMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.GW.Metrics.Snapshot())
}

// getTelemetry — история телеметрии для графиков и таблицы на дашборде.
// Параметры запроса:
//
//	device_id  — пусто = все устройства (для общего обзора)
//	since/until — RFC3339; если не заданы, используется range
//	range      — относительный период ("30m","1h","6h","12h","24h", ...),
//	             игнорируется если задан since
//	limit      — максимум точек (по умолчанию решает реализация хранилища)
func (s *Server) getTelemetry(w http.ResponseWriter, r *http.Request) {
	filter, err := parseTelemetryFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	readings, err := s.GW.Store.QueryTelemetry(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, readings)
}

func parseTelemetryFilter(r *http.Request) (store.TelemetryFilter, error) {
	q := r.URL.Query()
	filter := store.TelemetryFilter{DeviceID: q.Get("device_id")}

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return filter, fmt.Errorf("limit: %w", err)
		}
		// Верхняя граница: /api/v1/telemetry общедоступен любому клиенту с
		// валидным admin-токеном (не обязательно самому дашборду), и без
		// ограничения сверху явно завышенный limit (случайная опечатка в
		// лишний ноль или намеренно) заставил бы шлюз вытащить из БД и
		// сериализовать в JSON произвольно большой объём телеметрии одним
		// запросом. maxTelemetryLimit — тот же порядок, что уже
		// используется как внутренний дефолт хранилища (см.
		// store.MemStore/pgstore.Store: 5000), так что легитимные сценарии
		// использования дашборда не задеты.
		if n > maxTelemetryLimit {
			n = maxTelemetryLimit
		}
		filter.Limit = n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return filter, fmt.Errorf("since: %w", err)
		}
		filter.Since = t.UTC()
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return filter, fmt.Errorf("until: %w", err)
		}
		filter.Until = t.UTC()
	}
	if v := q.Get("range"); v != "" && filter.Since.IsZero() {
		d, err := time.ParseDuration(v)
		if err != nil {
			return filter, fmt.Errorf("range: %w", err)
		}
		filter.Since = time.Now().Add(-d)
	}
	return filter, nil
}

// maxTelemetryLimit — верхняя граница для параметра limit в /telemetry и
// /rotations (см. комментарий в parseTelemetryFilter). Значение подобрано так,
// чтобы вместить самый длинный диапазон дашборда (24 часа) для нескольких
// устройств: при отправке телеметрии раз в 2 с одно устройство даёт ~43k
// точек в сутки, поэтому 50k покрывает сутки для одного активного устройства
// и типичные сценарии для нескольких. Порог остаётся конечным — он защищает
// от попытки вытащить произвольно большой объём одним запросом.
//
// Важно: этот лимит применяется как страховка ПОСЛЕ фильтрации по времени
// (since/until) в хранилище, поэтому при выборе периода график больше не
// обрезается по количеству точек раньше, чем по времени.
const maxTelemetryLimit = 50000

// maxRegisterBodyBytes — предел размера тела POST /api/v1/devices. С запасом
// над самой большой легитимной регистрацией (hex ML-KEM-ключа — ~3.1 КБ).
const maxRegisterBodyBytes = 64 << 10

// getRotations — журнал попыток ротации ключа (успешных и неудачных).
// device_id пуст — для всех устройств (раздел "Журнал ротаций ключей").
// getFirmwareChecks — журнал проверок целостности прошивки по всем устройствам
// (или по одному через ?device_id=). Отдаёт как успешные проверки, так и
// отклонённые — по типу события видно, что именно произошло.
func (s *Server) getFirmwareChecks(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit: %w", err))
			return
		}
		// Ограничиваем диапазон: отрицательный limit в EventsByType означает
		// «без лимита» и выгрузил бы всю таблицу событий; слишком большой —
		// тяжёлый ответ. Держим в разумных пределах.
		if n < 1 {
			n = 1
		}
		if n > 1000 {
			n = 1000
		}
		limit = n
	}
	types := []string{"firmware_check", "firmware_check_rejected"}
	events, err := s.GW.Store.EventsByType(types, deviceID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) getRotations(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit: %w", err))
			return
		}
		if n < 0 {
			n = 0 // отрицательный limit трактуем как «без явного лимита», не как выборку всего наоборот
		}
		if n > maxTelemetryLimit {
			n = maxTelemetryLimit
		}
		limit = n
	}
	history, err := s.GW.Store.RotationHistory(deviceID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
