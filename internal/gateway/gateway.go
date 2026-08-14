// Package gateway реализует логику локального шлюза протокола LACERT —
// независимо от транспорта (REST/TCP/MQTT появятся на следующем этапе).
// Здесь шлюз обслуживает множество устройств через прямые вызовы методов;
// каждый метод соответствует одному из пяти "Основных алгоритмов системы"
// из работы.
package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/regtool"
	"lacert/internal/store"
	"lacert/internal/telemetry"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// pendingHandshake хранит состояние между Msg2 (отправлен) и Msg3 (получен)
// для одного устройства — аналог того, что в реальном шлюзе хранилось бы в
// краткоживущей таблице сессий-в-процессе-установки.
type pendingHandshake struct {
	// id — уникальный номер этой попытки рукопожатия. Нужен потому, что
	// незавершённые рукопожатия хранятся по deviceID, а одно и то же
	// устройство может открыть второе соединение, не дождавшись, пока шлюз
	// завершит первое (перезагрузка платы, флап Wi-Fi — обычное дело для
	// ESP32). Раньше второй Msg1 молча затирал состояние первого, и дальше
	// ломались ОБА соединения: Msg3 первого проверялся против транскрипта
	// второго и отвергался как «invalid signature», а Msg3 второго уже не
	// находил своей записи («no pending handshake»). Устройство при этом
	// выглядело в журнале как источник неудачных рукопожатий, хотя вело себя
	// совершенно законно. По id соединение узнаёт, что его попытка была
	// вытеснена более новой, и завершается с понятной ошибкой, не мешая
	// новому соединению нормально установить канал.
	id           uint64
	msg1         *crypto.HandshakeMsg1
	msg2         *crypto.HandshakeMsg2
	sharedSecret []byte
	issuedAt     time.Time
}

// PendingID — идентификатор конкретной попытки рукопожатия, выдаваемый
// HandleMsg1Tracked и предъявляемый в HandleMsg3Tracked.
type PendingID uint64

// ErrHandshakeSuperseded возвращается, когда Msg3 приходит по соединению,
// чьё рукопожатие уже вытеснено более новой попыткой того же устройства.
var ErrHandshakeSuperseded = errors.New("handshake superseded by a newer attempt from the same device")

// pendingHandshakeTimeout — сколько незавершённое рукопожатие (Msg2 отправлен,
// Msg3 не получен) хранится, прежде чем считаться протухшим. Такое состояние
// удерживает секретный материал (sharedSecret) и должно освобождаться, если
// устройство не завершило обмен (потеря пакета, обрыв связи, попытка
// накопить незавершённые рукопожатия). Значение с запасом покрывает время
// одного обмена даже с медленной подписью SLH-DSA.
var pendingHandshakeTimeout = 20 * time.Second

// pendingFirmwareCheck хранит отправленный challenge до получения ответа.
type pendingFirmwareCheck struct {
	challenge []byte
	issuedAt  time.Time
}

// firmwareChallengeTimeout — как долго challenge считается "ещё ожидающим
// ответа". Если за это время устройство не ответило, шлюз разрешает выдать
// новый challenge взамен (например, после потери пакета); до истечения
// этого времени повторный вызов IssueFirmwareChallenge для того же
// устройства возвращает ошибку, а не тихо подменяет challenge — иначе
// устройство, отвечающее на ПЕРВЫЙ challenge, было бы ошибочно отклонено,
// потому что шлюз уже ждёт ответ на ВТОРОЙ (см. регрессионный тест
// TestTCPConcurrentServerWrites в tcpserver).
var firmwareChallengeTimeout = 25 * time.Second

// firmwareResponseValidity — максимальный возраст challenge, при котором ответ
// на него ещё принимается при верификации. Если устройство отвечает позже —
// ответ отклоняется как устаревший. Это закрывает окно повторного
// воспроизведения (replay) заранее заготовленной пары (challenge, response):
// даже перехватив challenge и корректный ответ, злоумышленник не сможет
// применить их спустя это время. Значение с запасом покрывает сетевую задержку
// и время подписи даже на медленном SLH-DSA, но много меньше интервала между
// плановыми проверками (раз в час).
var firmwareResponseValidity = 15 * time.Second

// SetFirmwareResponseValidity переопределяет окно валидности ответа на проверку
// прошивки. Для тестов/демонстрации и подгонки параметров на стенде (см.
// LACERT_FIRMWARE_VALIDITY). В обычной работе используется значение по
// умолчанию (15 секунд).
func SetFirmwareResponseValidity(d time.Duration) { firmwareResponseValidity = d }

// SetPendingHandshakeTimeout переопределяет время протухания незавершённого
// рукопожатия. Для подгонки параметров на стенде (LACERT_PENDING_HANDSHAKE_TIMEOUT).
func SetPendingHandshakeTimeout(d time.Duration) { pendingHandshakeTimeout = d }

// SetFirmwareChallengeTimeout переопределяет паузу перед повторной выдачей
// firmware-challenge. Для подгонки параметров на стенде
// (LACERT_FIRMWARE_CHALLENGE_TIMEOUT).
func SetFirmwareChallengeTimeout(d time.Duration) { firmwareChallengeTimeout = d }

// Gateway — локальный шлюз. KEM-ключевая пара шлюза используется в схеме
// непрерывной ротации (см. internal/crypto/rotation.go): устройство может
// инициировать ротацию, инкапсулируя секрет под публичным ключом шлюза.
type Gateway struct {
	Store store.DeviceStore
	KEM   *crypto.KEMKeyPair

	// LogSessionKeys — если true, журнал ротаций (store.RotationLogEntry)
	// будет содержать ПОЛНЫЕ значения старого/нового сеансового ключа в hex.
	// По умолчанию false: ключи сессии — чувствительный материал, и даже в
	// журнале они не должны накапливаться без явного запроса для тестовой
	// среды (см. cmd/gatewayd: LACERT_LOG_SESSION_KEYS). В проде должно
	// оставаться выключенным.
	LogSessionKeys bool

	mu               sync.Mutex
	pendingHandshake map[string]*pendingHandshake
	nextPendingID    uint64
	pendingFirmware  map[string]*pendingFirmwareCheck
	sessions         map[string]*crypto.Session
	replayGuard      *crypto.ReplayGuard

	// Metrics — агрегированные счётчики для наблюдаемости (см. metrics.go).
	Metrics *Metrics

	// now — источник времени; в обычной сборке time.Now, в тестах подменяется
	// для детерминированной проверки тайм-аутов (например, возраста challenge).
	now func() time.Time
}

// New создаёт новый шлюз с in-memory хранилищем устройств (удобно для
// тестов и демонстрации). Для реального развёртывания используйте
// NewWithStore с pgstore.Store (PostgreSQL).
func New() (*Gateway, error) {
	return NewWithStore(store.New())
}

// NewWithStore создаёт шлюз с произвольной реализацией DeviceStore —
// например, pgstore.Store (PostgreSQL) в реальном развёртывании.
func NewWithStore(s store.DeviceStore) (*Gateway, error) {
	kem, err := crypto.GenerateKEMKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate gateway kem keypair: %w", err)
	}
	return &Gateway{
		Store:            s,
		KEM:              kem,
		pendingHandshake: make(map[string]*pendingHandshake),
		pendingFirmware:  make(map[string]*pendingFirmwareCheck),
		sessions:         make(map[string]*crypto.Session),
		replayGuard:      crypto.NewReplayGuard(crypto.DefaultNonceTTL),
		Metrics:          &Metrics{},
		now:              time.Now,
	}, nil
}

// RevokeDevice отзывает доверие устройству и немедленно завершает (с
// затиранием ключа) его активную сессию шлюза, если она есть — чтобы уже
// подключённое устройство не могло продолжать слать данные/ротации после
// отзыва. Самим закрытием TCP-сокета занимается транспортный слой (см.
// tcpserver.Server.Disconnect, вызываемый из REST-хендлера отзыва) —
// Gateway о транспорте ничего не знает.
//
// До появления этого метода REST-эндпоинт отзыва вызывал Store.Revoke
// напрямую, не трогая g.sessions: устройство с уже установленным каналом
// продолжало нормально работать (расшифровка данных, ротация) сколь угодно
// долго после того, как администратор нажимал "отозвать" в веб-интерфейсе —
// функция отзыва не имела эффекта для самого частого случая, ради которого
// её и нажимают: активно подключённого устройства.
func (g *Gateway) RevokeDevice(deviceID, reason string) error {
	return g.revokeAndCloseSession(deviceID, reason, "отозвано: "+reason)
}

// Shutdown корректно завершает работу шлюза: закрывает все активные сессии с
// затиранием их ключей (PFS-гигиена — при остановке процесса ключевой материал
// не должен оставаться в памяти) и очищает незавершённые состояния
// (рукопожатия и проверки прошивки), затирая связанный с ними секретный
// материал. Возвращает число закрытых сессий — для логирования.
//
// Вызывается из cmd/gatewayd при получении сигнала остановки, после закрытия
// сетевых слушателей, чтобы новые соединения уже не создавали сессий.
func (g *Gateway) Shutdown() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	closed := 0
	for id, s := range g.sessions {
		s.Close() // затирает текущий и ожидающий ключи
		delete(g.sessions, id)
		closed++
	}
	for id, p := range g.pendingHandshake {
		crypto.Zeroize(p.sharedSecret)
		delete(g.pendingHandshake, id)
	}
	// pendingFirmware не содержит секретов (только случайный challenge), но
	// очищаем для чистоты состояния.
	for id := range g.pendingFirmware {
		delete(g.pendingFirmware, id)
	}
	return closed
}

// revokeAndCloseSession — общая логика всех путей отзыва устройства
// (ручной через REST, автоматический после провала проверки прошивки):
// помечает устройство отозванным в хранилище, завершает и удаляет его
// активную сессию шлюза, пишет событие в журнал.
func (g *Gateway) revokeAndCloseSession(deviceID, reason, eventDetail string) error {
	if err := g.Store.Revoke(deviceID, reason); err != nil {
		return err
	}
	g.mu.Lock()
	if s, ok := g.sessions[deviceID]; ok {
		s.Close()
		delete(g.sessions, deviceID)
	}
	g.mu.Unlock()
	g.Metrics.incDeviceRevoked()
	// Ошибка записи в журнал намеренно игнорируется здесь и далее: журнал
	// вспомогательный, его сбой не должен прерывать работу протокола.
	// Подробнее — в комментарии к Store.LogEvent (internal/store/store.go).
	_ = g.Store.LogEvent(deviceID, "revoked", eventDetail)
	return nil
}

// CloseSession завершает сессию устройства и удаляет её из памяти шлюза,
// затирая сеансовый ключ. Вызывается транспортным слоем при разрыве
// соединения (см. tcpserver.handleConn).
//
// Без этого сессия жила до отзыва устройства или до остановки процесса:
// карта g.sessions удерживала сеансовый ключ каждого устройства, которое
// когда-либо подключалось, сколь угодно долго после того, как оно
// отключилось. Это прямо противоречит PFS-гигиене, ради которой ключи
// затираются в Session.Close() и Gateway.Shutdown(). Возвращает true, если
// сессия существовала и была закрыта.
func (g *Gateway) CloseSession(deviceID string) bool {
	return g.closeSession(deviceID, nil)
}

// CurrentSession возвращает объект текущей сессии устройства. Нужен
// транспортному слою, чтобы запомнить, КАКУЮ именно сессию создало его
// рукопожатие, и при разрыве закрыть только её (см. CloseSessionInstance).
func (g *Gateway) CurrentSession(deviceID string) (*crypto.Session, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[deviceID]
	return s, ok
}

// CloseSessionInstance закрывает сессию устройства, только если это всё ещё
// ТА САМАЯ сессия (сравнение по указателю), которую передал вызывающий.
//
// Зачем сравнение: устройство может переподключиться, и тогда его новое
// рукопожатие уже заменило запись в g.sessions. Горутина старого соединения
// завершается позже — и, закрывая сессию «своего» устройства по одному лишь
// deviceID, обрывала бы связь только что подключившемуся устройству. Сравнение
// по карте активных соединений эту гонку не закрывает: клиент считает
// рукопожатие завершённым, отправив Msg3, то есть ДО того, как сервер успел
// зарегистрировать новое соединение. Указатель на сессию — единственный
// признак, который к этому моменту уже точно обновлён.
//
// Возвращает true, если сессия была закрыта.
func (g *Gateway) CloseSessionInstance(deviceID string, want *crypto.Session) bool {
	if want == nil {
		return false
	}
	return g.closeSession(deviceID, want)
}

// closeSession — общая реализация: при want != nil закрывает сессию только
// при совпадении указателя.
func (g *Gateway) closeSession(deviceID string, want *crypto.Session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[deviceID]
	if !ok {
		return false
	}
	if want != nil && s != want {
		return false // устройство переподключилось, эта сессия уже не наша
	}
	s.Close()
	delete(g.sessions, deviceID)
	return true
}

// ActiveSessionCount возвращает число сессий, живущих в памяти шлюза, — для
// метрик и для теста, проверяющего, что сессии не накапливаются после
// отключения устройств.
func (g *Gateway) ActiveSessionCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}

// ---------------------------------------------------------------------------
// 1. Офлайн-регистрация
// ---------------------------------------------------------------------------

// deviceIDPattern ограничивает допустимые символы device ID: латиница,
// цифры, дефис, подчёркивание, точка — то, что реально печатают embedded
// устройства и что безопасно использовать как есть в (а) REST-путях
// (/api/v1/devices/{deviceID}), (б) MQTT-топиках
// ("devices/{deviceID}/telemetry", см. internal/mqttbridge).
//
// Без этой проверки device_id из REST-запроса регистрации (полностью
// произвольная строка, ничем не ограниченная на всём пути от веб-формы до
// этой точки) мог бы содержать "/", "+", "#" — символы, имеющие особый
// смысл в MQTT-топиках (разделитель уровня и wildcard'ы соответственно).
// Устройство с DeviceID вроде "a/#" не просто выглядело бы странно, а
// реально ломало бы структуру топиков брокера и потенциально
// взаимодействовало бы с чужими wildcard-подписками непредсказуемым
// образом. Найдено при аудите проекта.
var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func validateDeviceID(id string) error {
	if !deviceIDPattern.MatchString(id) {
		return fmt.Errorf("invalid device_id %q: must be 1-128 characters, only letters, digits, '.', '_', '-' allowed", id)
	}
	return nil
}

// RegisterDevice — вызывается консольной утилитой офлайн-администрирования
// после того, как администратор вручную перенёс данные с Serial-порта
// устройства. serial — данные, "считанные" с порта, включая эталонный хеш
// прошивки (а не сам образ — устройство никогда не передаёт прошивку
// целиком, ни здесь, ни при последующих проверках целостности, см.
// internal/crypto/firmware.go); serial.Checksum проверяется, чтобы
// исключить опечатки при переносе (подлинность самого устройства будет
// дополнительно подтверждена позже, на рукопожатии).
// ReregisterDevice заменяет ключи уже зарегистрированного устройства.
//
// Нужен, когда устройство свои ключи потеряло: очистили память платы,
// заменили плату с сохранением идентификатора, перепрошили с генерацией новой
// пары. Прежде такое устройство оставалось в реестре навсегда непригодным —
// зарегистрировать заново мешала запись с прежним идентификатором, а
// рукопожатие не проходило, потому что ключ у платы уже другой.
//
// Отозванное устройство перерегистрировать нельзя. Смена ключей не снимает
// отзыв, и делать вид, что устройство снова в строю, было бы опасно: отзыв
// ставится в том числе за неудачную проверку целостности прошивки, то есть по
// подозрению в подмене. Если оператор действительно хочет вернуть такое
// устройство, ему нужно удалить запись и завести её заново — действие
// осознанное и заметное.
//
// Действующая сессия закрывается: она работает на прежнем ключе, и оставлять
// её после смены ключей значило бы держать соединение, которое реестру уже не
// соответствует.
func (g *Gateway) ReregisterDevice(serial regtool.SerialOutput, sigAlg crypto.SigAlgorithm) error {
	if err := validateDeviceID(serial.DeviceID); err != nil {
		return err
	}
	if !regtool.VerifyChecksum(serial) {
		return errors.New("checksum mismatch: data may have been mistyped during manual transfer")
	}
	if _, err := crypto.UnpackKEMPublicKey(serial.KEMPub); err != nil {
		return fmt.Errorf("invalid kem_pub: %w", err)
	}
	if err := crypto.ValidateIdentityPublicKey(sigAlg, serial.IdentityPub); err != nil {
		return fmt.Errorf("invalid identity_pub: %w", err)
	}

	// Store.Get отдаёт запись отозванного устройства вместе с ErrDeviceRevoked,
	// поэтому отзыв распознаётся здесь, а не отдельной проверкой поля: своя
	// проверка оказалась бы недостижимой, потому что ошибка приходит раньше.
	rec, err := g.Store.Get(serial.DeviceID)
	if errors.Is(err, store.ErrDeviceRevoked) {
		return fmt.Errorf("устройство отозвано (%s): чтобы завести его заново, сначала удалите запись",
			rec.RevokedReason)
	}
	if err != nil {
		return err
	}

	updated := &store.DeviceRecord{
		DeviceID:     serial.DeviceID,
		SigAlgorithm: sigAlg,
		IdentityPub:  serial.IdentityPub,
		KEMPub:       serial.KEMPub,
		FirmwareHash: serial.FirmwareHash[:],
	}
	if err := g.Store.Reregister(updated); err != nil {
		return err
	}
	g.CloseSession(serial.DeviceID)
	_ = g.Store.LogEvent(serial.DeviceID, "reregistered",
		"ключи заменены при повторной офлайн-регистрации, контрольная сумма проверена")
	return nil
}

// DeleteDevice полностью убирает устройство из реестра вместе с его журналом
// событий и телеметрией.
//
// Отличается от отзыва: отозванное устройство остаётся в реестре и видно
// оператору вместе с причиной, а удалённое исчезает бесследно. Отзыв — это
// решение о недоверии, удаление — уборка. Для устройства, побывавшего в
// работе, обычно нужен отзыв, а удаление — для записей, заведённых по ошибке
// или созданных для проверок.
//
// Действующая сессия закрывается: держать соединение с устройством, которого
// в реестре больше нет, незачем.
func (g *Gateway) DeleteDevice(deviceID string) error {
	// Отозванное устройство удалять можно и нужно — именно так оператор
	// освобождает идентификатор для повторной регистрации. Поэтому
	// ErrDeviceRevoked здесь не препятствие, в отличие от ErrDeviceNotFound.
	if _, err := g.Store.Get(deviceID); err != nil && !errors.Is(err, store.ErrDeviceRevoked) {
		return err
	}
	g.CloseSession(deviceID)
	return g.Store.Delete(deviceID)
}

func (g *Gateway) RegisterDevice(serial regtool.SerialOutput, sigAlg crypto.SigAlgorithm) error {
	if err := validateDeviceID(serial.DeviceID); err != nil {
		return err
	}
	if !regtool.VerifyChecksum(serial) {
		return errors.New("checksum mismatch: data may have been mistyped during manual transfer")
	}
	// Валидация формата ключей ДО записи в реестр: без этой проверки
	// устройство с неверным размером KEM-ключа (опечатка при ручном вводе
	// через веб-форму, обрезанная строка при копировании и т.п.) успешно
	// регистрировалось бы, и ошибка проявлялась бы только при первой
	// попытке рукопожатия — с гораздо менее понятным сообщением и заметно
	// позже во времени, чем момент, когда администратор мог бы её сразу
	// заметить и исправить.
	if _, err := crypto.UnpackKEMPublicKey(serial.KEMPub); err != nil {
		return fmt.Errorf("invalid kem_pub: %w", err)
	}
	// Ключ подписи проверяется по тем же соображениям, что и KEM-ключ выше.
	// Прежде здесь стояла лишь проверка на непустоту, и устройство с
	// испорченным ключом подписи регистрировалось успешно, а отказывало позже,
	// на рукопожатии — там, где связь с ошибкой ввода уже не видна.
	if len(serial.IdentityPub) == 0 {
		return errors.New("identity_pub must not be empty")
	}
	if err := crypto.ValidateIdentityPublicKey(sigAlg, serial.IdentityPub); err != nil {
		return fmt.Errorf("invalid identity_pub: %w", err)
	}

	rec := &store.DeviceRecord{
		DeviceID:     serial.DeviceID,
		SigAlgorithm: sigAlg,
		IdentityPub:  serial.IdentityPub,
		KEMPub:       serial.KEMPub,
		FirmwareHash: serial.FirmwareHash[:],
	}
	if err := g.Store.Register(rec); err != nil {
		return err
	}
	_ = g.Store.LogEvent(serial.DeviceID, "registered", "офлайн-регистрация завершена, контрольная сумма проверена")
	return nil
}

// ---------------------------------------------------------------------------
// 2. Начальное постквантовое рукопожатие
// ---------------------------------------------------------------------------

// HandleMsg1 — шлюз получил Msg1 от устройства. Ищет устройство в реестре,
// инкапсулирует общий секрет под его зарегистрированным KEM-pubkey и
// возвращает Msg2.
func (g *Gateway) HandleMsg1(msg1 *crypto.HandshakeMsg1) (*crypto.HandshakeMsg2, error) {
	msg2, _, err := g.HandleMsg1Tracked(msg1)
	return msg2, err
}

// HandleMsg1Tracked — то же, что HandleMsg1, но дополнительно возвращает
// идентификатор этой попытки рукопожатия. Транспортный слой передаёт его в
// HandleMsg3Tracked, чтобы шлюз мог отличить «своё» Msg3 от Msg3 соединения,
// вытесненного более новой попыткой того же устройства.
func (g *Gateway) HandleMsg1Tracked(msg1 *crypto.HandshakeMsg1) (*crypto.HandshakeMsg2, PendingID, error) {
	// Защита от replay: отвергаем повторно воспроизведённое Msg1 (тот же
	// DeviceID + Nonce). Проверка идёт до любой криптографии и обращения к
	// хранилищу, чтобы записанное злоумышленником старое рукопожатие не
	// приводило к лишней работе и не создавало новое pending-состояние.
	if err := g.replayGuard.CheckAndRemember(msg1.DeviceID, msg1.Nonce); err != nil {
		g.Metrics.incReplayBlocked()
		g.Metrics.incHandshakeRejected()
		_ = g.Store.LogEvent(msg1.DeviceID, "handshake_rejected", "отклонено Msg1: обнаружен повтор nonce (replay)")
		return nil, 0, fmt.Errorf("reject msg1 from %q: %w", msg1.DeviceID, err)
	}

	rec, err := g.Store.Get(msg1.DeviceID)
	if err != nil {
		return nil, 0, fmt.Errorf("lookup device %q: %w", msg1.DeviceID, err)
	}

	devKEMPub, err := rec.KEMPublicKey()
	if err != nil {
		return nil, 0, fmt.Errorf("unpack device kem public key: %w", err)
	}

	msg2, sharedSecret, err := crypto.BuildMsg2(devKEMPub)
	if err != nil {
		return nil, 0, fmt.Errorf("build msg2: %w", err)
	}

	g.mu.Lock()
	g.prunePendingHandshakesLocked()
	g.nextPendingID++
	id := g.nextPendingID
	// Если у устройства уже висело незавершённое рукопожатие, его секрет
	// затирается здесь, а не остаётся висеть в памяти до протухания: запись
	// всё равно замещается более новой попыткой.
	if prev, ok := g.pendingHandshake[msg1.DeviceID]; ok {
		crypto.Zeroize(prev.sharedSecret)
	}
	g.pendingHandshake[msg1.DeviceID] = &pendingHandshake{
		id: id, msg1: msg1, msg2: msg2, sharedSecret: sharedSecret, issuedAt: g.now(),
	}
	g.mu.Unlock()

	return msg2, PendingID(id), nil
}

// prunePendingHandshakesLocked удаляет незавершённые рукопожатия, у которых
// истёк pendingHandshakeTimeout, затирая их секретный материал. Вызывается под
// уже захваченным g.mu при обработке нового Msg1, чтобы карта не накапливала
// протухшие записи (в том числе при попытках накопить незавершённые
// рукопожатия) и не удерживала ключевой материал дольше необходимого.
func (g *Gateway) prunePendingHandshakesLocked() {
	now := g.now()
	for id, p := range g.pendingHandshake {
		if now.Sub(p.issuedAt) > pendingHandshakeTimeout {
			crypto.Zeroize(p.sharedSecret)
			delete(g.pendingHandshake, id)
		}
	}
}

// HandleMsg3 — шлюз получил подтверждение от устройства. Проверяет подпись,
// финализирует K0 и создаёт рабочую сессию.
func (g *Gateway) HandleMsg3(deviceID string, msg3 *crypto.HandshakeMsg3) error {
	return g.handleMsg3(deviceID, msg3, 0)
}

// HandleMsg3Tracked — то же, что HandleMsg3, но принимает идентификатор
// попытки рукопожатия, выданный HandleMsg1Tracked. Если за это время
// устройство успело начать новое рукопожатие (второе соединение), запись уже
// принадлежит ему: старое соединение получает ErrHandshakeSuperseded и
// закрывается, НЕ забирая с собой состояние нового.
func (g *Gateway) HandleMsg3Tracked(deviceID string, id PendingID, msg3 *crypto.HandshakeMsg3) error {
	return g.handleMsg3(deviceID, msg3, id)
}

// handleMsg3 — общая реализация. При id == 0 проверка принадлежности не
// выполняется (поведение исходного HandleMsg3, которым пользуются тесты и
// демонстрационный сценарий с единственным соединением на устройство).
func (g *Gateway) handleMsg3(deviceID string, msg3 *crypto.HandshakeMsg3, id PendingID) error {
	g.mu.Lock()
	pending, ok := g.pendingHandshake[deviceID]
	if ok && id != 0 && pending.id != uint64(id) {
		// Запись принадлежит более новой попытке — не трогаем её.
		g.mu.Unlock()
		g.Metrics.incHandshakeRejected()
		return fmt.Errorf("finalize handshake for device %q: %w", deviceID, ErrHandshakeSuperseded)
	}
	if ok {
		delete(g.pendingHandshake, deviceID)
	}
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("no pending handshake for device %q (Msg1 not received or already finalized)", deviceID)
	}

	// Незавершённое рукопожатие протухло: Msg3 пришёл слишком поздно после
	// Msg2. Затираем секрет и отклоняем — устройство должно начать заново.
	if age := g.now().Sub(pending.issuedAt); age > pendingHandshakeTimeout {
		crypto.Zeroize(pending.sharedSecret)
		g.Metrics.incHandshakeRejected()
		return fmt.Errorf("handshake for device %q expired (age %s > %s), restart handshake",
			deviceID, age.Round(time.Second), pendingHandshakeTimeout)
	}

	rec, err := g.Store.Get(deviceID)
	if err != nil {
		return fmt.Errorf("lookup device %q: %w", deviceID, err)
	}

	k0, err := crypto.FinalizeHandshake(rec.IdentityPub, rec.SigAlgorithm, pending.msg1, pending.msg2, msg3, pending.sharedSecret)
	if err != nil {
		g.Metrics.incHandshakeRejected()
		return fmt.Errorf("finalize handshake: %w", err)
	}

	session, err := crypto.NewSession(k0)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	g.mu.Lock()
	g.sessions[deviceID] = session
	g.mu.Unlock()
	g.Metrics.incHandshakeCompleted()
	_ = g.Store.LogEvent(deviceID, "handshake", "начальное постквантовое рукопожатие завершено успешно")
	return nil
}

// GatewayKEMPublicKey возвращает публичный ключ ML-KEM-1024 шлюза — он нужен
// устройству, чтобы самому инициировать ротацию (передаётся устройству при
// провижининге, как и описано в device.SetGatewayKEMPublicKey).
func (g *Gateway) GatewayKEMPublicKey() *mlkem1024.PublicKey {
	return g.KEM.Pub
}

// ---------------------------------------------------------------------------
// 3. Непрерывная ротация ключей
// ---------------------------------------------------------------------------

// ControlKey отдаёт действующий сеансовый ключ устройства для вычисления
// метки подлинности служебных кадров.
//
// Ключ берётся до применения ротации: она вступает в силу только после
// подтверждения, и обе стороны должны считать метку одним и тем же ключом.
func (g *Gateway) ControlKey(deviceID string) ([32]byte, error) {
	sess, err := g.session(deviceID)
	if err != nil {
		return [32]byte{}, err
	}
	return sess.CurrentKey()
}

func (g *Gateway) session(deviceID string) (*crypto.Session, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[deviceID]
	if !ok {
		return nil, fmt.Errorf("no active session for device %q", deviceID)
	}
	return s, nil
}

// SessionIteration возвращает номер последней применённой атомарной ротации
// для устройства (0, если сессии нет или ротаций ещё не было).
// PendingHandshakeCountForTest возвращает число незавершённых рукопожатий —
// только для тестов проверки очистки протухших записей.
func (g *Gateway) PendingHandshakeCountForTest() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.pendingHandshake)
}

// SetNowForTest подменяет источник времени шлюза — только для тестов,
// проверяющих тайм-ауты (например, возраст firmware-challenge) без реальных
// задержек.
func (g *Gateway) SetNowForTest(fn func() time.Time) { g.now = fn }

func (g *Gateway) SessionIteration(deviceID string) uint64 {
	s, err := g.session(deviceID)
	if err != nil {
		return 0
	}
	return s.Iteration()
}

// HandleRotationFromDevice — устройство сам инициировал ротацию; шлюз
// декапсулирует присланный шифротекст своим приватным KEM-ключом и обновляет
// сессию.
func (g *Gateway) HandleRotationFromDevice(deviceID string, msg *crypto.RotationMsg) error {
	s, err := g.session(deviceID)
	if err != nil {
		return err
	}

	oldKey, _ := s.CurrentKey() // если CurrentKey вернёт ошибку (сессия уже закрыта), oldKey останется нулевым — это ляжет в журнал как часть неуспешной попытки ниже
	rotErr := crypto.RespondToRotation(s, g.KEM.Priv, msg)
	g.logRotationAttempt(deviceID, "device", s, oldKey, rotErr)
	if rotErr != nil {
		return rotErr
	}
	_ = g.Store.LogEvent(deviceID, "rotation", "ротация ключа, инициированная устройством")
	return nil
}

// InitiateRotationToDevice — шлюз сам инициирует ротацию (например, по
// собственному таймеру), инкапсулируя секрет под KEM-публичным ключом
// устройства.
func (g *Gateway) InitiateRotationToDevice(deviceID string) (*crypto.RotationMsg, error) {
	s, err := g.session(deviceID)
	if err != nil {
		return nil, err
	}
	rec, err := g.Store.Get(deviceID)
	if err != nil {
		return nil, err
	}
	devKEMPub, err := rec.KEMPublicKey()
	if err != nil {
		return nil, err
	}

	oldKey, _ := s.CurrentKey()
	msg, rotErr := crypto.InitiateRotation(s, devKEMPub)
	g.logRotationAttempt(deviceID, "gateway", s, oldKey, rotErr)
	if rotErr != nil {
		return nil, rotErr
	}
	_ = g.Store.LogEvent(deviceID, "rotation", "ротация ключа, инициированная шлюзом")
	return msg, nil
}

// ---------------------------------------------------------------------------
// Атомарная ротация (варианты А+В): ротация с ACK и номером итерации.
// Отличается от неатомарной тем, что инициатор (шлюз) не коммитит новый ключ,
// пока не получит подтверждение от устройства. Потеря сообщения ротации
// больше не рвёт связь. См. internal/crypto/rotation_atomic.go.
// ---------------------------------------------------------------------------

// InitiateAtomicRotationToDevice — шлюз инициирует атомарную ротацию.
// Возвращает сообщение RotationMsgV2 для отправки устройству. Новый ключ
// вычислен, но не применён: сессия останется на текущем ключе, пока не придёт
// RotationAck (см. ApplyRotationAckFromDevice).
func (g *Gateway) InitiateAtomicRotationToDevice(deviceID string) (*crypto.RotationMsgV2, error) {
	s, err := g.session(deviceID)
	if err != nil {
		return nil, err
	}
	rec, err := g.Store.Get(deviceID)
	if err != nil {
		return nil, err
	}
	devKEMPub, err := rec.KEMPublicKey()
	if err != nil {
		return nil, err
	}

	msg, err := crypto.InitiateRotationAtomic(s, devKEMPub)
	if err != nil {
		return nil, fmt.Errorf("initiate atomic rotation: %w", err)
	}
	return msg, nil
}

// ApplyRotationAckFromDevice — шлюз получил подтверждение от устройства и
// коммитит ротацию (переход на новый ключ, затирание старого). Логирует
// результат в журнал ротаций.
func (g *Gateway) ApplyRotationAckFromDevice(deviceID string, ack *crypto.RotationAck) error {
	s, err := g.session(deviceID)
	if err != nil {
		return err
	}
	oldKey, _ := s.CurrentKey()
	commitErr := crypto.ApplyRotationAck(s, ack)
	g.logRotationAttempt(deviceID, "gateway", s, oldKey, commitErr)
	if commitErr != nil {
		return commitErr
	}
	_ = g.Store.LogEvent(deviceID, "rotation", "атомарная ротация (инициатор: шлюз) подтверждена устройством")
	return nil
}

// HandleAtomicRotationFromDevice — устройство инициировало атомарную ротацию.
// Шлюз применяет её и возвращает RotationAck для отправки обратно устройству.
func (g *Gateway) HandleAtomicRotationFromDevice(deviceID string, msg *crypto.RotationMsgV2) (*crypto.RotationAck, error) {
	s, err := g.session(deviceID)
	if err != nil {
		return nil, err
	}
	oldKey, _ := s.CurrentKey()
	ack, rotErr := crypto.RespondToRotationAtomic(s, g.KEM.Priv, msg)
	g.logRotationAttempt(deviceID, "device", s, oldKey, rotErr)
	if rotErr != nil {
		return nil, rotErr
	}
	_ = g.Store.LogEvent(deviceID, "rotation", "атомарная ротация (инициатор: устройство) применена")
	return ack, nil
}

// AbortStaleRotationIfNeeded проверяет, не застряла ли у устройства
// незавершённая атомарная ротация (ACK не пришёл дольше тайм-аута). Если да —
// откатывает её (затирая недопринятый Ki+1), логирует неуспешную попытку в
// журнал ротаций и возвращает true. После этого планировщик может
// инициировать ротацию заново. Возвращает false, если сессии нет или откат не
// потребовался.
func (g *Gateway) AbortStaleRotationIfNeeded(deviceID string, timeout time.Duration) bool {
	s, err := g.session(deviceID)
	if err != nil {
		return false
	}
	if !s.AbortIfStale(timeout) {
		return false
	}
	// Логируем как неуспешную попытку ротации, чтобы это было видно в журнале
	// ротаций на дашборде (initiator=gateway, т.к. таймер шлюза инициировал).
	oldKey, _ := s.CurrentKey()
	g.logRotationAttempt(deviceID, "gateway", s, oldKey,
		fmt.Errorf("rotation ack timeout after %s: rolled back, will retry", timeout))
	_ = g.Store.LogEvent(deviceID, "rotation_timeout",
		"ротация откачена: подтверждение (ACK) не получено в срок, будет повторена")
	return true
}

// logRotationAttempt пишет в журнал результат одной попытки ротации —
// успешной или нет. Используется и для ротации, инициированной устройством,
// и для ротации, инициированной шлюзом (initiator различает их в журнале).
// Полные значения ключей (OldKeyHex/NewKeyHex) попадают в журнал ТОЛЬКО если
// g.LogSessionKeys включён — см. комментарий к полю.
func (g *Gateway) logRotationAttempt(deviceID, initiator string, s *crypto.Session, oldKey [32]byte, rotErr error) {
	entry := store.RotationLogEntry{
		DeviceID:  deviceID,
		Initiator: initiator,
		Success:   rotErr == nil,
	}
	if rotErr != nil {
		entry.ErrorText = rotErr.Error()
		g.Metrics.incRotationFailed()
	} else {
		entry.RotationCount = s.Stats().RotationCount
		g.Metrics.incRotationSucceeded()
		if g.LogSessionKeys {
			if newKey, err := s.CurrentKey(); err == nil {
				entry.OldKeyHex = hex.EncodeToString(oldKey[:])
				entry.NewKeyHex = hex.EncodeToString(newKey[:])
			}
		}
	}
	_ = g.Store.LogRotation(entry)
}

// NeedsRotation — проверка для конкретного устройства (используется в
// серверном цикле шлюза, который периодически обходит активные сессии).
func (g *Gateway) NeedsRotation(deviceID string) (bool, error) {
	s, err := g.session(deviceID)
	if err != nil {
		return false, err
	}
	return s.NeedsRotation(), nil
}

// ---------------------------------------------------------------------------
// 4. Приём данных
// ---------------------------------------------------------------------------

// HandleData расшифровывает пакет от устройства текущим сеансовым ключом,
// сохраняет его в историю телеметрии (для графиков на дашборде, см.
// internal/telemetry) и возвращает открытый текст для передачи в
// корпоративную информационную систему (REST/MQTT).
func (g *Gateway) HandleData(deviceID string, nonce, ciphertext []byte) ([]byte, error) {
	s, err := g.session(deviceID)
	if err != nil {
		return nil, err
	}
	key, err := s.CurrentKey()
	if err != nil {
		return nil, err
	}
	pt, err := crypto.DecryptPacket(key, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt packet from %q: %w", deviceID, err)
	}

	// Проверка на повтор ДО того, как расшифрованные данные уйдут в
	// хранилище и в корпоративную систему. Успешная расшифровка доказывает
	// подлинность пакета, но не его новизну: записанный из сети пакет
	// расшифровывается сколько угодно раз. См. internal/crypto/replay_data.go.
	if err := s.CheckDataNonce(nonce); err != nil {
		g.Metrics.incDataReplayBlocked()
		_ = g.Store.LogEvent(deviceID, "data_rejected", "пакет данных отклонён: повтор (replay)")
		return nil, fmt.Errorf("reject packet from %q: %w", deviceID, err)
	}

	s.RecordPacket()

	// Сбой записи не прерывает обработку пакета: устройство своё дело сделало,
	// и разрывать сессию из-за недоступности хранилища значило бы превращать
	// проблему базы в отказ связи. Но, в отличие от служебного журнала, здесь
	// теряются полезные данные, поэтому потеря считается отдельной метрикой и
	// видна на дашборде (telemetry_dropped).
	if err := g.Store.RecordTelemetry(store.TelemetryReading{
		DeviceID:   deviceID,
		RawPayload: string(pt),
		Parsed:     telemetry.ParseKV(string(pt)),
		ReceivedAt: time.Now().UTC(),
	}); err != nil {
		g.Metrics.incTelemetryDropped()
	}

	return pt, nil
}

// ---------------------------------------------------------------------------
// 5. Проверка целостности прошивки
// ---------------------------------------------------------------------------

// IssueFirmwareChallenge — шлюз раз в час генерирует случайный запрос для
// устройства.
func (g *Gateway) IssueFirmwareChallenge(deviceID string) ([]byte, error) {
	// Замок здесь отпускается на время генерации challenge и берётся снова для
	// записи. Это безопасно, пока функцию вызывает один поток: планировщик
	// обходит устройства последовательно в единственной горутине (см.
	// scheduler.tick). Если появится ещё один источник вызовов — например,
	// REST-обработчик «проверить прошивку сейчас», — два одновременных вызова
	// для одного устройства смогут оба пройти проверку «challenge уже выдан» и
	// записать свой, из-за чего ответ на первый будет отвергнут как неизвестный.
	// В таком случае удержание замка нужно будет распространить на всю функцию.
	if _, err := g.Store.Get(deviceID); err != nil {
		return nil, err
	}

	g.mu.Lock()
	if existing, ok := g.pendingFirmware[deviceID]; ok && g.now().Sub(existing.issuedAt) < firmwareChallengeTimeout {
		g.mu.Unlock()
		return nil, fmt.Errorf("firmware challenge already pending for device %q (issued %s ago, not yet answered)",
			deviceID, g.now().Sub(existing.issuedAt).Round(time.Second))
	}
	g.mu.Unlock()

	challenge, err := crypto.BuildFirmwareChallenge()
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.pendingFirmware[deviceID] = &pendingFirmwareCheck{challenge: challenge, issuedAt: g.now()}
	g.mu.Unlock()
	return challenge, nil
}

// VerifyFirmwareCheck — шлюз получил ответ устройства на запрос целостности.
// При несовпадении подписи или хеша устройство отзывается (исключается из
// доверенной сети) — это финальный шаг, описанный в работе.
func (g *Gateway) VerifyFirmwareCheck(deviceID string, resp *crypto.FirmwareResponse) (crypto.FirmwareCheckResult, error) {
	g.mu.Lock()
	pending, ok := g.pendingFirmware[deviceID]
	if ok {
		delete(g.pendingFirmware, deviceID)
	}
	g.mu.Unlock()
	if !ok {
		return crypto.FirmwareCheckResult{}, fmt.Errorf("no pending firmware challenge for device %q", deviceID)
	}

	// Отклоняем ответ на устаревший challenge: это закрывает окно повторного
	// воспроизведения заранее заготовленной пары (challenge, response). Запись
	// уже удалена выше, поэтому повторная попытка тоже не пройдёт.
	if age := g.now().Sub(pending.issuedAt); age > firmwareResponseValidity {
		g.Metrics.incFirmwareRejected()
		_ = g.Store.LogEvent(deviceID, "firmware_check_rejected",
			fmt.Sprintf("ответ на проверку прошивки отклонён: challenge устарел (%s)", age.Round(time.Second)))
		return crypto.FirmwareCheckResult{}, fmt.Errorf("firmware challenge expired for device %q (age %s > %s)",
			deviceID, age.Round(time.Second), firmwareResponseValidity)
	}

	rec, err := g.Store.Get(deviceID)
	if err != nil {
		return crypto.FirmwareCheckResult{}, err
	}

	refHash, err := rec.FirmwareHashArray()
	if err != nil {
		return crypto.FirmwareCheckResult{}, fmt.Errorf("read reference firmware hash: %w", err)
	}

	result, err := crypto.VerifyFirmwareResponse(rec.IdentityPub, rec.SigAlgorithm, pending.challenge, resp, refHash)
	if err != nil {
		return crypto.FirmwareCheckResult{}, err
	}

	if !result.OK() {
		g.Metrics.incFirmwareFailed()
		reason := "подпись не верифицирована"
		if result.SignatureValid {
			reason = "хеш прошивки не совпадает с эталонным"
		}
		if err := g.revokeAndCloseSession(deviceID, reason, "проверка целостности прошивки провалена: "+reason); err != nil {
			return result, fmt.Errorf("revoke device after failed firmware check: %w", err)
		}
	} else {
		g.Metrics.incFirmwarePassed()
		_ = g.Store.LogEvent(deviceID, "firmware_check", "проверка целостности прошивки пройдена")
	}

	return result, nil
}
