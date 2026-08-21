// Package tcpserver реализует сетевой транспорт шлюза поверх TCP — то, что
// в работе описано как "Передача данных... по протоколу TCP... без
// дополнительного TLS-шифрования — защита обеспечивается на уровне самого
// протокола" (т.е. самим LACERT). Каждое TCP-соединение обслуживает одно
// устройство: первое сообщение в соединении обязано быть Msg1 рукопожатия,
// после чего соединение переходит в рабочий режим (данные/ротация),
// и параллельно администратор/планировщик шлюза может в любой момент
// инициировать через это же соединение ротацию или проверку целостности
// прошивки.
package tcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"lacert/internal/gateway"
	"lacert/internal/wire"
)

// IdleTimeout — если от устройства долго нет ни одного кадра (ни данных, ни
// ротации, ни ответа на проверку прошивки), соединение считается мёртвым и
// закрывается, чтобы не держать "зависшую" горутину и место в реестре
// активных соединений бесконечно (например, при обрыве сети без
// корректного закрытия TCP-сессии устройством). Значение взято заметно
// больше интервала ротации (300 сек), чтобы не закрывать живые, но
// временно неактивные каналы.
const IdleTimeout = 15 * time.Minute

// keepAlivePeriod — период TCP-keepalive проб для обнаружения "повисших"
// соединений на уровне ОС (например, при отключении устройства от сети без
// FIN/RST).
const keepAlivePeriod = 30 * time.Second

// WriteTimeout — предельное время на запись одного кадра устройству. Без него
// send блокировался НАВСЕГДА, если устройство перестало читать сокет (буфер
// приёма переполнен, TCP zero window): само по себе это уронило бы одну
// горутину, но записи со стороны шлюза (ротация, challenge прошивки) идут под
// entry.ioMu из планировщика, который обходит устройства ПОСЛЕДОВАТЕЛЬНО в
// одной горутине. То есть одно «залипшее» устройство останавливало ротацию
// ключей и проверки прошивки для ВСЕХ остальных. Значение с большим запасом
// перекрывает время передачи самого крупного кадра (шифротекст ML-KEM, 1568
// байт) даже в медленной сети.
const WriteTimeout = 15 * time.Second

// MaxConnections — предельное число одновременно обслуживаемых соединений.
// Каждое принятое соединение занимает горутину и буферы, а рукопожатие ещё до
// проверки регистрации выполняет разбор кадров, поэтому без потолка поток
// подключений извне вынуждает шлюз выделять память неограниченно. Значение
// выбрано с большим запасом относительно ожидаемого парка устройств: шлюз
// рассчитан на десятки-сотни устройств, а лимит начинает действовать на
// порядок позже. Переменная, а не константа, чтобы поднять её на стенде
// нагрузочного тестирования (LACERT_MAX_CONNECTIONS, см. cmd/gatewayd).
var MaxConnections = 1024

// connEntry — состояние одного активного соединения устройства. Хранится в
// Server.conns как указатель, чтобы можно было надёжно отличить "эта же
// горутина обслуживает актуальное соединение" от "устройство уже
// переподключилось, а эта горутина обслуживает старое, отозванное
// соединение" — сравнением указателей при удалении из карты (см. handleConn).
type connEntry struct {
	conn   net.Conn
	remote string

	// ioMu защищает не только сами байты записи в conn от побайтового
	// перемешивания при конкурентных вызовах — она используется как точка
	// сериализации ВСЕЙ операции "вычислить следующий шаг протокола (новый
	// Kyber-шифротекст при ротации / challenge при проверке прошивки) и
	// сразу отправить его" в InitiateRotation/IssueFirmwareChallenge.
	// Без этого два конкурентных вызова InitiateRotation для одного и того
	// же устройства могли бы вычислить шаги в одном порядке, а отправить
	// кадры в другом (из-за планирования горутин ОС) — тогда устройство
	// применило бы Mi в порядке, отличном от того, в котором шлюз обновлял
	// свою сессию, и стороны разошлись бы по ключу, не имея при этом ни
	// одного повреждённого байта на проводе.
	ioMu sync.Mutex

	mu       sync.Mutex
	lastSeen time.Time
}

func (e *connEntry) write(msgType byte, payload []byte) error {
	e.ioMu.Lock()
	defer e.ioMu.Unlock()
	return writeFrameWithDeadline(e.conn, msgType, payload)
}

// writeFrameWithDeadline пишет кадр с ограничением по времени — см. комментарий
// к WriteTimeout о том, почему блокирующая запись здесь недопустима. Дедлайн
// снимается после записи, чтобы не влиять на последующие операции с сокетом.
func writeFrameWithDeadline(conn net.Conn, msgType byte, payload []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	return wire.WriteFrame(conn, msgType, payload)
}

func (e *connEntry) touch() {
	e.mu.Lock()
	e.lastSeen = time.Now()
	e.mu.Unlock()
}

func (e *connEntry) LastSeen() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSeen
}

// Status — статус соединения устройства, для REST API / будущей веб-страницы.
type Status struct {
	Online     bool
	RemoteAddr string
	LastSeen   time.Time
}

// Server — TCP-сервер шлюза.
type Server struct {
	GW     *gateway.Gateway
	Logger *slog.Logger

	mu     sync.Mutex
	conns  map[string]*connEntry
	ln     net.Listener
	wg     sync.WaitGroup
	active int // текущее число обслуживаемых соединений, под mu

	// serveStarted и serveExited дают Shutdown дождаться выхода самой горутины
	// Serve, а не только обслуживающих: флаг под mu отмечает, что цикл accept
	// запускался, канал закрывается при его завершении.
	serveStarted bool
	serveExited  chan struct{}

	// OnData вызывается каждый раз, когда шлюз успешно расшифровал пакет
	// данных от устройства — сюда подключается передача в корпоративную
	// систему (REST/MQTT, см. internal/api и internal/mqttbridge).
	OnData func(deviceID string, plaintext []byte)
}

// New создаёт TCP-сервер шлюза над уже настроенным gateway.Gateway.
func New(gw *gateway.Gateway, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		GW:          gw,
		Logger:      logger,
		conns:       make(map[string]*connEntry),
		serveExited: make(chan struct{}),
	}
}

// ListenAndServe запускает приём соединений на addr (например, ":7700") и
// блокируется до ошибки listener'а или вызова Shutdown.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ln)
}

// Serve принимает соединения на уже открытом listener'е и блокируется до
// его закрытия (в т.ч. через Shutdown). Вынесено отдельно от ListenAndServe,
// чтобы вызывающий код (в т.ч. тесты) мог сам создать listener на порту
// ":0" и узнать реальный назначенный порт через ln.Addr() до начала
// обслуживания соединений.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.serveStarted = true
	s.mu.Unlock()
	// Serve одноразовый, как и сам listener: закрытие serveExited сигналит
	// Shutdown, что цикл accept вышел и горутина завершилась.
	defer close(s.serveExited)

	// Предел читается один раз при старте — настройка и так задаётся до
	// запуска и на лету не меняется. Снимок ещё и исключает гонку с тестами,
	// которые возвращают прежнее значение глобальной переменной после
	// остановки сервера: цикл после старта к ней не обращается.
	limit := MaxConnections

	s.Logger.Info("шлюз слушает TCP-соединения от устройств", "addr", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.wg.Wait() // ждём завершения всех обслуживающих горутин при штатной остановке
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		// Потолок проверяем до запуска горутины: отказ должен быть дешёвым,
		// иначе защита сама становится нагрузкой.
		s.mu.Lock()
		over := s.active >= limit
		if !over {
			s.active++
		}
		s.mu.Unlock()
		if over {
			s.Logger.Warn("достигнут предел одновременных соединений, подключение отклонено",
				"remote", conn.RemoteAddr().String(), "limit", limit)
			_ = conn.Close()
			continue
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(keepAlivePeriod)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				s.active--
				s.mu.Unlock()
			}()
			s.handleConn(conn)
		}()
	}
}

// ActiveConnections возвращает число обслуживаемых сейчас соединений.
// Нужен тестам и полезен для наблюдения за приближением к пределу.
func (s *Server) ActiveConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Shutdown закрывает listener и все активные соединения с устройствами и
// дожидается завершения всех горутин сервера — и обслуживающих, и самой
// горутины с циклом accept. До этой правки Shutdown ждал только обслуживающие,
// а хвост Serve оставался жить и после возврата — на этом однажды поймалась
// гонка данных в тестах: восстановление глобального предела соединений
// пересекалось с его чтением в ещё живом цикле. Вызывается из cmd/gatewayd
// при получении сигнала остановки.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for _, e := range s.conns {
		_ = e.conn.Close()
	}
	started := s.serveStarted
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		if started {
			<-s.serveExited
		}
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	// Defense-in-depth: разбор кадров ниже работает с сырыми байтами от
	// недоверенного источника (что угодно, подключившееся к порту 7700 —
	// не обязательно настоящее устройство и не обязательно злонамеренное:
	// в проде уже наблюдался сетевой сканер, слепо стучащийся на порт).
	// Основная защита — корректные проверки границ в internal/wire (см.
	// исправленное там переполнение uint16 в takeFramed), но если где-то
	// в будущем появится подобная ошибка, паника должна уронить только
	// одно это соединение, а не весь процесс шлюза и все остальные
	// подключённые устройства вместе с ним.
	defer func() {
		if r := recover(); r != nil {
			s.Logger.Error("восстановление после паники при обработке соединения (см. defense-in-depth в handleConn)",
				"remote", conn.RemoteAddr().String(), "panic", r)
		}
	}()
	remote := conn.RemoteAddr().String()

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	msgType, payload, err := wire.ReadFrame(conn)
	if err != nil {
		s.Logger.Warn("соединение закрыто до получения Msg1", "remote", remote, "err", err)
		return
	}
	if msgType != wire.TypeHandshakeMsg1 {
		s.Logger.Warn("первое сообщение в соединении не Msg1 — отбрасываем", "remote", remote, "type", msgType)
		return
	}
	msg1, err := wire.DecodeMsg1(payload)
	if err != nil {
		s.Logger.Warn("не удалось декодировать Msg1", "remote", remote, "err", err)
		return
	}

	msg2, pendingID, err := s.GW.HandleMsg1Tracked(msg1)
	if err != nil {
		s.Logger.Warn("рукопожатие отклонено на этапе Msg1", "device_id", msg1.DeviceID, "remote", remote, "err", err)
		_ = writeFrameWithDeadline(conn, wire.TypeError, wire.EncodeErrorMsg(err.Error()))
		return
	}
	if err := writeFrameWithDeadline(conn, wire.TypeHandshakeMsg2, wire.EncodeMsg2(msg2)); err != nil {
		s.Logger.Warn("не удалось отправить Msg2", "device_id", msg1.DeviceID, "err", err)
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	msgType, payload, err = wire.ReadFrame(conn)
	if err != nil || msgType != wire.TypeHandshakeMsg3 {
		s.Logger.Warn("не получено корректное Msg3", "device_id", msg1.DeviceID, "remote", remote, "err", err)
		return
	}
	msg3, err := wire.DecodeMsg3(payload)
	if err != nil {
		s.Logger.Warn("не удалось декодировать Msg3", "device_id", msg1.DeviceID, "err", err)
		return
	}
	// HandleMsg3Tracked, а не HandleMsg3: если устройство успело открыть новое
	// соединение, пока это завершало рукопожатие, состояние в шлюзе уже
	// принадлежит новому — и забирать его нельзя (иначе не установится ни то,
	// ни другое соединение).
	if err := s.GW.HandleMsg3Tracked(msg1.DeviceID, pendingID, msg3); err != nil {
		s.Logger.Warn("рукопожатие отклонено на этапе Msg3", "device_id", msg1.DeviceID, "err", err)
		_ = writeFrameWithDeadline(conn, wire.TypeError, wire.EncodeErrorMsg(err.Error()))
		return
	}

	s.Logger.Info("рукопожатие завершено, защищённый канал установлен", "device_id", msg1.DeviceID, "remote", remote)

	// Запоминаем ИМЕННО ту сессию, которую создало это рукопожатие: при
	// разрыве соединения закроется только она (см. CloseSessionInstance).
	ownSession, _ := s.GW.CurrentSession(msg1.DeviceID)

	entry := &connEntry{conn: conn, remote: remote, lastSeen: time.Now()}
	s.registerConn(msg1.DeviceID, entry)
	defer s.unregisterConn(msg1.DeviceID, entry)

	s.serveSession(conn, entry, msg1.DeviceID)

	// Соединение закончилось — закрываем и криптографическую сессию, затирая
	// сеансовый ключ. Иначе Gateway.sessions удерживал бы ключ каждого
	// когда-либо подключавшегося устройства до отзыва или остановки процесса.
	//
	// Закрываем строго свою сессию: если устройство успело переподключиться,
	// в шлюзе уже живёт сессия нового рукопожатия, и трогать её нельзя.
	if s.GW.CloseSessionInstance(msg1.DeviceID, ownSession) {
		s.Logger.Info("сессия устройства закрыта, ключи затёрты", "device_id", msg1.DeviceID)
	}
}

// registerConn устанавливает соединение как активное для deviceID. Если
// устройство уже было подключено (переподключение — например, после
// перезагрузки или временного разрыва сети), старое соединение немедленно
// закрывается: новое соединение всегда замещает старое, чтобы не оставлять
// "зависшую" горутину и не путать адресацию серверной ротации/проверки
// прошивки между двумя сокетами одного устройства.
func (s *Server) registerConn(deviceID string, entry *connEntry) {
	s.mu.Lock()
	if old, exists := s.conns[deviceID]; exists {
		s.Logger.Warn("устройство переподключилось — закрываю предыдущее соединение",
			"device_id", deviceID, "old_remote", old.remote, "new_remote", entry.remote)
		_ = old.conn.Close()
	}
	s.conns[deviceID] = entry
	s.mu.Unlock()
}

// unregisterConn удаляет запись о соединении ТОЛЬКО если карта до сих пор
// указывает именно на эту запись (entry) — сравнение указателей. Это
// предотвращает ситуацию, когда устаревшая горутина старого соединения
// (которое уже было заменено через registerConn) случайно удаляет запись о
// новом, актуальном соединении после того, как старый сокет наконец
// закрылся и его serveSession завершился с ошибкой чтения.
func (s *Server) unregisterConn(deviceID string, entry *connEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.conns[deviceID]; ok && current == entry {
		delete(s.conns, deviceID)
	}
}

// serveSession обрабатывает сообщения уже установленной сессии: данные,
// ротацию (инициированную устройством) и ответы на проверку целостности
// прошивки.
func (s *Server) serveSession(conn net.Conn, entry *connEntry, deviceID string) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
		msgType, payload, err := wire.ReadFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.Logger.Info("устройство закрыло соединение", "device_id", deviceID)
			} else if errors.Is(err, net.ErrClosed) {
				s.Logger.Info("соединение закрыто сервером (переподключение/остановка)", "device_id", deviceID)
			} else {
				s.Logger.Warn("ошибка чтения кадра (возможно, простой дольше IdleTimeout)", "device_id", deviceID, "err", err)
			}
			return
		}
		entry.touch()

		switch msgType {
		case wire.TypeData:
			nonce, ciphertext, err := wire.DecodeData(payload)
			if err != nil {
				s.Logger.Warn("не удалось декодировать пакет данных", "device_id", deviceID, "err", err)
				continue
			}
			plaintext, err := s.GW.HandleData(deviceID, nonce, ciphertext)
			if err != nil {
				s.Logger.Warn("не удалось расшифровать пакет данных", "device_id", deviceID, "err", err)
				continue
			}
			if s.OnData != nil {
				s.OnData(deviceID, plaintext)
			}

		case wire.TypeRotation:
			// Устаревшая НЕатомарная ротация (см. PROTOCOL_SPEC, тип 4:
			// «не используется»). Приём её здесь был опасен: кадр ничем не
			// аутентифицирован, а Session.Rotate() не трогает счётчик
			// iteration — то есть один такой кадр, отправленный кем угодно,
			// менял ключ шлюза, не сдвигая номер итерации, и навсегда
			// рассинхронизировал атомарную ротацию с устройством. Ни прошивка,
			// ни эмулятор этот тип не отправляют, поэтому просто отвергаем.
			s.Logger.Warn("получена устаревшая неатомарная ротация (тип 4) — отвергнута",
				"device_id", deviceID)
			continue

		case wire.TypeRotationV2:
			// Устройство инициировало атомарную ротацию: применяем и отвечаем
			// подтверждением (ACK). Ответ отправляется в рамках ioMu, чтобы не
			// перемешаться с конкурентной записью (например, challenge прошивки).
			// Ключ берётся ДО применения ротации и служит дважды: для
			// проверки метки пришедшего кадра и для метки подтверждения.
			// После применения ключ станет новым, а устройство проверит
			// метку прежним.
			key, err := s.GW.ControlKey(deviceID)
			if err != nil {
				s.Logger.Warn("нет сеансового ключа для проверки метки", "device_id", deviceID, "err", err)
				continue
			}
			rotMsg, err := wire.DecodeRotationV2(payload, key[:])
			if err != nil {
				s.Logger.Warn("не удалось декодировать сообщение атомарной ротации", "device_id", deviceID, "err", err)
				continue
			}
			ack, err := s.GW.HandleAtomicRotationFromDevice(deviceID, rotMsg)
			if err != nil {
				s.Logger.Warn("атомарная ротация, инициированная устройством, не удалась", "device_id", deviceID, "err", err)
				continue
			}
			if err := entry.write(wire.TypeRotationAck, wire.EncodeRotationAck(ack, key[:])); err != nil {
				s.Logger.Warn("не удалось отправить подтверждение ротации", "device_id", deviceID, "err", err)
				continue
			}
			s.Logger.Info("атомарная ротация (инициатор: устройство) применена, ACK отправлен",
				"device_id", deviceID, "iteration", ack.Iteration)

		case wire.TypeRotationAck:
			// Устройство подтвердило ротацию, инициированную шлюзом: коммитим.
			// Ключ ещё прежний: ротация применится ниже, после проверки метки.
			key, err := s.GW.ControlKey(deviceID)
			if err != nil {
				s.Logger.Warn("нет сеансового ключа для проверки метки", "device_id", deviceID, "err", err)
				continue
			}
			ack, err := wire.DecodeRotationAck(payload, key[:])
			if err != nil {
				s.Logger.Warn("не удалось декодировать подтверждение ротации", "device_id", deviceID, "err", err)
				continue
			}
			if err := s.GW.ApplyRotationAckFromDevice(deviceID, ack); err != nil {
				s.Logger.Warn("не удалось применить подтверждение ротации", "device_id", deviceID, "err", err)
				continue
			}
			s.Logger.Info("атомарная ротация (инициатор: шлюз) подтверждена устройством",
				"device_id", deviceID, "iteration", ack.Iteration)

		case wire.TypeFirmwareResponse:
			resp, err := wire.DecodeFirmwareResponse(payload)
			if err != nil {
				s.Logger.Warn("не удалось декодировать ответ проверки прошивки", "device_id", deviceID, "err", err)
				continue
			}
			result, err := s.GW.VerifyFirmwareCheck(deviceID, resp)
			if err != nil {
				s.Logger.Warn("ошибка проверки целостности прошивки", "device_id", deviceID, "err", err)
				continue
			}
			if !result.OK() {
				s.Logger.Warn("проверка целостности прошивки провалена — устройство отозвано",
					"device_id", deviceID, "signature_valid", result.SignatureValid, "hash_matches", result.HashMatches)
				_ = entry.write(wire.TypeError, wire.EncodeErrorMsg("firmware check failed: device revoked"))
				return
			}
			s.Logger.Info("проверка целостности прошивки пройдена", "device_id", deviceID)

		default:
			s.Logger.Warn("неизвестный тип сообщения в установленной сессии", "device_id", deviceID, "type", msgType)
		}
	}
}

// InitiateRotation — серверный цикл шлюза вызывает это для устройства,
// сессия которого (по таймеру/счётчику) нуждается в ротации, и шлюз сам
// выступает инициатором. Вычисление нового шага протокола и его отправка
// выполняются как единая критическая секция (entry.ioMu) — см. комментарий
// к connEntry.ioMu о том, почему это важно при конкурентных вызовах для
// одного устройства.
func (s *Server) InitiateRotation(deviceID string) error {
	entry, err := s.activeConn(deviceID)
	if err != nil {
		return err
	}
	entry.ioMu.Lock()
	defer entry.ioMu.Unlock()

	rotMsg, err := s.GW.InitiateRotationToDevice(deviceID)
	if err != nil {
		return err
	}
	return writeFrameWithDeadline(entry.conn, wire.TypeRotation, wire.EncodeRotation(rotMsg))
}

// InitiateAtomicRotation — атомарная ротация, инициированная шлюзом. Вычисляет
// RotationMsgV2 и отправляет его устройству; новый ключ применится только
// после того, как устройство пришлёт RotationAck (обрабатывается в
// serveSession как TypeRotationAck). Как и InitiateRotation, весь шаг
// сериализуется через ioMu.
func (s *Server) InitiateAtomicRotation(deviceID string) error {
	entry, err := s.activeConn(deviceID)
	if err != nil {
		return err
	}
	entry.ioMu.Lock()
	defer entry.ioMu.Unlock()

	rotMsg, err := s.GW.InitiateAtomicRotationToDevice(deviceID)
	if err != nil {
		return err
	}
	// Ключ действующий: новый вступит в силу только после подтверждения.
	key, err := s.GW.ControlKey(deviceID)
	if err != nil {
		return err
	}
	return writeFrameWithDeadline(entry.conn, wire.TypeRotationV2, wire.EncodeRotationV2(rotMsg, key[:]))
}

// IssueFirmwareChallenge — серверный цикл шлюза вызывает это раз в час для
// каждого устройства с активным соединением. См. также
// gateway.firmwareChallengeTimeout: повторный вызов для устройства с уже
// выданным, но пока неответным challenge вернёт ошибку, а не тихо подменит
// его — иначе устройство, отвечающее на ПЕРВЫЙ challenge, было бы
// неправомерно отклонено как не прошедшее проверку.
func (s *Server) IssueFirmwareChallenge(deviceID string) error {
	entry, err := s.activeConn(deviceID)
	if err != nil {
		return err
	}
	entry.ioMu.Lock()
	defer entry.ioMu.Unlock()

	challenge, err := s.GW.IssueFirmwareChallenge(deviceID)
	if err != nil {
		return err
	}
	return writeFrameWithDeadline(entry.conn, wire.TypeFirmwareChallenge, wire.EncodeFirmwareChallenge(challenge))
}

// ActiveDeviceIDs возвращает список устройств с активным TCP-соединением —
// используется серверным циклом, который периодически обходит подключённые
// устройства (ротация по таймеру, проверка прошивки раз в час), а также
// будущей веб-страницей для отображения статуса "онлайн".
func (s *Server) ActiveDeviceIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.conns))
	for id := range s.conns {
		ids = append(ids, id)
	}
	return ids
}

// Status возвращает текущий статус соединения устройства — для REST API /
// веб-страницы (онлайн/офлайн, адрес, время последнего полученного кадра).
func (s *Server) Status(deviceID string) (Status, bool) {
	s.mu.Lock()
	entry, ok := s.conns[deviceID]
	s.mu.Unlock()
	if !ok {
		return Status{}, false
	}
	return Status{Online: true, RemoteAddr: entry.remote, LastSeen: entry.LastSeen()}, true
}

// Disconnect принудительно закрывает активное соединение устройства, если
// оно есть, предварительно отправив явный кадр с причиной. Возвращает
// false, если активного соединения не было (например, устройство уже было
// offline на момент отзыва — это не ошибка, а нормальный случай).
//
// Вызывается после отзыва устройства (см. gateway.Gateway.RevokeDevice) —
// сам по себе отзыв в Gateway/Store не разрывает уже установленный TCP-канал
// (Gateway намеренно ничего не знает о транспорте), поэтому транспортный
// слой должен сделать это явно, иначе уже подключённое устройство продолжит
// нормально работать (слать данные, ротировать ключи) вплоть до естественного
// разрыва соединения, несмотря на отзыв.
func (s *Server) Disconnect(deviceID, reason string) bool {
	entry, err := s.activeConn(deviceID)
	if err != nil {
		return false
	}
	entry.ioMu.Lock()
	_ = writeFrameWithDeadline(entry.conn, wire.TypeError, wire.EncodeErrorMsg(reason))
	entry.ioMu.Unlock()
	_ = entry.conn.Close()
	return true
}

func (s *Server) activeConn(deviceID string) (*connEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.conns[deviceID]
	if !ok {
		return nil, fmt.Errorf("no active connection for device %q", deviceID)
	}
	return entry, nil
}
