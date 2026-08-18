// Package scheduler реализует серверный фоновый цикл шлюза: периодический
// обход активных соединений для инициирования ротации ключа по таймеру
// (300 секунд — см. internal/crypto.RotationInterval) и проверки
// целостности прошивки раз в час (см. раздел "5. Проверка целостности
// прошивки" работы).
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"lacert/internal/crypto"
	"lacert/internal/gateway"
	"lacert/internal/transport/tcpserver"
)

// FirmwareCheckInterval — периодичность проверки целостности прошивки,
// упомянутая в работе ("раз в час").
const FirmwareCheckInterval = time.Hour

// DefaultMaxConsecutiveRotationFailures — сколько подряд неуспешных ротаций
// (ACK не пришёл в срок) допускается для устройства, прежде чем шлюз отзовёт
// его. Значение по умолчанию для поля Scheduler.MaxRotationFailures.
const DefaultMaxConsecutiveRotationFailures = 3

// MaxConsecutiveRotationFailures сохранён для обратной совместимости ссылок в
// тестах; фактический порог берётся из поля Scheduler.MaxRotationFailures.
const MaxConsecutiveRotationFailures = DefaultMaxConsecutiveRotationFailures

// Scheduler — фоновый цикл шлюза.
type Scheduler struct {
	GW     *gateway.Gateway
	Srv    *tcpserver.Server
	Logger *slog.Logger

	// RotationCheckPeriod — как часто планировщик опрашивает сессии на
	// предмет "не пора ли ротировать" (сама ротация всё равно происходит не
	// чаще, чем раз в RotationInterval/RotationPacketLimit — это просто
	// частота опроса). Маленькое значение по умолчанию (5 сек) не нагружает
	// систему, так как Session.NeedsRotation() — это две дешёвые проверки.
	RotationCheckPeriod time.Duration

	// FirmwareInterval — как часто проверять целостность прошивки каждого
	// устройства. По умолчанию FirmwareCheckInterval (1 час); может быть
	// уменьшен для тестов/демонстрации (см. LACERT_FIRMWARE_INTERVAL).
	FirmwareInterval time.Duration

	// MaxRotationFailures — порог подряд идущих неуспешных ротаций, после
	// которого устройство отзывается. По умолчанию
	// DefaultMaxConsecutiveRotationFailures (3); настраивается на стенде через
	// LACERT_MAX_ROTATION_FAILURES.
	MaxRotationFailures int

	lastFirmwareCheck map[string]time.Time
	// rotationFailures — счётчик подряд идущих неуспешных ротаций на устройство.
	// Сбрасывается при успешной ротации; при достижении порога устройство
	// отзывается (см. MaxConsecutiveRotationFailures).
	rotationFailures map[string]int
	// failureSeen — когда счётчик неудач устройства обновлялся в последний
	// раз. Нужен, чтобы удалять записи устройств, которые давно не
	// появлялись: сам счётчик переживает переподключения намеренно.
	failureSeen map[string]time.Time
	// lastIteration — последний известный номер итерации ротации на устройство,
	// для обнаружения успешного продвижения ротации между тактами.
	lastIteration map[string]uint64
}

// New создаёт планировщик с настройками по умолчанию.
func New(gw *gateway.Gateway, srv *tcpserver.Server, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		GW:                  gw,
		Srv:                 srv,
		Logger:              logger,
		RotationCheckPeriod: 5 * time.Second,
		FirmwareInterval:    FirmwareCheckInterval,
		MaxRotationFailures: DefaultMaxConsecutiveRotationFailures,
		lastFirmwareCheck:   make(map[string]time.Time),
		rotationFailures:    make(map[string]int),
		failureSeen:         make(map[string]time.Time),
		lastIteration:       make(map[string]uint64),
	}
}

// Run блокируется и периодически обходит активные устройства до отмены ctx.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.RotationCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick()
		}
	}
}

func (s *Scheduler) tick() {
	active := s.Srv.ActiveDeviceIDs()
	for _, deviceID := range active {
		s.maybeRotate(deviceID)
		s.maybeCheckFirmware(deviceID)
	}
	s.pruneFirmwareCheckState(active)
}

// pruneFirmwareCheckState удаляет из lastFirmwareCheck записи устройств,
// которых больше нет среди активных соединений — без этого карта росла бы
// неограниченно на долго работающем процессе с частой сменой устройств
// (переподключения под новыми ID, повторные регистрации при тестировании и
// т.п.), поскольку раньше запись добавлялась при каждом новом deviceID, но
// никогда не удалялась.
func (s *Scheduler) pruneFirmwareCheckState(active []string) {
	activeSet := make(map[string]struct{}, len(active))
	for _, id := range active {
		activeSet[id] = struct{}{}
	}
	// Чистим ВСЕ карты состояния, а не только lastFirmwareCheck: раньше
	// rotationFailures и lastIteration росли теми же темпами и по той же
	// причине (запись заводится на каждый новый deviceID и не удаляется
	// никогда), просто про них забыли. Заодно это правильно и по смыслу:
	// счётчик неуспешных ротаций отключившегося устройства не должен
	// доживать до его следующего подключения — там будет новая сессия с
	// нулевой итерацией.
	for id := range s.lastFirmwareCheck {
		if _, ok := activeSet[id]; !ok {
			delete(s.lastFirmwareCheck, id)
		}
	}
	// Счётчик неуспешных ротаций намеренно НЕ чистится при отключении.
	//
	// Прежде чистился, и это было верно, пока неудача означала повторную
	// попытку ротации в той же сессии. Теперь неудача приводит к разрыву
	// соединения ради нового рукопожатия — и если стирать счётчик при
	// отключении, он обнулялся бы после каждого разрыва, порог отзыва не
	// достигался бы никогда, а неисправное устройство переподключалось бы
	// бесконечно.
	//
	// Счётчик обнуляется в двух случаях: успешная ротация (см.
	// checkRotationProgress) и превышение порога с отзывом. Чтобы записи не
	// копились от устройств, которые больше не появятся, они удаляются по
	// сроку давности.
	s.forgetStaleFailures()
	for id := range s.lastIteration {
		if _, ok := activeSet[id]; !ok {
			delete(s.lastIteration, id)
		}
	}
}

func (s *Scheduler) maybeRotate(deviceID string) {
	// Подтверждение ротации не пришло в срок, и шлюз откатился на прежний
	// ключ. Устройство при этом новый ключ уже применило: в протоколе оно
	// делает это до отправки подтверждения, иначе метку подлинности пришлось
	// бы считать ключом, которого у шлюза ещё нет.
	//
	// Отсюда следствие, ради которого этот блок и переписан: после отката
	// ключи сторон расходятся немедленно. Шлюз перестаёт расшифровывать
	// пакеты устройства, а устройство об этом не знает и продолжает слать.
	// Прежде шлюз просто повторял попытку ротации, копил неудачи и после
	// третьей отзывал устройство — то есть исправная плата с медленной сетью
	// выводилась из строя навсегда, а разошедшиеся ключи всё это время не
	// давали работать.
	//
	// Правильный выход — не повторять ротацию, а разорвать соединение.
	// Устройство переподключится и пройдёт рукопожатие заново, получив свежий
	// ключ; проверено, что после расхождения повторное рукопожатие проходит.
	// Отзыв остаётся, но лишь как последняя мера: если переподключение не
	// помогает раз за разом, дело не в сети, и устройство действительно
	// неисправно.
	if s.GW.AbortStaleRotationIfNeeded(deviceID, crypto.RotationAckTimeout) {
		s.rotationFailures[deviceID]++
		s.failureSeen[deviceID] = time.Now()
		fails := s.rotationFailures[deviceID]

		if fails < s.MaxRotationFailures {
			s.Logger.Warn("подтверждение ротации не получено в срок — разрываем соединение для повторного рукопожатия",
				"device_id", deviceID, "подряд_неуспешных", fails,
				"порог_отзыва", s.MaxRotationFailures)
			s.Srv.Disconnect(deviceID, "rotation not acknowledged: reconnect and handshake again")
			_ = s.GW.Store.LogEvent(deviceID, "rotation_timeout",
				"подтверждение ротации не получено в срок, соединение разорвано для повторного рукопожатия")
			return
		}

		// Порог исчерпан: переподключение не помогло, дело не в задержках сети.
		s.Logger.Error("устройство не подтверждает ротацию даже после переподключений — отзыв",
			"device_id", deviceID, "лимит", s.MaxRotationFailures)
		_ = s.GW.Store.LogEvent(deviceID, "rotation_timeout",
			"подтверждение ротации не получено в срок, лимит переподключений исчерпан — устройство отзывается")
		if err := s.GW.RevokeDevice(deviceID,
			"устройство не подтвердило ротацию ключа заданное число раз подряд, включая попытки после переподключения"); err != nil {
			s.Logger.Warn("не удалось отозвать устройство после серии неуспешных ротаций",
				"device_id", deviceID, "err", err)
		}
		// Отзыв в Gateway закрывает криптографическую сессию, но не рвёт
		// TCP-сокет: транспорт про отзыв ничего не знает. Без явного разрыва
		// отозванное устройство оставалось подключённым, попадало в
		// ActiveDeviceIDs, и планировщик бесконечно пытался ротировать ему
		// ключ.
		s.Srv.Disconnect(deviceID, "device revoked: rotation not acknowledged")
		delete(s.rotationFailures, deviceID)
		delete(s.failureSeen, deviceID)
		return
	}

	// Ротация уже начата и ждёт подтверждения, но срок ожидания ещё не вышел
	// (иначе её откатили бы выше). Начинать вторую нельзя, и пытаться незачем:
	// попытка вернула бы отказ и записала в журнал тревожное сообщение о
	// неудавшейся ротации там, где всё идёт по плану. Ждём следующего такта.
	if s.GW.HasPendingRotation(deviceID) {
		return
	}

	needs, err := s.GW.NeedsRotation(deviceID)
	if err != nil || !needs {
		// Даже когда ротация сейчас не требуется, проверяем: не продвинулся ли
		// номер итерации с прошлого раза (т.е. ротация успешно завершилась) —
		// тогда сбрасываем счётчик неуспешных попыток.
		s.checkRotationProgress(deviceID)
		return
	}
	// Ротация нужна: если предыдущая уже успела успешно примениться, сбросим
	// счётчик перед новой попыткой.
	s.checkRotationProgress(deviceID)
	if err := s.Srv.InitiateAtomicRotation(deviceID); err != nil {
		s.Logger.Warn("плановая атомарная ротация по таймеру не удалась", "device_id", deviceID, "err", err)
		return
	}
	s.Logger.Info("плановая атомарная ротация ключа (по таймеру) инициирована шлюзом", "device_id", deviceID)
}

// checkRotationProgress сбрасывает счётчик неуспешных ротаций устройства, если
// номер итерации его сессии продвинулся с прошлого такта (значит, ротация
// подтверждена). Так одиночные сбои не копятся до отзыва у нормально
// работающего устройства.
func (s *Scheduler) checkRotationProgress(deviceID string) {
	iter := s.GW.SessionIteration(deviceID)
	if prev, ok := s.lastIteration[deviceID]; ok && iter > prev {
		s.noteRotationSuccess(deviceID)
	}
	s.lastIteration[deviceID] = iter
}

// failureRetention — как долго счётчик неудачных ротаций живёт без обновления.
//
// Значение с запасом: устройству нужно время на переподключение и новое
// рукопожатие, а между попытками ротации проходит целый её период. Час
// покрывает и медленную сеть, и устройство, которое ушло спать.
const failureRetention = time.Hour

// forgetStaleFailures удаляет счётчики устройств, которые давно не отмечались.
// Без этого карта росла бы от каждого устройства, побывавшего на связи.
func (s *Scheduler) forgetStaleFailures() {
	cutoff := time.Now().Add(-failureRetention)
	for id, seen := range s.failureSeen {
		if seen.Before(cutoff) {
			delete(s.rotationFailures, id)
			delete(s.failureSeen, id)
		}
	}
}

// noteRotationSuccess сбрасывает счётчик неуспешных ротаций устройства — это
// вызывается, когда ротация подтверждена (счётчик обнуляется, чтобы одиночные
// сбои сети не накапливались до отзыва). Планировщик определяет успех по тому,
// что номер итерации сессии продвинулся с прошлого такта.
func (s *Scheduler) noteRotationSuccess(deviceID string) {
	if s.rotationFailures[deviceID] != 0 {
		delete(s.rotationFailures, deviceID)
		delete(s.failureSeen, deviceID)
	}
}

func (s *Scheduler) maybeCheckFirmware(deviceID string) {
	last, seen := s.lastFirmwareCheck[deviceID]
	if seen && time.Since(last) < s.FirmwareInterval {
		return
	}
	if err := s.Srv.IssueFirmwareChallenge(deviceID); err != nil {
		s.Logger.Warn("не удалось отправить запрос проверки целостности прошивки", "device_id", deviceID, "err", err)
		return
	}
	s.lastFirmwareCheck[deviceID] = time.Now()
	s.Logger.Info("отправлен плановый запрос проверки целостности прошивки", "device_id", deviceID)
}
