package emulator

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"strings"
	"time"
)

// Profile — тип эмулируемого датчика/прибора. Разные профили шлют разные
// наборы полей, чтобы дашборд мониторинга (раздел "Мониторинг" в
// веб-интерфейсе) показывал содержательно разные графики для разных
// устройств вместо одной и той же температуры/влажности, скопированной на
// все эмулированные приборы.
type Profile string

const (
	// ProfileClimate — датчик климата помещения/склада.
	ProfileClimate Profile = "climate"
	// ProfilePower — счётчик электропотребления (вводной щит/линия).
	ProfilePower Profile = "power"
	// ProfilePressure — датчик давления (трубопровод/резервуар).
	ProfilePressure Profile = "pressure"
	// ProfileFuel — датчик уровня топлива/жидкости в ёмкости.
	ProfileFuel Profile = "fuel"
	// ProfileMotor — вибро-датчик вращающегося оборудования (мотор/насос).
	ProfileMotor Profile = "motor"
)

// AllProfiles — полный список доступных профилей, в фиксированном порядке
// (используется для равномерного распределения профилей по индексу
// устройства в cmd/gatewayd, чтобы при LACERT_EMULATE_DEVICES=5 получить
// ровно 5 разных типов приборов, а не случайное совпадение).
func AllProfiles() []Profile {
	return []Profile{ProfileClimate, ProfilePower, ProfilePressure, ProfileFuel, ProfileMotor}
}

// ProfileForIndex возвращает профиль для устройства по его порядковому
// номеру (1-based) — циклически по AllProfiles(), так что 10 устройств
// дадут по 2 каждого типа, а не 10 одинаковых.
func ProfileForIndex(i int) Profile {
	all := AllProfiles()
	if i <= 0 {
		i = 1
	}
	return all[(i-1)%len(all)]
}

// profileForDeviceID — запасной вариант, когда явный индекс недоступен
// (например, отдельный процесс cmd/devicesim с произвольным DeviceID):
// детерминированно выбирает профиль по хешу DeviceID, чтобы один и тот же
// DeviceID между перезапусками всегда получал один и тот же тип прибора.
func profileForDeviceID(deviceID string) Profile {
	h := fnv.New32a()
	_, _ = h.Write([]byte(deviceID))
	all := AllProfiles()
	return all[int(h.Sum32())%len(all)]
}

// telemetryGenerator формирует реалистично выглядящие, но синтетические
// показания во времени: базовый уровень + медленная синусоидальная волна +
// случайный шум. База и амплитуда выбираются один раз при создании
// генератора детерминированным по DeviceID источником случайности — то есть
// один и тот же DeviceID между перезапусками процесса получает один и тот
// же характер показаний (но разные конкретные точки, так как шум не
// детерминирован), а разные DeviceID с одним профилем всё равно выглядят
// по-разному на графике (разная база/амплитуда/фаза).
type telemetryGenerator struct {
	profile Profile
	start   time.Time
	rng     *rand.Rand

	// Параметры синтетических волн — конкретный смысл зависит от профиля,
	// см. fieldSpecs ниже.
	base  [3]float64
	amp   [3]float64
	noise [3]float64
	phase [3]float64
	// periodSec — период синусоиды в секундах для каждого поля; разный для
	// разных полей одного устройства, чтобы графики не были идеально
	// синфазными (как было раньше: пилообразная temperature и humidity
	// двигались одинаково).
	periodSec [3]float64
}

type fieldSpec struct {
	name string
	// baseMin/baseMax — диапазон случайного выбора базового уровня при
	// создании генератора (имитирует "разные приборы откалиброваны
	// чуть по-разному").
	baseMin, baseMax float64
	amp              float64
	noise            float64
	periodSec        float64
	decimals         int
	// monotonicDrift, если true — поле не колеблется синусоидой, а медленно
	// и монотонно дрейфует от base к base-amp за characteristic time (для
	// "уровень топлива снижается со временем").
	monotonicDrift bool
}

var profileFields = map[Profile][]fieldSpec{
	ProfileClimate: {
		{name: "temperature", baseMin: 18, baseMax: 26, amp: 2.5, noise: 0.15, periodSec: 600, decimals: 1},
		{name: "humidity", baseMin: 35, baseMax: 55, amp: 8, noise: 0.8, periodSec: 900, decimals: 0},
	},
	ProfilePower: {
		{name: "voltage", baseMin: 218, baseMax: 232, amp: 3, noise: 0.4, periodSec: 120, decimals: 1},
		{name: "current_a", baseMin: 2, baseMax: 14, amp: 3, noise: 0.3, periodSec: 240, decimals: 2},
		{name: "power_w", baseMin: 500, baseMax: 3000, amp: 400, noise: 25, periodSec: 240, decimals: 0},
	},
	ProfilePressure: {
		{name: "pressure_kpa", baseMin: 95, baseMax: 110, amp: 4, noise: 0.3, periodSec: 1800, decimals: 2},
		{name: "temperature", baseMin: 15, baseMax: 35, amp: 3, noise: 0.2, periodSec: 1200, decimals: 1},
	},
	ProfileFuel: {
		{name: "level_percent", baseMin: 60, baseMax: 95, amp: 35, noise: 0.3, periodSec: 7200, decimals: 1, monotonicDrift: true},
		{name: "temperature", baseMin: 10, baseMax: 25, amp: 1.5, noise: 0.2, periodSec: 1800, decimals: 1},
	},
	ProfileMotor: {
		{name: "rpm", baseMin: 1200, baseMax: 2800, amp: 80, noise: 15, periodSec: 60, decimals: 0},
		{name: "vibration_mm_s", baseMin: 0.8, baseMax: 3.5, amp: 0.6, noise: 0.15, periodSec: 45, decimals: 2},
		{name: "temperature", baseMin: 45, baseMax: 75, amp: 4, noise: 0.3, periodSec: 900, decimals: 1},
	},
}

func newTelemetryGenerator(deviceID string, profile Profile) *telemetryGenerator {
	seed := deterministicSeed(deviceID, profile)
	rng := rand.New(rand.NewSource(seed))

	g := &telemetryGenerator{profile: profile, start: time.Now(), rng: rng}
	specs := profileFields[profile]
	for i, spec := range specs {
		if i >= len(g.base) {
			break // защита на случай расширения profileFields сверх 3 полей
		}
		g.base[i] = spec.baseMin + rng.Float64()*(spec.baseMax-spec.baseMin)
		g.amp[i] = spec.amp
		g.noise[i] = spec.noise
		g.periodSec[i] = spec.periodSec
		g.phase[i] = rng.Float64() * 2 * math.Pi // случайный сдвиг фазы — устройства не синхронны друг с другом
	}
	return g
}

// deterministicSeed комбинирует DeviceID и профиль в числовой seed — два
// устройства с одинаковым DeviceID (между перезапусками процесса) получат
// одинаковую базу/амплитуду/фазу, а разные DeviceID почти наверняка получат
// разные (не криптографическое свойство, просто для разнообразия графиков).
func deterministicSeed(deviceID string, profile Profile) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(deviceID))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(profile))
	return int64(h.Sum64())
}

// Next формирует один payload в формате "key=value;key2=value2..." (см.
// internal/telemetry.ParseKV) для текущего момента времени.
func (g *telemetryGenerator) Next(seq int) string {
	specs := profileFields[g.profile]
	elapsed := time.Since(g.start).Seconds()

	parts := make([]string, 0, len(specs)+1)
	for i, spec := range specs {
		var v float64
		if spec.monotonicDrift {
			// Монотонный медленный спад/рост к (base - amp), асимптотически,
			// плюс небольшой шум — имитирует, например, расход топлива.
			progress := 1 - math.Exp(-elapsed/spec.periodSec)
			v = g.base[i] - spec.amp*progress
		} else {
			wave := math.Sin(2*math.Pi*elapsed/spec.periodSec + g.phase[i])
			v = g.base[i] + g.amp[i]*wave
		}
		v += (g.rng.Float64()*2 - 1) * spec.noise
		parts = append(parts, fmt.Sprintf("%s=%s", spec.name, formatFloat(v, spec.decimals)))
	}
	parts = append(parts, fmt.Sprintf("seq=%d", seq))
	return strings.Join(parts, ";")
}

func formatFloat(v float64, decimals int) string {
	return fmt.Sprintf("%.*f", decimals, v)
}
