package emulator

import (
	"testing"

	"lacert/internal/telemetry"
)

func TestAllProfilesHaveFieldSpecs(t *testing.T) {
	for _, p := range AllProfiles() {
		specs, ok := profileFields[p]
		if !ok || len(specs) == 0 {
			t.Fatalf("profile %q has no field specs defined", p)
		}
		if len(specs) > 3 {
			t.Fatalf("profile %q defines %d fields, but telemetryGenerator only has 3 slots (base/amp/noise/phase/periodSec arrays)", p, len(specs))
		}
	}
}

func TestProfileForIndexCyclesThroughAllProfiles(t *testing.T) {
	all := AllProfiles()
	for i := 1; i <= len(all)*2; i++ {
		got := ProfileForIndex(i)
		want := all[(i-1)%len(all)]
		if got != want {
			t.Fatalf("ProfileForIndex(%d) = %q, want %q", i, got, want)
		}
	}
	// Индекс <= 0 не должен паниковать — клампится к первому профилю.
	if got := ProfileForIndex(0); got != all[0] {
		t.Fatalf("ProfileForIndex(0) = %q, want %q (clamped to first)", got, all[0])
	}
	if got := ProfileForIndex(-5); got != all[0] {
		t.Fatalf("ProfileForIndex(-5) = %q, want %q (clamped to first)", got, all[0])
	}
}

func TestProfileForDeviceIDIsDeterministic(t *testing.T) {
	a := profileForDeviceID("emulated-esp32-1")
	b := profileForDeviceID("emulated-esp32-1")
	if a != b {
		t.Fatalf("profileForDeviceID should be deterministic for the same DeviceID, got %q then %q", a, b)
	}
}

func TestTelemetryGeneratorProducesParsableNumericFields(t *testing.T) {
	for _, p := range AllProfiles() {
		t.Run(string(p), func(t *testing.T) {
			gen := newTelemetryGenerator("test-device-"+string(p), p)
			payload := gen.Next(1)

			parsed := telemetry.ParseKV(payload)
			specs := profileFields[p]
			for _, spec := range specs {
				v, ok := parsed[spec.name]
				if !ok {
					t.Fatalf("profile %q: expected field %q in payload %q, parsed=%v", p, spec.name, payload, parsed)
				}
				// Значение должно быть в разумных пределах вокруг заявленного
				// диапазона (с запасом на амплитуду+шум).
				lo := spec.baseMin - spec.amp - spec.noise*3
				hi := spec.baseMax + spec.amp + spec.noise*3
				if v < lo || v > hi {
					t.Fatalf("profile %q field %q = %v is out of plausible range [%v, %v]", p, spec.name, v, lo, hi)
				}
			}
			if _, ok := parsed["seq"]; !ok {
				t.Fatalf("expected 'seq' field in payload %q", payload)
			}
		})
	}
}

func TestTelemetryGeneratorIsDeterministicForSameDeviceID(t *testing.T) {
	gen1 := newTelemetryGenerator("device-x", ProfileClimate)
	gen2 := newTelemetryGenerator("device-x", ProfileClimate)

	// Базовые уровни (до применения шума) должны совпадать для одного и того
	// же DeviceID+Profile — иначе один и тот же реальный прибор выглядел бы
	// по-разному на графике после каждого перезапуска эмулятора.
	if gen1.base != gen2.base {
		t.Fatalf("expected identical base levels for same DeviceID, got %v vs %v", gen1.base, gen2.base)
	}
	if gen1.phase != gen2.phase {
		t.Fatalf("expected identical phase for same DeviceID, got %v vs %v", gen1.phase, gen2.phase)
	}
}

func TestTelemetryGeneratorDiffersAcrossDevices(t *testing.T) {
	gen1 := newTelemetryGenerator("device-a", ProfileClimate)
	gen2 := newTelemetryGenerator("device-b", ProfileClimate)

	if gen1.base == gen2.base {
		t.Fatalf("expected different base levels for different DeviceIDs (got identical %v) — graphs would be indistinguishable", gen1.base)
	}
}

func TestFuelProfileDriftsDownwardOverTime(t *testing.T) {
	gen := newTelemetryGenerator("fuel-tank-1", ProfileFuel)
	// Имитация прошедшего времени: подменяем start в прошлое, чтобы не ждать
	// реальные часы в тесте.
	gen.start = gen.start.Add(-2 * 3600 * 1e9) // -2 часа в наносекундах

	payload := gen.Next(1)
	parsed := telemetry.ParseKV(payload)
	level, ok := parsed["level_percent"]
	if !ok {
		t.Fatalf("expected level_percent field, got %v", parsed)
	}
	spec := profileFields[ProfileFuel][0]
	// После двух часов (характерное время дрейфа 7200с = 2ч) уровень должен
	// заметно просесть относительно базового — это и есть смысл "топливо
	// расходуется", а не оставаться на месте, как при обычной синусоиде.
	if level > spec.baseMax-spec.amp*0.3 {
		t.Fatalf("expected fuel level to have drifted down noticeably after 2h, got %v (base range %v..%v, amp %v)",
			level, spec.baseMin, spec.baseMax, spec.amp)
	}
}
