package telemetry

import "testing"

// Проверяем, что шлюз разбирает телеметрию с замерами, снятыми на плате.
func TestParseOnDeviceMeasurements(t *testing.T) {
	payload := "temperature=25.5; seq=42; heap_free=244340; heap_min=238112; " +
		"handshake_us=185300; rotation_us=612; fw_sign_us=1240"
	parsed := ParseKV(payload)
	want := map[string]float64{
		"temperature":  25.5,
		"seq":          42,
		"heap_free":    244340,
		"heap_min":     238112,
		"handshake_us": 185300,
		"rotation_us":  612,
		"fw_sign_us":   1240,
	}
	for k, v := range want {
		got, ok := parsed[k]
		if !ok {
			t.Fatalf("поле %q не распознано шлюзом", k)
		}
		if got != v {
			t.Fatalf("%q: получено %v, ожидалось %v", k, got, v)
		}
	}
	t.Logf("шлюз распознал все %d полей замеров", len(want))
}
