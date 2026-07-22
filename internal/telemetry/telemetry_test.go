package telemetry

import "testing"

func TestParseKV(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    map[string]float64
	}{
		{
			name:    "typical emulator payload",
			payload: "temperature=23.5;humidity=41;seq=3",
			want:    map[string]float64{"temperature": 23.5, "humidity": 41, "seq": 3},
		},
		{
			name:    "negative and decimal values",
			payload: "temperature=-5.25;voltage=3.3",
			want:    map[string]float64{"temperature": -5.25, "voltage": 3.3},
		},
		{
			name:    "non-numeric field ignored, others kept",
			payload: "status=ok;temperature=20",
			want:    map[string]float64{"temperature": 20},
		},
		{
			name:    "empty payload",
			payload: "",
			want:    map[string]float64{},
		},
		{
			name:    "garbage payload",
			payload: "this is not key=value at all except maybe;a=b;",
			want:    map[string]float64{},
		},
		{
			name:    "extra whitespace and empty fields tolerated",
			payload: " temperature = 21.0 ; ; humidity=50;",
			want:    map[string]float64{"temperature": 21.0, "humidity": 50},
		},
		{
			name:    "field without equals sign ignored",
			payload: "noequalshere;temperature=22",
			want:    map[string]float64{"temperature": 22},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseKV(tc.payload)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseKV(%q) = %v, want %v", tc.payload, got, tc.want)
			}
			for k, v := range tc.want {
				gv, ok := got[k]
				if !ok {
					t.Fatalf("ParseKV(%q): missing key %q in result %v", tc.payload, k, got)
				}
				if gv != v {
					t.Fatalf("ParseKV(%q): key %q = %v, want %v", tc.payload, k, gv, v)
				}
			}
		})
	}
}
