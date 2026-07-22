package regtool

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func sampleOutput() SerialOutput {
	return BuildSerialOutput(
		"xiao-esp32c6-0001",
		[]byte{0x01, 0x02, 0x03, 0x04},
		[]byte{0x05, 0x06, 0x07, 0x08},
		sha256.Sum256([]byte("firmware-v1")),
	)
}

func TestStringParseRoundTrip(t *testing.T) {
	out := sampleOutput()
	line := out.String()

	parsed, err := Parse(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.DeviceID != out.DeviceID {
		t.Errorf("device id mismatch: got %q want %q", parsed.DeviceID, out.DeviceID)
	}
	if !bytes.Equal(parsed.IdentityPub, out.IdentityPub) {
		t.Errorf("identity pub mismatch")
	}
	if !bytes.Equal(parsed.KEMPub, out.KEMPub) {
		t.Errorf("kem pub mismatch")
	}
	if parsed.FirmwareHash != out.FirmwareHash {
		t.Errorf("firmware hash mismatch")
	}
	if parsed.Checksum != out.Checksum {
		t.Errorf("checksum mismatch")
	}
	if !VerifyChecksum(parsed) {
		t.Error("parsed output should pass checksum verification")
	}
}

func TestVerifyChecksumDetectsTampering(t *testing.T) {
	out := sampleOutput()

	tampered := out
	tampered.DeviceID = "different-device"
	if VerifyChecksum(tampered) {
		t.Error("checksum should not validate after changing DeviceID")
	}

	tampered2 := out
	tampered2.FirmwareHash[0] ^= 0xFF
	if VerifyChecksum(tampered2) {
		t.Error("checksum should not validate after changing FirmwareHash (this is the whole point of including it)")
	}
}

func TestParseRejectsIncompleteLine(t *testing.T) {
	cases := []string{
		"",
		"DeviceID=foo",
		"DeviceID=foo IdentityPub=0102",
		"DeviceID=foo IdentityPub=0102 KEMPub=0304",
		"DeviceID=foo IdentityPub=0102 KEMPub=0304 FirmwareHash=zz Checksum=abcd1234", // невалидный hex
		"DeviceID=foo IdentityPub=0102 KEMPub=0304 FirmwareHash=01 Checksum=abcd1234", // слишком короткий хеш
	}
	for _, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("expected error parsing %q, got nil", c)
		}
	}
}

func TestParseHandlesExtraWhitespace(t *testing.T) {
	out := sampleOutput()
	// Реалистичный шум при копировании из терминала: лишние пробелы по краям.
	line := "  " + out.String() + "  \n"
	parsed, err := Parse(line)
	if err != nil {
		t.Fatalf("parse with surrounding whitespace: %v", err)
	}
	if parsed.DeviceID != out.DeviceID {
		t.Errorf("device id mismatch after whitespace-tolerant parse: got %q", parsed.DeviceID)
	}
}
