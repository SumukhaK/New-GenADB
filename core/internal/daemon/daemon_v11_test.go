package daemon

import (
	"testing"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

func errKind(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	d, _ := e["data"].(map[string]any)
	k, _ := d["kind"].(string)
	return k
}

func TestDaemonPairADBValidation(t *testing.T) {
	_, r := setup(t, "", genadb.WithRelayURL("127.0.0.1:1"))
	if errCode(r.call("session.pair_adb", map[string]any{"device_id": "d"})) != CodeInvalidParams {
		t.Fatal("missing pairing_code accepted")
	}
	if m := r.call("session.pair_adb", map[string]any{"device_id": "d", "pairing_port": 37000, "pairing_code": "12345"}); errCode(m) != CodeBadCode || errKind(m) != "bad_code" {
		t.Fatalf("short code: %v", m)
	}
	if m := r.call("session.pair_adb", map[string]any{"device_id": "d", "pairing_port": 37000, "pairing_code": "123456"}); errCode(m) != CodeNotPaired {
		t.Fatalf("unpaired device: %v", m)
	}
	if errCode(r.call("session.pair_adb", map[string]any{"device_id": "d", "pairing_code": "123456", "nope": true})) != CodeInvalidParams {
		t.Fatal("unknown params accepted")
	}
}

func TestDaemonSetTokenNeedsAuthAndCorporateMode(t *testing.T) {
	_, r := setup(t, "tok")
	if errCode(r.call("auth.set_token", map[string]any{"token": "a.b.c"})) != CodeUnauthorized {
		t.Fatal("auth.set_token before auth")
	}
	r.call("auth", map[string]any{"token": "tok"})
	if errCode(r.call("auth.set_token", map[string]any{})) != CodeInvalidParams {
		t.Fatal("empty token accepted")
	}
	if m := r.call("auth.set_token", map[string]any{"token": "a.b.c"}); errCode(m) != CodeDenied {
		t.Fatalf("solo daemon accepted a token: %v", m)
	}
}
