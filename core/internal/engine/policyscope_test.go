package engine

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const orgPolicy = `{"relay_id":"r1","issuer":"https://idp","idp_ed25519_public_key":"AAAA",
 "max_session_seconds":900,"x_custom":{"k":1},
 "grants":[{"user":"alice","devices":["dev-A","dev-B"]},{"user":"bob","devices":["dev-B"]},
           {"user":"carol","devices":["dev-A"]},{"user":"alice","devices":["dev-A"]}]}`

func TestScopePolicyKeepsOnlyThisDevicesGrants(t *testing.T) {
	out, err := ScopePolicy([]byte(orgPolicy), "dev-A")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "dev-B") || strings.Contains(string(out), "bob") {
		t.Fatalf("scoped policy leaks other devices or users:\n%s", out)
	}
	var m map[string]any
	json.Unmarshal(out, &m)
	want := []any{map[string]any{"user": "alice", "devices": []any{"dev-A"}}, map[string]any{"user": "carol", "devices": []any{"dev-A"}}}
	if !reflect.DeepEqual(m["grants"], want) {
		t.Fatalf("grants %v", m["grants"])
	}
	for _, k := range []string{"relay_id", "issuer", "idp_ed25519_public_key", "max_session_seconds", "x_custom"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("scoping dropped %s", k)
		}
	}
	// It is still a policy the device can load and use.
	none, _ := ScopePolicy([]byte(orgPolicy), "dev-Z")
	json.Unmarshal(none, &m)
	if g, _ := m["grants"].([]any); g == nil || len(g) != 0 {
		t.Fatalf("unknown device must get an empty grant list, got %v", m["grants"])
	}
	if _, err := ScopePolicy([]byte("{nope"), "dev-A"); err == nil {
		t.Fatal("bad JSON accepted")
	}
	if _, err := ScopePolicy([]byte(orgPolicy), ""); err == nil {
		t.Fatal("empty device id accepted")
	}
}

func TestDeviceAgentKeepsOnlyItsOwnGrants(t *testing.T) {
	var p policy
	json.Unmarshal([]byte(orgPolicy), &p)
	p.scopedTo("dev-B")
	if len(p.Grants) != 2 || !p.granted("alice", "dev-B") || !p.granted("bob", "dev-B") || p.granted("alice", "dev-A") || p.granted("carol", "dev-A") {
		t.Fatalf("scoped grants %+v", p.Grants)
	}
}
