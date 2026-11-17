package genadb

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sumukhak/new-genadb/core/internal/engine"
	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// CheckStatus is the outcome of one diagnostic check.
type CheckStatus string

const (
	CheckOK   CheckStatus = "ok"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
	CheckSkip CheckStatus = "skip"
)

// Check is one diagnostic result.
type Check struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Hint   string      `json:"hint,omitempty"`
}

// DoctorReport is the result of Diagnose.
type DoctorReport struct {
	Version  string  `json:"version"`
	Platform string  `json:"platform"`
	OK       bool    `json:"ok"` // no check failed
	Checks   []Check `json:"checks"`
}

// DoctorOptions selects what Diagnose inspects.
type DoctorOptions struct {
	StateDir  string
	Relay     string
	AuditPath string
	Transport TransportProvider // nil = DefaultTransport(TransportOptions{})
	ADBPath   string            // "" = look up "adb" on PATH
	Timeout   time.Duration     // per network check, default 8s
}

// Doctor runs Diagnose with this client's configuration.
func (c *Client) Doctor(ctx context.Context) DoctorReport {
	return Diagnose(ctx, DoctorOptions{StateDir: c.cfg.state, Relay: c.cfg.relay, AuditPath: c.auditPath, Transport: c.cfg.transport})
}

// Diagnose checks the local toolchain, state, network path to the relay and
// audit log integrity. It never sends credentials anywhere.
func Diagnose(ctx context.Context, o DoctorOptions) DoctorReport {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Transport == nil {
		o.Transport = DefaultTransport(TransportOptions{})
	}
	if o.StateDir == "" {
		o.StateDir = defaultState()
	}
	r := DoctorReport{Version: Version, Platform: runtime.GOOS + "/" + runtime.GOARCH, OK: true}
	add := func(c Check) {
		if c.Status == CheckFail {
			r.OK = false
		}
		r.Checks = append(r.Checks, c)
	}
	add(checkADB(ctx, o.ADBPath))
	add(checkState(o.StateDir))
	add(checkPaired(o.StateDir))
	add(checkProxyEnv())
	for _, c := range checkRelay(ctx, o.Relay, o.Transport, o.Timeout) {
		add(c)
	}
	add(checkAudit(o.AuditPath))
	return r
}

func checkADB(ctx context.Context, path string) Check {
	c := Check{Name: "adb"}
	if path == "" {
		p, err := exec.LookPath("adb")
		if err != nil {
			c.Status, c.Detail = CheckWarn, "adb not found on PATH"
			c.Hint = "install Android SDK platform-tools; Android Studio users can ignore this"
			return c
		}
		path = p
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		c.Status, c.Detail = CheckWarn, fmt.Sprintf("%s: %v", path, err)
		return c
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	c.Status, c.Detail = CheckOK, path+": "+first
	return c
}

func checkState(dir string) Check {
	c := Check{Name: "state"}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		c.Status, c.Detail = CheckFail, err.Error()
		return c
	}
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		c.Status, c.Detail = CheckFail, "state directory is not writable: "+err.Error()
		return c
	}
	f.Close()
	os.Remove(f.Name())
	c.Status, c.Detail = CheckOK, dir
	if engine.HasIdentity(dir) {
		c.Detail += " (identity key present)"
	} else {
		c.Detail += " (identity key will be created on first use)"
	}
	if fi, err := os.Stat(filepath.Join(dir, "identity.key")); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		c.Status, c.Hint = CheckWarn, "identity.key is readable by other users; chmod 600 it"
	}
	return c
}

func checkPaired(dir string) Check {
	ids, err := engine.PairedDevices(dir)
	switch {
	case err != nil:
		return Check{Name: "paired_devices", Status: CheckWarn, Detail: err.Error()}
	case len(ids) == 0:
		return Check{Name: "paired_devices", Status: CheckOK, Detail: "none yet",
			Hint: "pair with the code shown in the phone app (solo mode)"}
	}
	return Check{Name: "paired_devices", Status: CheckOK, Detail: fmt.Sprintf("%d: %s", len(ids), strings.Join(ids, ", "))}
}

func checkProxyEnv() Check {
	var set []string
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			v = u.Scheme + "://" + u.Host // never print proxy credentials
		}
		if len(v) > 48 {
			v = v[:45] + "..."
		}
		set = append(set, k+"="+v)
	}
	if len(set) == 0 {
		return Check{Name: "proxy_env", Status: CheckOK, Detail: "no proxy variables set"}
	}
	return Check{Name: "proxy_env", Status: CheckOK, Detail: strings.Join(set, " "),
		Hint: "ws:// and wss:// relays honour these; plain host:port relays do not"}
}

func relayHost(spec string) (string, string) {
	if u, err := url.Parse(spec); err == nil && strings.Contains(spec, "://") {
		port := u.Port()
		if port == "" {
			port = map[string]string{"wss": "443", "ws": "80"}[u.Scheme]
		}
		return u.Hostname(), port
	}
	h, p, err := net.SplitHostPort(spec)
	if err != nil {
		return spec, ""
	}
	return h, p
}

func checkRelay(ctx context.Context, spec string, t TransportProvider, timeout time.Duration) []Check {
	if spec == "" {
		return []Check{{Name: "relay", Status: CheckSkip, Detail: "no relay configured", Hint: "pass --relay or WithRelayURL"}}
	}
	host, _ := relayHost(spec)
	var out []Check
	dctx, cancel := context.WithTimeout(ctx, timeout)
	addrs, err := net.DefaultResolver.LookupHost(dctx, host)
	cancel()
	if err != nil {
		out = append(out, Check{Name: "relay_dns", Status: CheckFail, Detail: err.Error(), Hint: "check the relay host name and DNS"})
		return out
	}
	out = append(out, Check{Name: "relay_dns", Status: CheckOK, Detail: fmt.Sprintf("%s -> %d address(es)", host, len(addrs))})
	type res struct {
		d   time.Duration
		err error
	}
	ch := make(chan res, 1)
	start := time.Now()
	go func() {
		c, err := t.Dial(spec)
		if err == nil {
			c.Close()
		}
		ch <- res{time.Since(start), err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			out = append(out, Check{Name: "relay_reach", Status: CheckFail, Detail: r.err.Error(),
				Hint: "a firewall may block the port; a wss:// relay on 443 passes most corporate networks"})
		} else {
			out = append(out, Check{Name: "relay_reach", Status: CheckOK,
				Detail: fmt.Sprintf("%s via %s in %d ms", spec, t.Label(spec), r.d.Milliseconds())})
		}
	case <-time.After(timeout + 7*time.Second):
		out = append(out, Check{Name: "relay_reach", Status: CheckFail, Detail: "timed out"})
	case <-ctx.Done():
		out = append(out, Check{Name: "relay_reach", Status: CheckSkip, Detail: ctx.Err().Error()})
	}
	return out
}

func checkAudit(path string) Check {
	if path == "" {
		return Check{Name: "audit_log", Status: CheckSkip, Detail: "audit logging off"}
	}
	_, serr := os.Stat(path)
	_, aerr := os.Stat(audit.AnchorPath(path))
	if os.IsNotExist(serr) && os.IsNotExist(aerr) {
		return Check{Name: "audit_log", Status: CheckOK, Detail: path + " (no records yet)"}
	}
	st, err := audit.VerifyFile(path, audit.VerifyOptions{})
	if err != nil {
		return Check{Name: "audit_log", Status: CheckFail, Detail: err.Error()}
	}
	if !st.Valid {
		where := ""
		if st.BrokenAt > 0 {
			where = fmt.Sprintf(" at record %d", st.BrokenAt)
		}
		return Check{Name: "audit_log", Status: CheckFail, Detail: fmt.Sprintf("%s: verification failed%s: %s", path, where, st.Problem),
			Hint: "the log or its anchor was edited, truncated or reordered; preserve both files for investigation"}
	}
	detail := fmt.Sprintf("%s: %d records, chain intact, anchor %s", path, st.Records, st.Anchor)
	if len(st.Warnings) > 0 {
		return Check{Name: "audit_log", Status: CheckWarn, Detail: detail + "; " + strings.Join(st.Warnings, "; ")}
	}
	return Check{Name: "audit_log", Status: CheckOK, Detail: detail}
}
