package engine

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sumukhak/new-genadb/core/pkg/genadb/audit"
)

// WebhookSecretEnv names the environment variable holding the webhook HMAC
// secret, so it never appears in a process listing.
const WebhookSecretEnv = "GENADB_AUDIT_WEBHOOK_SECRET"

type webhookFlags struct{ url, secretFile string }

// auditOff are the --audit values that ask for no log.
func auditOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "none", "false", "no", "-":
		return true
	}
	return false
}

// resolveAuditPath applies the corporate rule (issue #7): corporate agents
// always keep a hash-chained log, at def unless --audit names another file,
// and refuse an explicit opt-out. Solo agents log only when asked.
func resolveAuditPath(flagValue string, corporate bool, def string) (string, error) {
	switch {
	case auditOff(flagValue) && corporate:
		return "", fmt.Errorf("corporate mode always keeps an audit log; --audit=%s is not allowed (pass a path to choose where it goes)", flagValue)
	case auditOff(flagValue):
		return "", nil
	case flagValue == "" && corporate:
		return def, nil
	}
	return flagValue, nil
}

func addWebhookFlags(fs *flag.FlagSet) *webhookFlags {
	w := &webhookFlags{}
	fs.StringVar(&w.url, "audit-webhook-url", "", "also POST every audit record (HMAC-SHA256 signed) to this URL")
	fs.StringVar(&w.secretFile, "audit-webhook-secret-file", "", "file holding the webhook HMAC secret (default: $"+WebhookSecretEnv+")")
	return w
}

func (w *webhookFlags) sink() (audit.Sink, error) {
	if w.url == "" {
		return nil, nil
	}
	secret := os.Getenv(WebhookSecretEnv)
	if w.secretFile != "" {
		b, err := os.ReadFile(w.secretFile)
		if err != nil {
			return nil, err
		}
		secret = strings.TrimSpace(string(b))
	}
	if secret == "" {
		return nil, fmt.Errorf("--audit-webhook-url needs a secret: set $%s or --audit-webhook-secret-file", WebhookSecretEnv)
	}
	return audit.NewWebhookSink(w.url, []byte(secret), nil)
}

// combineAudit builds the sink for a file path and/or webhook: the file seals
// records and tees them to the webhook; without a file the webhook gets its
// own in-memory chain.
func combineAudit(path, keyFile string, hook audit.Sink) (audit.Sink, error) {
	if path == "" {
		if hook == nil {
			return nil, nil
		}
		return audit.Chained(hook), nil
	}
	f, err := audit.OpenFileWith(path, audit.FileOptions{AnchorKeyFile: keyFile})
	if err != nil {
		return nil, err
	}
	if hook != nil {
		f.Tee(hook)
	}
	return f, nil
}
