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
func combineAudit(path string, hook audit.Sink) (audit.Sink, error) {
	if path == "" {
		if hook == nil {
			return nil, nil
		}
		return audit.Chained(hook), nil
	}
	f, err := audit.OpenFile(path, false)
	if err != nil {
		return nil, err
	}
	if hook != nil {
		f.Tee(hook)
	}
	return f, nil
}
