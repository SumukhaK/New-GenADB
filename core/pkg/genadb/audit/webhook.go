package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// WebhookSink POSTs each event as JSON to a URL, signed with HMAC-SHA256.
//
// Headers:
//
//	X-GenADB-Timestamp: unix seconds
//	X-GenADB-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
//
// Delivery is asynchronous with a bounded queue and retries with backoff, so
// a slow or unreachable collector never stalls a debugging session. Events
// that cannot be queued are counted in Dropped. Keep a FileSink alongside it
// for a complete local record.
type WebhookSink struct {
	URL    string
	secret []byte
	client *http.Client
	q      chan []byte
	wg     sync.WaitGroup
	mu     sync.Mutex
	drop   int
	fail   int
	closed bool
}

// NewWebhookSink starts a sink. secret must be non-empty.
func NewWebhookSink(url string, secret []byte, client *http.Client) (*WebhookSink, error) {
	if url == "" || len(secret) == 0 {
		return nil, errorf("webhook needs a URL and a signing secret")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	s := &WebhookSink{URL: url, secret: append([]byte(nil), secret...), client: client, q: make(chan []byte, 1024)}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

// Sign returns the signature header value for a body sent at ts.
func Sign(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// VerifySignature checks a webhook delivery; collectors should also reject
// timestamps outside a small window to stop replays.
func VerifySignature(secret []byte, tsHeader, sigHeader string, body []byte) bool {
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(Sign(secret, ts, body)), []byte(sigHeader))
}

func (s *WebhookSink) Write(e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errorf("webhook sink closed")
	}
	select {
	case s.q <- b:
	default:
		s.drop++
	}
	return nil
}

func (s *WebhookSink) loop() {
	defer s.wg.Done()
	for b := range s.q {
		backoff := 500 * time.Millisecond
		for attempt := 0; attempt < 5; attempt++ {
			if s.post(b) {
				break
			}
			if attempt == 4 {
				s.mu.Lock()
				s.fail++
				s.mu.Unlock()
				break
			}
			time.Sleep(backoff)
			backoff *= 2
		}
	}
}

func (s *WebhookSink) post(b []byte) bool {
	ts := time.Now().Unix()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(b))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "genadb-audit/1")
	req.Header.Set("X-GenADB-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-GenADB-Signature", Sign(s.secret, ts, b))
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// Stats reports events dropped because the queue was full and events given
// up after retries.
func (s *WebhookSink) Stats() (dropped, failed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drop, s.fail
}

// Close stops accepting events and waits for queued deliveries to finish.
func (s *WebhookSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.q)
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}
