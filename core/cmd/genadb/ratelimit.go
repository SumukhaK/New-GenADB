package main

import (
	"sync"
	"time"
)

// Per-client token buckets protecting the relay (and, through it, devices)
// from connection floods, session-open storms and credential guessing.

type rateRule struct {
	perSec float64
	burst  float64
}

var relayRules = map[string]rateRule{
	"accept":    {perSec: 50, burst: 200}, // new TCP / WebSocket connections per IP
	"desktop":   {perSec: 10, burst: 60},  // session opens per IP
	"auth-fail": {perSec: 1.0 / 3, burst: 20},
	"device":    {perSec: 2, burst: 20}, // device registrations per IP
}

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	sweep   time.Time
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*bucket{}, sweep: time.Now()} }

// take consumes one token for (ip, kind); returns false when exhausted.
func (l *limiter) take(ip, kind string, peek bool) bool {
	rule, ok := relayRules[kind]
	if !ok {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.sweep) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.sweep = now
	}
	k := kind + "|" + ip
	b := l.buckets[k]
	if b == nil {
		b = &bucket{tokens: rule.burst, last: now}
		l.buckets[k] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rule.perSec
	if b.tokens > rule.burst {
		b.tokens = rule.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	if !peek {
		b.tokens--
	}
	return true
}
