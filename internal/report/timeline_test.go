package report

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

/* warm resolves each distinct host exactly once and does so concurrently, not one-at-a-time. */
func TestResolverWarmDeduplicatesAndParallel(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	var inflight, maxInflight int32

	r := newResolver(true)
	r.lookupFn = func(host string) string {
		n := atomic.AddInt32(&inflight, 1)
		for { /* record peak concurrency */
			m := atomic.LoadInt32(&maxInflight)
			if n <= m || atomic.CompareAndSwapInt32(&maxInflight, m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond) /* simulate DNS latency */
		mu.Lock()
		calls[host]++
		mu.Unlock()
		atomic.AddInt32(&inflight, -1)
		return "name-" + host
	}

	/* same host on different ports + a repeat -> 3 distinct hosts */
	r.warm([]string{"1.1.1.1:443", "1.1.1.1:80", "8.8.8.8:53", "9.9.9.9:53", "8.8.8.8:443"})

	mu.Lock()
	defer mu.Unlock()
	for _, h := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		if calls[h] != 1 {
			t.Errorf("host %s looked up %d times, want exactly 1", h, calls[h])
		}
	}
	if len(calls) != 3 {
		t.Errorf("resolved %d distinct hosts, want 3", len(calls))
	}
	if maxInflight < 2 {
		t.Errorf("peak concurrent lookups = %d, want >= 2 (warm must be parallel, not serial)", maxInflight)
	}
}

/* After warm, label() is a cache hit and never triggers another lookup. */
func TestResolverLabelUsesWarmCache(t *testing.T) {
	var n int32
	r := newResolver(true)
	r.lookupFn = func(host string) string {
		atomic.AddInt32(&n, 1)
		return "host-" + host
	}
	r.warm([]string{"203.0.113.5:443"})
	if got, want := r.label("203.0.113.5:443"), "203.0.113.5:443 (host-203.0.113.5)"; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
	if n != 1 {
		t.Errorf("lookups = %d, want 1 (label must hit the warm cache)", n)
	}
}

/* Resolution off: warm and label are pure pass-throughs, no lookups. */
func TestResolverOffIsNoop(t *testing.T) {
	r := newResolver(false)
	r.lookupFn = func(host string) string { t.Fatal("must not resolve when off"); return "" }
	r.warm([]string{"1.2.3.4:80"})
	if got := r.label("1.2.3.4:80"); got != "1.2.3.4:80" {
		t.Errorf("label(off) = %q, want pass-through", got)
	}
}
