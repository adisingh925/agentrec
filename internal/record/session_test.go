package record

import "testing"

/* Bytes grows as events are added and a fresh session starts at zero (so a flush that swaps in a new session resets the buffer estimate). */
func TestSessionBytesAccumulatesAndResets(t *testing.T) {
	s := NewSession(1, "t")
	if s.Bytes() != 0 {
		t.Fatalf("new session should start at 0 bytes, got %d", s.Bytes())
	}
	s.Add(Event{Type: "open", Path: "/some/long/path/to/a/file", Comm: "curl", Call: 1})
	one := s.Bytes()
	if one <= 0 {
		t.Fatalf("Bytes did not grow after Add: %d", one)
	}
	s.Add(Event{Type: "open", Path: "/another/path", Comm: "curl", Call: 1})
	if s.Bytes() <= one {
		t.Fatalf("Bytes did not grow on second Add: %d then %d", one, s.Bytes())
	}
	/* a fresh session (what flushFn swaps in) is back to zero */
	if fresh := NewSession(2, "t").Bytes(); fresh != 0 {
		t.Fatalf("fresh session should be 0 bytes, got %d", fresh)
	}
}

/* eventSize scales with the event's variable payload (path + argv), not just a flat constant. */
func TestEventSizeScalesWithPayload(t *testing.T) {
	small := eventSize(Event{Type: "open", Path: "/a"})
	big := eventSize(Event{Type: "open", Path: "/a/very/long/path/that/is/much/larger/than/the/other"})
	if big <= small {
		t.Fatalf("eventSize should grow with payload: small=%d big=%d", small, big)
	}
	withArgv := eventSize(Event{Type: "exec", Path: "/bin/sh", Argv: []string{"-c", "echo hello world"}})
	noArgv := eventSize(Event{Type: "exec", Path: "/bin/sh"})
	if withArgv <= noArgv {
		t.Fatalf("eventSize should count argv: %d vs %d", withArgv, noArgv)
	}
}
