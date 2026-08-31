package record

import "testing"

/* Len counts every event added and a fresh session starts empty (so a flush that swaps in a new session resets the count that drives the event-based flush). */
func TestSessionLenCountsAndResets(t *testing.T) {
	s := NewSession(1, "t")
	if s.Len() != 0 {
		t.Fatalf("new session should start empty, got %d", s.Len())
	}
	s.Add(Event{Type: "open", Path: "/a", Call: 1})
	s.Add(Event{Type: "open", Path: "/b", Call: 1})
	s.Add(Event{Type: "open", Path: "/c", Call: 2})
	if s.Len() != 3 {
		t.Fatalf("Len should be 3 after three Adds, got %d", s.Len())
	}
	if fresh := NewSession(2, "t").Len(); fresh != 0 {
		t.Fatalf("fresh session should be empty, got %d", fresh)
	}
}
