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

/*
Events() reconstructs every event from the per-call buckets (events are stored once) in

	chronological order, even when events interleave across tool calls.
*/
func TestSessionEventsReconstructsChronologically(t *testing.T) {
	s := NewSession(1, "t")
	s.Add(Event{Type: "open", Path: "/a", Call: 1, Ts: 100})
	s.Add(Event{Type: "open", Path: "/b", Call: 2, Ts: 300})
	s.Add(Event{Type: "open", Path: "/c", Call: 1, Ts: 200})
	evs := s.Events()
	if len(evs) != 3 {
		t.Fatalf("Events len = %d, want 3 (all events reconstructed)", len(evs))
	}
	for i := 1; i < len(evs); i++ {
		if evs[i-1].Ts > evs[i].Ts {
			t.Fatalf("Events not chronological: %v", []uint64{evs[0].Ts, evs[1].Ts, evs[2].Ts})
		}
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if s.Duration() == 0 {
		t.Fatal("Duration should be non-zero after events with distinct timestamps")
	}
}
