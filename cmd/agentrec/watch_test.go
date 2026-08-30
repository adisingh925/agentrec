package main

import (
	"testing"

	"agentrec/internal/record"
)

func ev(typ string, pid uint32, path string) record.Event {
	return record.Event{Type: typ, Pid: pid, Path: path}
}

/* A matching exec adopts the pid (tag) and records it; a later event from that pid records without re-tagging. */
func TestTagSetAdoptsMatchingExec(t *testing.T) {
	ts := tagSet{}
	if d := ts.decide(ev("exec", 100, "/usr/bin/curl"), []string{"curl"}); !d.tag || d.skip {
		t.Fatalf("matching exec should tag+record, got %+v", d)
	}
	if !ts[100] {
		t.Fatal("pid 100 not adopted")
	}
	if d := ts.decide(ev("open", 100, "/etc/hosts"), []string{"curl"}); d.tag || d.skip {
		t.Fatalf("event from an adopted pid should just record, got %+v", d)
	}
}

/* An untagged exec matching no pattern is skipped (discovery noise) and never adopted. */
func TestTagSetSkipsNonMatchingExec(t *testing.T) {
	ts := tagSet{}
	if d := ts.decide(ev("exec", 200, "/usr/bin/vim"), []string{"curl"}); !d.skip || d.tag {
		t.Fatalf("non-matching untagged exec should skip, got %+v", d)
	}
	if ts[200] {
		t.Fatal("non-matching pid must not be adopted")
	}
}

/* Exit prunes the pid so the set stays bounded (mirrors the kernel's pid_tags cleanup). */
func TestTagSetPrunesOnExit(t *testing.T) {
	ts := tagSet{}
	ts.decide(ev("exec", 300, "/usr/bin/python3"), []string{"python3"})
	if !ts[300] {
		t.Fatal("precondition: pid 300 adopted")
	}
	if d := ts.decide(ev("exit", 300, ""), []string{"python3"}); d.skip || d.tag {
		t.Fatalf("exit should just record, got %+v", d)
	}
	if ts[300] || len(ts) != 0 {
		t.Fatalf("pid must be pruned on exit; set size=%d", len(ts))
	}
}

/*
Regression for the fix: a recycled pid (adopted -> exited -> reused for a new matching exec)

	must be re-adopted. Before the exit-prune, the stale entry blocked re-tagging and the reused
	process went unrecorded.
*/
func TestTagSetReadoptsRecycledPid(t *testing.T) {
	ts := tagSet{}
	ts.decide(ev("exec", 400, "/usr/bin/curl"), []string{"curl", "python3"})
	ts.decide(ev("exit", 400, ""), []string{"curl", "python3"})
	if d := ts.decide(ev("exec", 400, "/usr/bin/python3"), []string{"curl", "python3"}); !d.tag {
		t.Fatal("recycled pid must be re-adopted after exit (stale-entry regression)")
	}
	if !ts[400] {
		t.Fatal("recycled pid not re-adopted")
	}
}
