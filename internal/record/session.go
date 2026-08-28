package record

import (
	"sort"
	"sync"
)

// Call is one agent tool call: the declared intent, plus everything the kernel saw while
// it was in flight.
type Call struct {
	Seq    uint64  `json:"seq"`
	Label  string  `json:"label"`
	Start  float64 `json:"t_start"`
	End    float64 `json:"t_end"`
	Events []Event `json:"events"`
}

// Proc is a process observed inside a call.
type Proc struct {
	Pid    uint32
	Ppid   uint32
	Comm   string
	Cmd    string // resolved from the exec event, when there was one
	First  float64
	Events []Event
}

// Session accumulates a whole recording. Safe for concurrent use: the ring buffer reader
// appends while the control socket adds marks.
type Session struct {
	mu        sync.Mutex
	ID        uint64
	Name      string
	RootPid   uint32
	startTsNs uint64

	events []Event
	calls  map[uint64]*Call
	order  []uint64
}

func NewSession(id uint64, name string) *Session {
	s := &Session{ID: id, Name: name, calls: map[uint64]*Call{}}
	s.ensureCall(0, "(session setup)", 0)
	return s
}

// Add records one decoded event, stamping it relative to the first event seen.
func (s *Session) Add(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.startTsNs == 0 {
		s.startTsNs = e.Ts
	}
	if e.Ts >= s.startTsNs {
		e.Rel = float64(e.Ts-s.startTsNs) / 1e9
	}

	s.events = append(s.events, e)
	c := s.ensureCall(e.Call, "", e.Rel)
	c.Events = append(c.Events, e)
	if e.Rel > c.End {
		c.End = e.Rel
	}
}

// Mark opens a new tool call. Called from the control socket when the agent (or a hook)
// declares what it is about to do.
func (s *Session) Mark(seq uint64, label string, at float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.ensureCall(seq, label, at)
	c.Label = label
}

func (s *Session) ensureCall(seq uint64, label string, at float64) *Call {
	if c, ok := s.calls[seq]; ok {
		return c
	}
	c := &Call{Seq: seq, Label: label, Start: at, End: at}
	s.calls[seq] = c
	s.order = append(s.order, seq)
	return c
}

func (s *Session) Calls() []*Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	// order is appended unsorted on the hot path; sort once here at read time.
	sort.Slice(s.order, func(i, j int) bool { return s.order[i] < s.order[j] })
	out := make([]*Call, 0, len(s.order))
	for _, seq := range s.order {
		out = append(out, s.calls[seq])
	}
	return out
}

func (s *Session) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

func (s *Session) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Duration is the span from the first to the last observed event.
func (s *Session) Duration() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return 0
	}
	return s.events[len(s.events)-1].Rel
}

// Procs groups a call's events into the processes that produced them, preserving the order
// in which the processes first appeared. Attribution to a process uses tid, so a threaded
// runtime's worker threads roll up under the thread that did the work.
func (c *Call) Procs() []*Proc {
	byPid := map[uint32]*Proc{}
	var order []uint32

	// Keyed by tgid, not tid: a resolver thread inside curl is part of curl, not a
	// separate process. Thread-creation forks still arrive keyed by the new tid and
	// produce an entry with no events, which the renderer drops.
	get := func(e Event) *Proc {
		p, ok := byPid[e.Pid]
		if !ok {
			p = &Proc{Pid: e.Pid, Ppid: e.Ppid, Comm: e.Comm, First: e.Rel}
			byPid[e.Pid] = p
			order = append(order, e.Pid)
		}
		return p
	}

	for _, e := range c.Events {
		if e.IsRecorderItself() {
			continue // never record the recorder
		}
		p := get(e)
		switch e.Type {
		case "fork":
			if p.Ppid == 0 {
				p.Ppid = e.Ppid
			}
		case "exec":
			// A process can exec more than once (shell -> binary); the last one wins as
			// the label, but every exec stays in the event list.
			p.Cmd = e.CommandLine()
			p.Events = append(p.Events, e)
		case "exit":
			// Nothing to show; the process's presence is already established.
		default:
			p.Events = append(p.Events, e)
		}
		if p.Comm == "" {
			p.Comm = e.Comm
		}
	}

	out := make([]*Proc, 0, len(order))
	for _, pid := range order {
		out = append(out, byPid[pid])
	}
	return out
}
