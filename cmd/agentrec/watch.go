package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"agentrec/internal/probe"
	"agentrec/internal/record"
	"agentrec/internal/report"

	"github.com/cilium/ebpf/ringbuf"
)

// cmdWatch runs node-wide: instead of wrapping a command, the kernel emits every untagged
// exec (when watch is on) as a candidate; here we match the binary name against --match and,
// on a hit, tag the pid so the kernel captures it and all its descendants. Accumulated
// activity is flushed to the control plane on an interval. This is the DaemonSet mode.
func cmdWatch(argv []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	match := fs.String("match", "", "comma-separated process-name substrings to auto-record (e.g. node,python,claude)")
	endpoint := fs.String("endpoint", "", "ingest endpoint (or AGENTREC_ENDPOINT)")
	token := fs.String("token", "", "ingest token (or AGENTREC_TOKEN)")
	flush := fs.Duration("flush", 30*time.Second, "how often to upload the accumulated node session")
	name := fs.String("session", "node-watch", "session name")
	noResolve := fs.Bool("no-resolve", false, "skip reverse DNS")
	noColor := fs.Bool("no-color", false, "plain output when printing locally")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	var patterns []string
	for _, p := range strings.Split(*match, ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return errors.New("--match is required: at least one process-name substring (e.g. --match node,python)")
	}
	ep, tok := resolveTarget(*endpoint, *token)

	// Meter node-hours for billing while this node is being watched.
	hbStop := make(chan struct{})
	defer close(hbStop)
	startHeartbeat(ep, tok, hbStop)

	p, err := probe.Load()
	if err != nil {
		return err
	}
	defer p.Close()

	if err := watchSelfTest(p); err != nil {
		return err
	}

	sessionID := uint64(time.Now().UnixNano())
	if err := p.SetWatch(true, sessionID); err != nil {
		return fmt.Errorf("configuring watch: %w", err)
	}

	var mu sync.Mutex
	cur := record.NewSession(sessionID, *name)
	tagged := make(map[uint32]bool) // pids we've adopted

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		dec := record.NewDecoder()
		var rec ringbuf.Record
		for {
			err := p.Reader.ReadInto(&rec)
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			e, err := dec.Decode(rec.RawSample)
			if err != nil {
				continue
			}
			// exec of an untagged pid is a candidate: match, and adopt on a hit.
			if e.Type == "exec" && !tagged[e.Pid] {
				if !matchWatch(e, patterns) {
					continue // not an agent we care about
				}
				tagged[e.Pid] = true
				_ = p.Tag(e.Pid, probe.Tag{SessionID: sessionID, CallSeq: uint64(e.Pid)})
			}
			mu.Lock()
			cur.Add(e)
			mu.Unlock()
		}
	}()

	fmt.Fprintf(os.Stderr, "agentrec: node-wide watch on %s; matching %v; flushing every %s\n",
		probe.KernelHint(), patterns, *flush)

	flushFn := func() {
		mu.Lock()
		s := cur
		if s.Len() == 0 {
			mu.Unlock()
			return
		}
		cur = record.NewSession(uint64(time.Now().UnixNano()), *name)
		mu.Unlock()
		if ep != "" && tok != "" {
			if body, err := json.Marshal(sessionDoc(s)); err == nil {
				if uErr := uploadRecording(ep, tok, body); uErr != nil {
					fmt.Fprintf(os.Stderr, "agentrec: flush upload failed: %v\n", uErr)
				}
			}
		} else {
			report.Render(os.Stdout, s, report.Options{Resolve: !*noResolve, Color: !*noColor})
		}
	}

	ticker := time.NewTicker(*flush)
	defer ticker.Stop()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			flushFn()
		case <-sigc:
			fmt.Fprintln(os.Stderr, "agentrec: stopping, final flush…")
			p.Reader.Close()
			<-readerDone
			flushFn()
			return nil
		}
	}
}

// matchWatch reports whether an exec event's binary name matches any watch pattern.
func matchWatch(e record.Event, patterns []string) bool {
	base := e.Path
	if base == "" {
		base = e.Comm
	}
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	for _, pat := range patterns {
		if strings.Contains(base, pat) {
			return true
		}
	}
	return false
}

// watchSelfTest proves the pipeline before enabling watch: tag our own pid, make one
// recognisable syscall, and require it back within 2s. Catches the pid-namespace mismatch
// (must run with hostPID) before we silently record nothing.
func watchSelfTest(p *probe.Probe) error {
	self := uint32(os.Getpid())
	sentinel := fmt.Sprintf("/agentrec-watch-selftest-%d", self)
	if err := p.Tag(self, probe.Tag{SessionID: 1, CallSeq: 0}); err != nil {
		return err
	}
	defer p.Untag(self)

	p.Reader.SetDeadline(time.Now().Add(2 * time.Second))
	defer p.Reader.SetDeadline(time.Time{})

	go func() {
		if f, err := os.Open(sentinel); err == nil {
			f.Close()
		}
	}()

	for {
		rec, err := p.Reader.Read()
		if err != nil {
			return errors.New(`watch self-test failed: no events reaching userspace. ` +
				`Run in the host PID namespace (--pid=host / hostPID: true)`)
		}
		e, derr := record.Decode(rec.RawSample)
		if derr == nil && e.Type == "open" && e.Path == sentinel {
			return nil
		}
	}
}
