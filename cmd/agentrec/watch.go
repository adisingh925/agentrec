package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"agentrec/internal/probe"
	"agentrec/internal/record"
	"agentrec/internal/report"

	"github.com/cilium/ebpf/ringbuf"
)

/* cmdWatch runs node-wide (DaemonSet mode): tags pids whose binary matches --match and flushes captured activity on an interval. */
func cmdWatch(argv []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	match := fs.String("match", "", "comma-separated process-name substrings to auto-record (e.g. node,python,claude)")
	endpoint := fs.String("endpoint", "", "ingest endpoint (or AGENTREC_ENDPOINT)")
	token := fs.String("token", "", "ingest token (or AGENTREC_TOKEN)")
	flush := fs.Duration("flush", 30*time.Second, "how often to upload the accumulated node session")
	name := fs.String("session", "node-watch", "session name")
	noResolve := fs.Bool("no-resolve", false, "skip reverse DNS")
	noColor := fs.Bool("no-color", false, "plain output when printing locally")
	foreground := fs.Bool("foreground", false, "run the watch loop in this terminal instead of installing a systemd service")
	maxEvents := fs.Int("max-events", 100000, "flush early when the in-memory session reaches this many events, bounding memory between flushes (0 = time-based flush only)")
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

	/* Run by hand as root on a systemd host: install a service instead of blocking. INVOCATION_ID means systemd already runs us. */
	if !*foreground && os.Getenv("INVOCATION_ID") == "" && os.Geteuid() == 0 {
		if _, err := exec.LookPath("systemctl"); err == nil {
			return installWatchService(patterns, *flush, *name, ep, tok, *maxEvents)
		}
	}

	/* Meter node-hours for billing while this node is being watched. */
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
	tagged := tagSet{} /* adopted pids; pruned on exit so the set stays bounded */

	/* Uploads run off the reader's hot path: a dedicated goroutine marshals + uploads each flushed
	   session, then returns its pages to the OS. A small bounded queue backpressures if uploads fall
	   behind (the enqueue blocks, the ring buffer absorbs, and only then are events dropped). */
	uploadCh := make(chan *record.Session, 1)
	var uploadWG sync.WaitGroup
	uploadWG.Add(1)
	go func() {
		defer uploadWG.Done()
		for s := range uploadCh {
			if ep != "" && tok != "" {
				if body, err := json.Marshal(sessionDoc(s)); err == nil {
					if uErr := uploadRecording(ep, tok, body); uErr != nil {
						fmt.Fprintf(os.Stderr, "agentrec: flush upload failed: %v\n", uErr)
					}
				}
			} else {
				report.Render(os.Stdout, s, report.Options{Resolve: !*noResolve, Color: !*noColor})
			}
			s = nil              /* release the flushed session... */
			debug.FreeOSMemory() /* ...so its pages return to the OS, not just the Go heap */
		}
	}()

	/* flush swaps in a fresh session and hands the old one to the uploader. The swap is instant (a
	   pointer under lock), so the live session stays bounded to ~max-events even when the reader
	   saturates the CPU -- no waiting on another goroutine to be scheduled before the session grows. */
	doFlush := func() {
		mu.Lock()
		if cur.Len() == 0 {
			mu.Unlock()
			return
		}
		old := cur
		cur = record.NewSession(uint64(time.Now().UnixNano()), *name)
		mu.Unlock()
		uploadCh <- old /* blocks only when the upload queue is full (backpressure) */
	}

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
			/* Maintain the adopted-pid set and decide what to do with this event. */
			d := tagged.decide(e, patterns)
			if d.skip {
				continue /* an untagged exec matching no pattern: discovery noise, not recorded */
			}
			if d.tag {
				_ = p.Tag(e.Pid, probe.Tag{SessionID: sessionID, CallSeq: uint64(e.Pid)})
			}
			mu.Lock()
			cur.Add(e)
			over := *maxEvents > 0 && cur.Len() >= *maxEvents
			mu.Unlock()
			if over {
				doFlush() /* swap inline (instant), enqueue for async upload */
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "agentrec: node-wide watch on %s; matching %v; flushing every %s\n",
		probe.KernelHint(), patterns, *flush)

	ticker := time.NewTicker(*flush)
	defer ticker.Stop()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			doFlush()
		case <-sigc:
			fmt.Fprintln(os.Stderr, "agentrec: stopping, final flush…")
			p.Reader.Close()
			<-readerDone
			doFlush()       /* final swap + enqueue */
			close(uploadCh) /* no more sessions; end the uploader's range */
			uploadWG.Wait() /* let queued uploads finish before exit */
			return nil
		}
	}
}

/* tagSet is the watcher's set of adopted pids, kept in sync with the kernel's pid_tags: a pid is added on a matching exec and removed when it exits, so a recycled pid can be re-adopted and the set stays bounded over a long-running watch. */
type tagSet map[uint32]bool

/* watchDecision tells the consumer loop what to do with an event: skip recording it (an untagged exec matching no pattern), and/or issue a kernel Tag for e.Pid. */
type watchDecision struct{ skip, tag bool }

/* decide updates the adopted-pid set for one event and returns the action to take. */
func (t tagSet) decide(e record.Event, patterns []string) watchDecision {
	switch {
	case e.Type == "exit":
		delete(t, e.Pid) /* mirror the kernel's pid_tags cleanup so a recycled pid re-adopts */
		return watchDecision{}
	case e.Type == "exec" && !t[e.Pid]:
		if !matchWatch(e, patterns) {
			return watchDecision{skip: true}
		}
		t[e.Pid] = true
		return watchDecision{tag: true}
	default:
		return watchDecision{}
	}
}

/* matchWatch reports whether an exec's binary name matches any watch pattern. */
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

/* watchSelfTest proves the pipeline before enabling watch, catching a pid-namespace mismatch (needs hostPID) before we silently record nothing. */
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

/* installWatchService writes and enables a systemd unit running "watch --foreground" for capture that survives reboots. */
func installWatchService(patterns []string, flush time.Duration, session, endpoint, token string, maxEvents int) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating agentrec binary: %w", err)
	}
	/* The service does not inherit shell env, so persist the resolved endpoint/token (only when we have values). */
	if endpoint != "" || token != "" {
		if mkErr := os.MkdirAll("/etc/agentrec", 0o755); mkErr == nil {
			env := fmt.Sprintf(`AGENTREC_ENDPOINT=%s
AGENTREC_TOKEN=%s
`, endpoint, token)
			_ = os.WriteFile("/etc/agentrec/agent.env", []byte(env), 0o600)
		}
	}
	execLine := fmt.Sprintf("%s watch --match %s --flush %s --session %s --max-events %d --foreground --no-color",
		self, strings.Join(patterns, ","), flush, session, maxEvents)
	unit := fmt.Sprintf(`[Unit]
Description=agentrec node-wide watch
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=-/etc/agentrec/agent.env
ExecStart=%s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, execLine)
	if wErr := os.WriteFile("/etc/systemd/system/agentrec-watch.service", []byte(unit), 0o644); wErr != nil {
		return fmt.Errorf("writing service unit (run as root): %w", wErr)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "agentrec-watch"}} {
		if out, sErr := exec.Command("systemctl", args...).CombinedOutput(); sErr != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), sErr, strings.TrimSpace(string(out)))
		}
	}
	fmt.Println("agentrec-watch installed and started (match: " + strings.Join(patterns, ",") + ", flush: " + flush.String() + ")")
	if endpoint == "" || token == "" {
		fmt.Println("  note: no endpoint/token set - put them in /etc/agentrec/agent.env or pass --endpoint/--token, or it will not upload")
	}
	fmt.Println("  logs:  journalctl -u agentrec-watch -f")
	fmt.Println("  stop:  systemctl disable --now agentrec-watch")
	fmt.Println("  (add --foreground to record in this terminal instead)")
	return nil
}
