/* Command agentrec records an AI agent's process tree at the syscall level, attributed to the tool call that caused it. */
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"agentrec/internal/probe"
	"agentrec/internal/record"
	"agentrec/internal/report"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const defaultSock = "/run/agentrec.sock"

/* Compile-time check that the record decoder matches the probe's struct layout. */
var _ = [1]struct{}{}[probe.EventSize-record.RawEventSize]

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "trace":
		err = cmdTrace(os.Args[2:])
	case "mark":
		err = cmdMark(os.Args[2:])
	case "info":
		err = cmdInfo()
	case "push":
		err = cmdPush(os.Args[2:])
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "__stub":
		err = cmdStub(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentrec: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `agentrec - syscall-level flight recorder for AI agents

  agentrec trace [flags] -- <command>    record a command and everything it spawns
  agentrec mark <label>                  open a new tool call in the active recording
  agentrec push [flags] <rec.json>       upload a recording to the control plane (- for stdin)
  agentrec watch [flags]                 node-wide: auto-record processes matching --match
  agentrec info                          show kernel / BTF diagnostics

trace flags:
  --session NAME     name for this recording (default "session")
  --sock PATH        control socket path (default `+defaultSock+`)
  --out FILE         write the structured recording as JSON
  --jsonl FILE       write one JSON object per kernel event
  --all              show linker/libc noise that is filtered by default
  --no-resolve       skip reverse DNS on network destinations
  --no-color         plain output
  --endpoint URL     control-plane ingest base URL (or AGENTREC_ENDPOINT); enables auto-upload
  --token TOKEN      ingest token ar_ing_… (or AGENTREC_TOKEN)
  --no-upload        record locally but skip upload even if an endpoint is set
  --enforce          deny the workspace's block rules in-kernel via BPF-LSM (clean -EPERM)

push flags:
  --endpoint URL     ingest base URL (or AGENTREC_ENDPOINT)
  --token TOKEN      ingest token (or AGENTREC_TOKEN)
`)
}

/* pollBlockRules refreshes the in-kernel block rules every 30s; a fetch error keeps the last-known rules in force. */
func pollBlockRules(p *probe.Probe, endpoint, token, cur string, stop <-chan struct{}) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			ver, rules, err := fetchBlockRules(endpoint, token)
			if err != nil || ver == cur {
				continue
			}
			n, err := p.SetBlockRules(rules)
			if err != nil {
				fmt.Fprintf(os.Stderr, "agentrec: applying block rules: %v\n", err)
				continue
			}
			cur = ver
			fmt.Fprintf(os.Stderr, "agentrec: policy: reloaded %d custom block rule(s)\n", n)
		}
	}
}

/* ---------- trace ---------- */

type tracer struct {
	probe     *probe.Probe
	session   *record.Session
	sessionID uint64
	rootPid   atomic.Uint32
	seq       atomic.Uint64

	/* selfTesting diverts the event stream during the pipeline self-test. */
	selfTesting  atomic.Bool
	selfTestPath string
	selfTestHit  chan struct{}
}

func cmdTrace(argv []string) error {
	cmdArgs, flagArgs := splitDoubleDash(argv)
	if len(cmdArgs) == 0 {
		return errors.New("no command given; use: agentrec trace [flags] -- <command>")
	}

	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	name := fs.String("session", "session", "name for this recording")
	sock := fs.String("sock", defaultSock, "control socket path")
	out := fs.String("out", "", "write structured recording as JSON")
	jsonl := fs.String("jsonl", "", "write one JSON object per event")
	all := fs.Bool("all", false, "include linker/libc noise")
	noResolve := fs.Bool("no-resolve", false, "skip reverse DNS")
	noColor := fs.Bool("no-color", false, "plain output")
	endpoint := fs.String("endpoint", "", "ingest endpoint base URL (or AGENTREC_ENDPOINT); enables auto-upload")
	token := fs.String("token", "", "ingest token ar_ing_… (or AGENTREC_TOKEN)")
	noUpload := fs.Bool("no-upload", false, "record locally but do not upload even if an endpoint is set")
	enforce := fs.Bool("enforce", false, "deny the workspace's block rules in-kernel via BPF-LSM (clean -EPERM); requires a BPF-LSM host")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	sessionID := uint64(time.Now().UnixNano())

	p, err := probe.Load()
	if err != nil {
		return err
	}
	defer p.Close()

	/* Meter node-hours for billing while recording. */
	hbStop := make(chan struct{})
	defer close(hbStop)
	if !*noUpload {
		startHeartbeat(*endpoint, *token, hbStop)
	}

	enfMode := "off"
	if *enforce {
		m, err := p.SetEnforce(true)
		if err != nil {
			return fmt.Errorf("enabling enforcement: %w", err)
		}
		enfMode = m
		if m == "unavailable" {
			fmt.Fprintln(os.Stderr, "agentrec: --enforce requested, but this host has no BPF LSM in its active list; in-kernel enforcement is unavailable — recording only")
		}
	}

	t := &tracer{
		probe:     p,
		session:   record.NewSession(sessionID, *name),
		sessionID: sessionID,
	}

	ln, err := listenControl(*sock)
	if err != nil {
		return err
	}
	defer func() {
		ln.Close()
		os.Remove(*sock)
	}()
	go t.serveControl(ln)

	/* Ring buffer consumer; runs until Close() unblocks it. */
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		dec := record.NewDecoder()
		var rec ringbuf.Record
		for {
			err := p.Reader.ReadInto(&rec)
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
				fmt.Fprintf(os.Stderr, "agentrec: ring buffer: %v\n", err)
				return
			}
			e, err := dec.Decode(rec.RawSample)
			if err != nil {
				fmt.Fprintf(os.Stderr, "agentrec: decode: %v\n", err)
				continue
			}
			if t.selfTesting.Load() {
				if e.Type == "open" && e.Path == t.selfTestPath {
					select {
					case t.selfTestHit <- struct{}{}:
					default:
					}
				}
				continue /* self-test traffic is not recorded */
			}
			t.session.Add(e)
		}
	}()

	if err := t.selfTest(); err != nil {
		return err
	}

	/* Load the workspace's block rules into the kernel and keep them fresh; BPF-LSM only, best-effort. */
	pollStop := make(chan struct{})
	defer close(pollStop)
	if *enforce && enfMode == "lsm" {
		ep, tok := resolveTarget(*endpoint, *token)
		if ep == "" || tok == "" {
			fmt.Fprintln(os.Stderr, "agentrec: warning: --enforce with no control-plane endpoint/token — no block rules loaded, nothing will be denied (pass --endpoint/--token or set AGENTREC_ENDPOINT/AGENTREC_TOKEN)")
		} else {
			ver, rules, ferr := fetchBlockRules(ep, tok)
			if ferr != nil {
				fmt.Fprintf(os.Stderr, "agentrec: could not load block rules: %v\n", ferr)
			} else if n, aerr := p.SetBlockRules(rules); aerr != nil {
				fmt.Fprintf(os.Stderr, "agentrec: applying block rules: %v\n", aerr)
			} else if n > 0 {
				fmt.Fprintf(os.Stderr, "agentrec: policy: %d block rule(s) enforced in-kernel\n", n)
			} else {
				fmt.Fprintln(os.Stderr, "agentrec: policy: no block rules for this workspace — nothing will be denied")
			}
			go pollBlockRules(p, ep, tok, ver, pollStop)
		}
	}

	mode := "observe"
	if *enforce {
		if enfMode == "lsm" {
			mode = "ENFORCE via BPF-LSM (block rules denied with -EPERM)"
		} else {
			mode = "observe (enforcement unavailable: no BPF-LSM on this host)"
		}
	}
	fmt.Fprintf(os.Stderr, "agentrec: probes attached on %s; mode=%s; recording %v\n",
		probe.KernelHint(), mode, cmdArgs)

	code, err := t.runTarget(cmdArgs, *sock)
	if err != nil {
		return err
	}

	/* Let the process tree exit and the reader drain. */
	time.Sleep(400 * time.Millisecond)
	p.Reader.Close()
	<-readerDone

	t.session.RootPid = t.rootPid.Load()

	report.Render(os.Stdout, t.session, report.Options{
		All:     *all,
		Resolve: !*noResolve,
		Color:   !*noColor,
		Enforce: enfMode,
	})

	emitted, dropped := p.Stats()
	fmt.Fprintf(os.Stderr, "agentrec: %d events emitted by the kernel, %d dropped, exit code %d\n",
		emitted, dropped, code)

	if *out != "" {
		if err := writeJSON(*out, t.session); err != nil {
			return err
		}
	}
	if *jsonl != "" {
		if err := writeJSONL(*jsonl, t.session); err != nil {
			return err
		}
	}

	/* Auto-upload, best-effort: upload errors are logged, not returned. */
	if ep, tok := resolveTarget(*endpoint, *token); ep != "" && tok != "" && !*noUpload {
		body, mErr := json.Marshal(sessionDoc(t.session))
		if mErr != nil {
			fmt.Fprintf(os.Stderr, "agentrec: marshal for upload failed: %v\n", mErr)
		} else if uErr := uploadRecording(ep, tok, body); uErr != nil {
			fmt.Fprintf(os.Stderr, "agentrec: upload failed (recording kept locally): %v\n", uErr)
		}
	}

	if code != 0 {
		os.Exit(code)
	}
	return nil
}

/* selfTest tags our own pid and requires the syscall back through the ring buffer, catching a pid-namespace mismatch that would otherwise silently record nothing. */
func (t *tracer) selfTest() error {
	self := uint32(os.Getpid())
	t.selfTestPath = fmt.Sprintf("/agentrec-selftest-%d", self)
	t.selfTestHit = make(chan struct{}, 1)
	t.selfTesting.Store(true)
	defer t.selfTesting.Store(false)

	if err := t.probe.Tag(self, probe.Tag{SessionID: t.sessionID, CallSeq: 0}); err != nil {
		return fmt.Errorf("self-test: tagging own pid: %w", err)
	}
	defer t.probe.Untag(self)

	/* Expected to fail with ENOENT; the tracepoint fires on entry regardless. */
	f, err := os.Open(t.selfTestPath)
	if err == nil {
		f.Close()
	}

	select {
	case <-t.selfTestHit:
		return nil
	case <-time.After(2 * time.Second):
		return fmt.Errorf(`self-test failed: probes are attached but no events are reaching userspace.

The usual cause is a pid namespace mismatch: the kernel reports init-namespace pids while
this process sees container pids, so attribution can never match. Run the collector in the
host pid namespace:

    docker run --privileged --pid=host ...

(in Kubernetes: hostPID: true, which is how node-level eBPF agents normally deploy)`)
	}
}

/* runTarget launches the command via a stub that blocks until tagged, so the tag lands before the target's execve. */
func (t *tracer) runTarget(cmdArgs []string, sock string) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}

	gateR, gateW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer gateW.Close()

	cmd := exec.Command(self, append([]string{"__stub", "--"}, cmdArgs...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{gateR}
	cmd.Env = append(os.Environ(), "AGENTREC_SOCK="+sock, "AGENTREC_SESSION="+t.session.Name)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		gateR.Close()
		return 0, fmt.Errorf("starting target: %w", err)
	}
	gateR.Close()

	pid := uint32(cmd.Process.Pid)
	t.rootPid.Store(pid)
	if err := t.probe.Tag(pid, probe.Tag{SessionID: t.sessionID, CallSeq: 0}); err != nil {
		return 0, fmt.Errorf("tagging root pid %d: %w", pid, err)
	}

	/* Tag is live; release the stub. */
	if _, err := gateW.Write([]byte{1}); err != nil {
		return 0, fmt.Errorf("releasing stub: %w", err)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigc)
	go func() {
		if _, ok := <-sigc; ok {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		}
	}()

	err = cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

/* ---------- control socket ---------- */

type markRequest struct {
	Cmd   string `json:"cmd"`
	Label string `json:"label"`
}

type markResponse struct {
	Seq      uint64   `json:"seq"`
	Retagged []uint32 `json:"retagged"`
	Error    string   `json:"error,omitempty"`
}

func listenControl(path string) (*net.UnixListener, error) {
	os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("control socket %s: %w", path, err)
	}
	/* World-writable so the agent can mark regardless of its user. */
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (t *tracer) serveControl(ln *net.UnixListener) {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		go t.handleControl(conn)
	}
}

func (t *tracer) handleControl(conn *net.UnixConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	var req markRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(markResponse{Error: "bad request: " + err.Error()})
		return
	}
	if req.Cmd != "mark" {
		json.NewEncoder(conn).Encode(markResponse{Error: "unknown cmd " + req.Cmd})
		return
	}

	seq := t.seq.Add(1)
	peer, _ := peerPID(conn)
	retagged := t.advance(peer, seq)

	t.session.Mark(seq, req.Label, t.session.Duration())
	json.NewEncoder(conn).Encode(markResponse{Seq: seq, Retagged: retagged})
}

/* advance retags the caller's tagged ancestors (and always the root) onto the new tool call so later forks inherit it. */
func (t *tracer) advance(peer uint32, seq uint64) []uint32 {
	tag := probe.Tag{SessionID: t.sessionID, CallSeq: seq}
	var updated []uint32

	if peer != 0 {
		pid := ppidOf(peer)
		for i := 0; i < 16 && pid > 1; i++ {
			if _, ok := t.probe.LookupTag(pid); ok {
				if err := t.probe.Tag(pid, tag); err == nil {
					updated = append(updated, pid)
				}
			}
			pid = ppidOf(pid)
		}
	}

	if root := t.rootPid.Load(); root != 0 {
		if err := t.probe.Tag(root, tag); err == nil {
			if !contains(updated, root) {
				updated = append(updated, root)
			}
		}
	}
	return updated
}

func peerPID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		pid   uint32
		inner error
	)
	err = raw.Control(func(fd uintptr) {
		ucred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			inner = e
			return
		}
		pid = uint32(ucred.Pid)
	})
	if err != nil {
		return 0, err
	}
	return pid, inner
}

/* ppidOf reads the parent pid from /proc/<pid>/stat, parsing after the final ')' to skip the comm field. */
func ppidOf(pid uint32) uint32 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func contains(xs []uint32, x uint32) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

/* ---------- mark ---------- */

func cmdMark(argv []string) error {
	if len(argv) == 0 {
		return errors.New("usage: agentrec mark <label>")
	}
	label := strings.Join(argv, " ")

	path := os.Getenv("AGENTREC_SOCK")
	if path == "" {
		path = defaultSock
	}

	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		/* Marking is advisory; don't fail when nothing is recording. */
		fmt.Fprintf(os.Stderr, "agentrec: no recorder at %s (%v); mark ignored\n", path, err)
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if err := json.NewEncoder(conn).Encode(markRequest{Cmd: "mark", Label: label}); err != nil {
		return err
	}
	var resp markResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	fmt.Fprintf(os.Stderr, "agentrec: call %d -> %q (retagged pids %v)\n", resp.Seq, label, resp.Retagged)
	return nil
}

/* ---------- stub ---------- */

/* cmdStub is the pre-exec gate: it blocks on fd 3 for one byte, then execs the target while already tagged. */
func cmdStub(argv []string) error {
	cmdArgs, _ := splitDoubleDash(argv)
	if len(cmdArgs) == 0 {
		return errors.New("__stub: no command")
	}

	gate := os.NewFile(3, "agentrec-gate")
	if gate != nil {
		buf := make([]byte, 1)
		gate.Read(buf) /* a closed pipe is fine; proceed either way */
		gate.Close()
	}

	bin, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return fmt.Errorf("__stub: %w", err)
	}
	return syscall.Exec(bin, cmdArgs, os.Environ())
}

/* ---------- info ---------- */

func cmdInfo() error {
	fmt.Printf("kernel:   %s\n", probe.KernelHint())
	if err := probe.EnsureTracefs(); err != nil {
		fmt.Printf("tracefs:  %v\n", err)
	}
	for _, p := range []string{
		"/sys/kernel/btf/vmlinux",
		"/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat",
		"/sys/kernel/tracing/events/syscalls/sys_enter_openat",
	} {
		status := "missing"
		if _, err := os.Stat(p); err == nil {
			status = "present"
		}
		fmt.Printf("%-8s %s\n", status+":", p)
	}
	return nil
}

/* ---------- helpers ---------- */

/* splitDoubleDash returns (args after "--", args before it). */
func splitDoubleDash(argv []string) (after, before []string) {
	for i, a := range argv {
		if a == "--" {
			return argv[i+1:], argv[:i]
		}
	}
	return nil, argv
}

func writeJSON(path string, s *record.Session) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	doc := sessionDoc(s)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func writeJSONL(path string, s *record.Session) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range s.Events() {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
