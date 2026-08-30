package probe

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

/* Tag is the kernel-side attribution record: which session and tool call a process belongs to. */
type Tag struct {
	SessionID uint64
	CallSeq   uint64
}

type Probe struct {
	coll   *ebpf.Collection
	links  []link.Link
	Reader *ringbuf.Reader

	pidTags     *ebpf.Map
	arConfig    *ebpf.Map
	nodeSess    *ebpf.Map
	stats       *ebpf.Map
	blockRules  *ebpf.Map
	ruleEvCount *ebpf.Map

	/* lsmAvail is true when the BPF LSM is in the kernel's active list, letting lsm/* programs attach. */
	lsmAvail bool
}

type tracepoint struct {
	group string
	name  string
	prog  string /* program (C function) name within the collection */
	/* optional: skip rather than fail if the kernel lacks this tracepoint. */
	optional bool
}

var tracepoints = []tracepoint{
	{group: "sched", name: "sched_process_fork", prog: "on_fork"},
	{group: "sched", name: "sched_process_exit", prog: "on_exit"},
	{group: "syscalls", name: "sys_enter_execve", prog: "on_execve"},
	{group: "syscalls", name: "sys_enter_execveat", prog: "on_execveat"},
	{group: "syscalls", name: "sys_enter_openat", prog: "on_openat"},
	{group: "syscalls", name: "sys_enter_openat2", prog: "on_openat2", optional: true},
	{group: "syscalls", name: "sys_enter_unlinkat", prog: "on_unlinkat"},
	{group: "syscalls", name: "sys_enter_connect", prog: "on_connect"},
}

var lsmPrograms = []string{"ar_file_open", "ar_socket_connect", "ar_bprm_check", "ar_path_unlink"}

/* bpfLSMActive reports whether "bpf" is in the kernel's active lsm= list (required to attach lsm/* programs). */
func bpfLSMActive() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, s := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if s == "bpf" {
			return true
		}
	}
	return false
}

/* Load verifies, loads and attaches every probe. The returned Probe owns the ring buffer. */
func Load() (*Probe, error) {
	if err := ensureTracefs(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising memlock rlimit: %w", err)
	}

	spec, err := loadAgentrec()
	if err != nil {
		return nil, fmt.Errorf("loading probe spec: %w", err)
	}

	lsmAvail := bpfLSMActive()
	if !lsmAvail {
		/* Drop lsm/* programs when the BPF LSM is absent; they can't attach (or even load) so recording still works everywhere. */
		for _, name := range lsmPrograms {
			delete(spec.Programs, name)
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected the program:\n%+v", ve)
		}
		return nil, fmt.Errorf("loading probe: %w", err)
	}

	p := &Probe{
		coll:        coll,
		lsmAvail:    lsmAvail,
		pidTags:     coll.Maps["pid_tags"],
		arConfig:    coll.Maps["ar_config"],
		nodeSess:    coll.Maps["node_sess"],
		stats:       coll.Maps["stats"],
		blockRules:  coll.Maps["block_rules"],
		ruleEvCount: coll.Maps["rule_ev_count"],
	}

	for _, tp := range tracepoints {
		prog := coll.Programs[tp.prog]
		if prog == nil {
			if tp.optional {
				continue
			}
			p.Close()
			return nil, fmt.Errorf("program %s missing from collection", tp.prog)
		}
		l, err := link.Tracepoint(tp.group, tp.name, prog, nil)
		if err != nil {
			if tp.optional {
				continue
			}
			p.Close()
			return nil, fmt.Errorf("attaching %s:%s: %w", tp.group, tp.name, err)
		}
		p.links = append(p.links, l)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	p.Reader = rd

	/* Loading is done and the runtime path never touches kernel BTF again; free the parsed vmlinux Spec and return the memory to the OS now. */
	btf.FlushKernelSpec()
	debug.FreeOSMemory()
	return p, nil
}

/* LSMAvailable reports whether in-kernel BPF-LSM enforcement can be used on this host. */
func (p *Probe) LSMAvailable() bool { return p.lsmAvail }

/* SetEnforce toggles in-kernel enforcement and reports the mode in effect: "lsm", "unavailable", or "off". */
func (p *Probe) SetEnforce(on bool) (string, error) {
	var v uint32
	if on {
		v = 1
	}
	if err := p.arConfig.Put(uint32(0), v); err != nil {
		return "", err
	}
	if !on {
		_ = p.arConfig.Put(uint32(2), uint32(0))
		return "off", nil
	}
	if p.lsmAvail {
		if err := p.attachLSM(); err != nil {
			return "", fmt.Errorf("attaching BPF-LSM hooks: %w", err)
		}
		if err := p.arConfig.Put(uint32(2), uint32(1)); err != nil {
			return "", err
		}
		return "lsm", nil
	}
	if err := p.arConfig.Put(uint32(2), uint32(0)); err != nil {
		return "", err
	}
	return "unavailable", nil
}

func (p *Probe) attachLSM() error {
	for _, name := range lsmPrograms {
		prog := p.coll.Programs[name]
		if prog == nil {
			return fmt.Errorf("%s not loaded", name)
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		p.links = append(p.links, l)
	}
	return nil
}

/* Dynamic block rules mirror the "block" policy into the block_rules map that LSM hooks consult; in-kernel matching covers file-open and unix-connect paths by suffix/prefix/equals, everything else stays detection-only. */
const (
	MaxBlockRules = 32 /* must equal MAX_RULES in bpf/agentrec.bpf.c */
	MaxBlockPat   = 63 /* must equal MAX_PAT in bpf/agentrec.bpf.c */

	EvOpen    uint8 = 1 /* REV_OPEN */
	EvConnect uint8 = 2 /* REV_CONNECT */
	EvExec    uint8 = 3 /* REV_EXEC */
	EvUnlink  uint8 = 4 /* REV_UNLINK */
	OpSuffix  uint8 = 1 /* ROP_SUFFIX */
	OpPrefix  uint8 = 2 /* ROP_PREFIX */
	OpEquals  uint8 = 3 /* ROP_EQUALS */
)

/* BlockRule is one enforceable policy rule in the form the kernel consumes. */
type BlockRule struct {
	Event   uint8  /* EvOpen | EvConnect */
	Op      uint8  /* OpSuffix | OpPrefix | OpEquals */
	Pattern string /* 1..MaxBlockPat bytes */
}

/* bpfBlockRule mirrors `struct block_rule` in the BPF program byte-for-byte (68 bytes, no padding). */
type bpfBlockRule struct {
	Active uint8
	Event  uint8
	Op     uint8
	Len    uint8
	Pat    [MaxBlockPat + 1]byte
}

/* SetBlockRules replaces the in-kernel dynamic policy with `rules` (capped at MaxBlockRules), skipping malformed ones; returns the number applied. */
func (p *Probe) SetBlockRules(rules []BlockRule) (int, error) {
	if p.blockRules == nil {
		return 0, errors.New("block_rules map not loaded")
	}
	/* Mark every event type hot before the rewrite so no LSM hook reads a 0 count mid-swap; exact counts published after. */
	if p.ruleEvCount != nil {
		for ev := uint32(1); ev <= 4; ev++ {
			_ = p.ruleEvCount.Put(ev, uint32(MaxBlockRules))
		}
	}
	var perEv [5]uint32
	n := 0
	for _, r := range rules {
		if n >= MaxBlockRules {
			break
		}
		if len(r.Pattern) == 0 || len(r.Pattern) > MaxBlockPat {
			continue
		}
		if r.Event != EvOpen && r.Event != EvConnect && r.Event != EvExec && r.Event != EvUnlink {
			continue
		}
		if r.Op != OpSuffix && r.Op != OpPrefix && r.Op != OpEquals {
			continue
		}
		e := bpfBlockRule{Active: 1, Event: r.Event, Op: r.Op, Len: uint8(len(r.Pattern))}
		copy(e.Pat[:], r.Pattern)
		if err := p.blockRules.Put(uint32(n), &e); err != nil {
			return n, fmt.Errorf("writing block rule %d: %w", n, err)
		}
		perEv[r.Event]++
		n++
	}
	/* Publish the active count; the kernel scans only slots [0,count), so stale higher slots need no clearing. */
	if err := p.arConfig.Put(uint32(3), uint32(n)); err != nil {
		return n, fmt.Errorf("publishing rule count: %w", err)
	}
	/* exact per-event counts: types with no rule drop to 0 so their LSM hook fast-skips. */
	if p.ruleEvCount != nil {
		for ev := uint32(1); ev <= 4; ev++ {
			if err := p.ruleEvCount.Put(ev, perEv[ev]); err != nil {
				return n, fmt.Errorf("publishing per-event rule count: %w", err)
			}
		}
	}
	return n, nil
}

/* SetWatch toggles node-wide discovery: the kernel emits every untagged exec, userspace tags pids matching the binary name so descendants are captured. */
func (p *Probe) SetWatch(enabled bool, session uint64) error {
	var w uint32
	if enabled {
		w = 1
	}
	if err := p.arConfig.Put(uint32(1), w); err != nil {
		return err
	}
	return p.nodeSess.Put(uint32(0), session)
}

/* Tag seeds attribution for a pid. Descendants inherit it in-kernel at fork time. */
func (p *Probe) Tag(pid uint32, t Tag) error {
	return p.pidTags.Put(pid, agentrecTag{SessionId: t.SessionID, CallSeq: t.CallSeq})
}

/* Untag removes attribution for a pid. Used to clean up after the self-test. */
func (p *Probe) Untag(pid uint32) error {
	return p.pidTags.Delete(pid)
}

func (p *Probe) LookupTag(pid uint32) (Tag, bool) {
	var v agentrecTag
	if err := p.pidTags.Lookup(pid, &v); err != nil {
		return Tag{}, false
	}
	return Tag{SessionID: v.SessionId, CallSeq: v.CallSeq}, true
}

func (p *Probe) TaggedPIDs() []uint32 {
	var out []uint32
	var key uint32
	var val agentrecTag
	iter := p.pidTags.Iterate()
	for iter.Next(&key, &val) {
		out = append(out, key)
	}
	return out
}

/* Stats reports emitted and dropped event counts, summed across CPUs. */
func (p *Probe) Stats() (emitted, dropped uint64) {
	/* stats is a PERCPU_ARRAY: Lookup fills a per-CPU slice; sum every element for the global total. */
	var perCPU []uint64
	if err := p.stats.Lookup(uint32(0), &perCPU); err == nil {
		for _, c := range perCPU {
			dropped += c
		}
	}
	perCPU = nil
	if err := p.stats.Lookup(uint32(1), &perCPU); err == nil {
		for _, c := range perCPU {
			emitted += c
		}
	}
	return emitted, dropped
}

func (p *Probe) Close() {
	if p.Reader != nil {
		p.Reader.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
}

/* EnsureTracefs mounts debugfs if needed so tracepoints attach inside a container; exported for diagnostics. */
func EnsureTracefs() error { return ensureTracefs() }

func ensureTracefs() error {
	for _, dir := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(dir); err == nil {
			return nil
		}
	}
	if err := unix.Mount("none", "/sys/kernel/debug", "debugfs", 0, ""); err != nil {
		return fmt.Errorf("tracefs unavailable and mounting debugfs failed (%w) - "+
			"run with --privileged, or mount -t debugfs none /sys/kernel/debug on the host", err)
	}
	if _, err := os.Stat("/sys/kernel/debug/tracing/events"); err != nil {
		return errors.New("mounted debugfs but tracing/events is missing; kernel lacks CONFIG_FTRACE")
	}
	return nil
}

/* KernelHint returns a short description of the running kernel, for diagnostics. */
func KernelHint() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	trim := func(b []byte) string { return strings.TrimRight(string(b), "\x00") }
	btf := "no BTF"
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		btf = "BTF"
	}
	return fmt.Sprintf("%s %s (%s)", trim(u.Sysname[:]), trim(u.Release[:]), btf)
}
