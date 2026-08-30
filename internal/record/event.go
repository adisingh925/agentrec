package record

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/* Event types, mirroring the EVT_* constants in the probe. */
const (
	EvtFork    = 1
	EvtExec    = 2
	EvtExit    = 3
	EvtOpen    = 4
	EvtConnect = 5
	EvtUnlink  = 6
)

/*
 * struct event wire layout (little-endian; mirrors agentrec.bpf.c):
 * 0 ts u64 | 8 session u64 | 16 call u64 | 24 pid | 28 tid | 32 ppid | 36 type | 40 arg_len
 * 44 flags i32 | 48 blocked | 52 _pad | 56 dport | 60 af | 64 daddr[16] | 80 comm[16] | 96 buf[640]
 */

/* RawEventSize is the wire size of `struct event`; cmd/agentrec asserts it against the probe's BTF. */
const RawEventSize = 736

const rawEventSize = RawEventSize

/* rawHeaderSize is offsetof(struct event, buf); metadata-only events reserve just the header. */
const rawHeaderSize = 96

/* Event is the decoded, userspace-friendly form. */
type Event struct {
	Ts      uint64   `json:"ts_ns"`
	Rel     float64  `json:"t"` /* seconds since session start */
	Session uint64   `json:"session_id"`
	Call    uint64   `json:"call_seq"`
	Pid     uint32   `json:"pid"`
	Tid     uint32   `json:"tid"`
	Ppid    uint32   `json:"ppid,omitempty"`
	Type    string   `json:"type"`
	Comm    string   `json:"comm"`
	Path    string   `json:"path,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	Flags   int32    `json:"flags,omitempty"`
	Dest    string   `json:"dest,omitempty"`
	Family  string   `json:"family,omitempty"`
	Write   bool     `json:"write,omitempty"`
	Blocked bool     `json:"blocked,omitempty"`
}

func typeName(t uint32) string {
	switch t {
	case EvtFork:
		return "fork"
	case EvtExec:
		return "exec"
	case EvtExit:
		return "exit"
	case EvtOpen:
		return "open"
	case EvtConnect:
		return "connect"
	case EvtUnlink:
		return "unlink"
	}
	return fmt.Sprintf("type%d", t)
}

/* Decoder holds per-reader decode state (a Comm intern table); not safe for concurrent use. */
type Decoder struct{ commTab map[string]string }

/* NewDecoder returns a Decoder that interns Comm strings so recurring names allocate once. */
func NewDecoder() *Decoder { return &Decoder{commTab: make(map[string]string, 64)} }

/* internComm returns cstr(b), reusing a cached backing string for repeat names (nil table skips interning). */
func (d *Decoder) internComm(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		i = len(b)
	}
	key := b[:i]
	if d.commTab == nil {
		return string(key)
	}
	if s, ok := d.commTab[string(key)]; ok {
		return s
	}
	s := string(key)
	if len(d.commTab) >= 4096 { /* bound growth in the long-lived watch reader */
		d.commTab = make(map[string]string, 64)
	}
	d.commTab[s] = s
	return s
}

/* Decode parses one record with no interning (fresh Comm each call); used by self-test and tests. */
func Decode(rec []byte) (Event, error) { var d Decoder; return d.Decode(rec) }

/* Decode parses one ring buffer record, reading fields at fixed little-endian offsets (see layout above). */
func (d *Decoder) Decode(rec []byte) (Event, error) {
	if len(rec) < rawHeaderSize {
		return Event{}, fmt.Errorf("short record: %d bytes, want >= %d", len(rec), rawHeaderSize)
	}
	le := binary.LittleEndian
	typ := le.Uint32(rec[36:])
	flags := int32(le.Uint32(rec[44:]))

	e := Event{
		Ts:      le.Uint64(rec[0:]),
		Session: le.Uint64(rec[8:]),
		Call:    le.Uint64(rec[16:]),
		Pid:     le.Uint32(rec[24:]),
		Tid:     le.Uint32(rec[28:]),
		Ppid:    le.Uint32(rec[32:]),
		Type:    typeName(typ),
		Comm:    d.internComm(rec[80:96]),
		Flags:   flags,
		Blocked: le.Uint32(rec[48:]) != 0,
	}

	const bufOff = 96
	n := int(le.Uint32(rec[40:])) /* arg_len */
	if n > len(rec)-bufOff {
		n = len(rec) - bufOff
	}
	payload := rec[bufOff : bufOff+n]

	switch typ {
	case EvtExec:
		parts := splitNUL(payload)
		if len(parts) > 0 {
			e.Path = parts[0]
			/* Drop argv[0] when it just repeats the path. */
			rest := parts[1:]
			if len(rest) > 0 && (rest[0] == e.Path || strings.HasSuffix(e.Path, "/"+rest[0])) {
				rest = rest[1:]
			}
			e.Argv = rest
		}
	case EvtOpen, EvtUnlink:
		e.Path = cstr(payload)
		/* O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND */
		e.Write = flags&0x3 != 0 || flags&0o100 != 0 || flags&0o1000 != 0 || flags&0o2000 != 0
	case EvtConnect:
		switch le.Uint32(rec[60:]) { /* af */
		case 1:
			e.Family = "unix"
			e.Dest = cstr(payload)
		case 2:
			e.Family = "ipv4"
			e.Dest = net.JoinHostPort(net.IP(rec[64:68]).String(), strconv.Itoa(int(le.Uint32(rec[56:]))))
		case 10:
			e.Family = "ipv6"
			e.Dest = net.JoinHostPort(net.IP(rec[64:80]).String(), strconv.Itoa(int(le.Uint32(rec[56:]))))
		}
	}
	return e, nil
}

/* CommandLine renders an exec event as a human would type it, collapsing embedded newlines. */
func (e Event) CommandLine() string {
	if e.Type != "exec" {
		return ""
	}
	name := e.Path
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if len(e.Argv) == 0 {
		return name
	}
	return collapse(name + " " + strings.Join(e.Argv, " "))
}

/* IsRecorderItself reports whether the event came from agentrec's own instrumentation. */
func (e Event) IsRecorderItself() bool {
	return strings.HasPrefix(e.Comm, "agentrec") ||
		strings.HasSuffix(e.Path, "/agentrec") ||
		strings.HasSuffix(e.Dest, "/agentrec.sock")
}

var (
	wsRun   = regexp.MustCompile(`\s+`)
	semiRun = regexp.MustCompile(`(;\s*)+`)
)

/* collapse folds a multi-line command onto one line, turning newlines into "; " separators. */
func collapse(s string) string {
	s = strings.ReplaceAll(s, "\n", " ; ")
	s = wsRun.ReplaceAllString(s, " ")
	s = semiRun.ReplaceAllString(s, "; ")
	return strings.TrimSuffix(strings.TrimSpace(s), ";")
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func splitNUL(b []byte) []string {
	var out []string
	for len(b) > 0 {
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			out = append(out, string(b))
			break
		}
		if i > 0 {
			out = append(out, string(b[:i]))
		}
		b = b[i+1:]
	}
	return out
}

func durStr(sec float64) string {
	return time.Duration(sec * float64(time.Second)).Truncate(time.Millisecond).String()
}
