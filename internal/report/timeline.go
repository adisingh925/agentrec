package report

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"agentrec/internal/record"
)

type Options struct {
	All     bool /* include linker/libc noise */
	Resolve bool /* reverse-DNS network destinations */
	Color   bool
	Enforce string /* enforcement mode ("lsm" | "off"); sharpens the BLOCKED label */
}

type finding struct {
	sev    int
	what   string
	detail string
	call   string
}

/* Render writes the human-facing recording: a timeline grouped by tool call, then the findings. */
func Render(w io.Writer, s *record.Session, opts Options) {
	c := palette(opts.Color)
	res := newResolver(opts.Resolve)

	calls := s.Calls()

	/* Resolve every network destination concurrently up front so the serial render below never blocks on DNS one address at a time. */
	if opts.Resolve {
		var dests []string
		for _, call := range calls {
			for _, e := range call.Events {
				if e.Type == "connect" && e.Family != "unix" && !e.IsRecorderItself() {
					dests = append(dests, e.Dest)
				}
			}
		}
		res.warm(dests)
	}

	nCalls := 0
	for _, call := range calls {
		if call.Seq > 0 {
			nCalls++
		}
	}

	fmt.Fprintf(w, "\n%sagent recording%s  session=%s  root pid=%d\n",
		c.bold, c.reset, s.Name, s.RootPid)
	fmt.Fprintf(w, "%s%d tool calls, %d kernel events, %s%s\n\n",
		c.dim, nCalls, s.Len(), dur(s.Duration()), c.reset)

	var findings []finding

	for _, call := range calls {
		shown := renderCall(w, call, opts, c, res)
		if !shown {
			continue
		}
		/* The agent surfaces only what enforcement denied in-kernel; detection findings are computed by the control plane. */
		for _, e := range call.Events {
			if e.Blocked {
				findings = append(findings, finding{
					sev:    3,
					what:   "blocked in-kernel",
					detail: describe(e, res),
					call:   callName(call),
				})
			}
		}
	}

	renderFindings(w, findings, c)
	renderEgress(w, calls, res, c)
}

func callName(call *record.Call) string {
	if call.Label != "" {
		return call.Label
	}
	if call.Seq == 0 {
		return "(session setup)"
	}
	return fmt.Sprintf("(unlabelled call %d)", call.Seq)
}

func renderCall(w io.Writer, call *record.Call, opts Options, c colors, res *resolver) bool {
	procs := call.Procs()

	/* Filter before printing, so empty calls stay quiet. */
	type shownProc struct {
		p      *record.Proc
		events []record.Event
	}
	var visible []shownProc
	for _, p := range procs {
		var evs []record.Event
		for _, e := range p.Events {
			if e.Type == "exec" {
				continue /* rendered as the process label */
			}
			if !opts.All && !record.Interesting(e) {
				continue
			}
			evs = append(evs, e)
		}
		if p.Cmd == "" && len(evs) == 0 {
			continue
		}
		visible = append(visible, shownProc{p: p, events: evs})
	}
	if len(visible) == 0 {
		return false
	}

	label := callName(call)
	if call.Seq == 0 {
		fmt.Fprintf(w, "%s%s%s\n", c.dim, label, c.reset)
	} else {
		fmt.Fprintf(w, "%s[%d]%s %s%s%s  %s%s+%s%s\n",
			c.cyan, call.Seq, c.reset, c.bold, label, c.reset,
			c.dim, "", dur(call.Start), c.reset)
	}

	for i, sp := range visible {
		last := i == len(visible)-1
		branch, cont := "├─", "│  "
		if last {
			branch, cont = "└─", "   "
		}

		title := sp.p.Cmd
		if title == "" {
			/* No exec of its own: a shell running builtins, or a process watched mid-life. */
			title = sp.p.Comm
		}
		fmt.Fprintf(w, "  %s %s%s%s %spid %d%s\n",
			branch, c.green, truncate(title, 110), c.reset, c.dim, sp.p.Pid, c.reset)

		for _, e := range sp.events {
			mark := " "
			col := c.dim
			tail := ""
			if e.Blocked {
				mark, col = "x", c.red
				/* Blocked events come from BPF-LSM hooks denying with -EPERM. */
				if opts.Enforce == "lsm" {
					tail = c.red + "  <- BLOCKED (denied, -EPERM)" + c.reset
				} else {
					tail = c.red + "  <- BLOCKED" + c.reset
				}
			}
			fmt.Fprintf(w, "  %s   %s%s %-7s%s %s%s%s%s\n",
				cont, col, mark, e.Type, c.reset, col, describe(e, res), c.reset, tail)
		}
	}
	fmt.Fprintln(w)
	return true
}

func renderFindings(w io.Writer, fs []finding, c colors) {
	if len(fs) == 0 {
		fmt.Fprintf(w, "%sfindings%s  none\n\n", c.bold, c.reset)
		return
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].sev > fs[j].sev })

	fmt.Fprintf(w, "%sfindings%s\n", c.bold, c.reset)
	for _, f := range fs {
		col, mark := c.yellow, "*"
		if f.sev >= 3 {
			col, mark = c.red, "!"
		}
		fmt.Fprintf(w, "  %s%s %s%s\n", col, mark, f.what, c.reset)
		fmt.Fprintf(w, "      %s%s%s\n", c.dim, f.detail, c.reset)
		fmt.Fprintf(w, "      %sduring: %s%s\n", c.dim, f.call, c.reset)
	}
	fmt.Fprintln(w)
}

func renderEgress(w io.Writer, calls []*record.Call, res *resolver, c colors) {
	type dest struct {
		addr  string
		count int
		calls map[string]bool
	}
	seen := map[string]*dest{}
	var order []string

	for _, call := range calls {
		for _, e := range call.Events {
			if e.Type != "connect" || e.Family == "unix" || e.IsRecorderItself() {
				continue
			}
			d, ok := seen[e.Dest]
			if !ok {
				d = &dest{addr: e.Dest, calls: map[string]bool{}}
				seen[e.Dest] = d
				order = append(order, e.Dest)
			}
			d.count++
		}
	}
	if len(order) == 0 {
		return
	}

	fmt.Fprintf(w, "%snetwork egress%s  %d distinct destinations\n", c.bold, c.reset, len(order))
	sort.Strings(order)
	for _, a := range order {
		d := seen[a]
		fmt.Fprintf(w, "  %s%-28s%s %sx%d%s\n", "", res.label(a), "", c.dim, d.count, c.reset)
	}
	fmt.Fprintln(w)
}

func describe(e record.Event, res *resolver) string {
	switch e.Type {
	case "open":
		mode := "read"
		if e.Write {
			mode = "write"
		}
		p := e.Path
		if p == "" {
			p = "(path unavailable)"
		}
		return p + " (" + mode + ")"
	case "unlink":
		p := e.Path
		if p == "" {
			p = "(path unavailable)"
		}
		return "deleted " + p
	case "connect":
		if e.Family == "unix" {
			return e.Dest
		}
		return res.label(e.Dest)
	case "exec":
		return e.CommandLine()
	case "fork":
		return fmt.Sprintf("%s forked from %d", e.Comm, e.Ppid)
	}
	return e.Type
}

/* resolver does cached, short-timeout reverse DNS so destinations read as names rather than IPs. */
type resolver struct {
	on       bool
	mu       sync.Mutex
	cache    map[string]string
	lookupFn func(host string) string /* reverseLookup by default; swapped in tests */
}

func newResolver(on bool) *resolver {
	r := &resolver{on: on, cache: map[string]string{}}
	r.lookupFn = reverseLookup
	return r
}

/* reverseLookup does one short-timeout reverse-DNS query, returning "" when the host has no name. */
func reverseLookup(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var rr net.Resolver
	if names, err := rr.LookupAddr(ctx, host); err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

/* warm reverse-resolves every distinct host concurrently and fills the cache, so label() never blocks the serial render on DNS one address at a time. */
func (r *resolver) warm(hostports []string) {
	if !r.on {
		return
	}
	seen := map[string]bool{}
	var hosts []string
	r.mu.Lock()
	for _, hp := range hostports {
		host, _, err := net.SplitHostPort(hp)
		if err != nil || seen[host] {
			continue
		}
		seen[host] = true
		if _, done := r.cache[host]; !done {
			hosts = append(hosts, host)
		}
	}
	r.mu.Unlock()

	sem := make(chan struct{}, 16) /* bound concurrent lookups */
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			name := r.lookupFn(host)
			r.mu.Lock()
			r.cache[host] = name
			r.mu.Unlock()
		}(host)
	}
	wg.Wait()
}

func (r *resolver) label(hostport string) string {
	if !r.on {
		return hostport
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}

	r.mu.Lock()
	name, ok := r.cache[host]
	r.mu.Unlock()

	if !ok {
		name = r.lookupFn(host)
		r.mu.Lock()
		r.cache[host] = name
		r.mu.Unlock()
	}

	if name == "" {
		return hostport
	}
	return fmt.Sprintf("%s:%s (%s)", host, port, name)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func dur(sec float64) string {
	return time.Duration(sec * float64(time.Second)).Truncate(time.Millisecond).String()
}

type colors struct {
	bold, dim, red, yellow, green, cyan, reset string
}

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{
		bold: "\033[1m", dim: "\033[2m", red: "\033[31m",
		yellow: "\033[33m", green: "\033[32m", cyan: "\033[36m", reset: "\033[0m",
	}
}
