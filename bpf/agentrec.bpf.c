// SPDX-License-Identifier: GPL-2.0
//
// agentrec: attribute kernel-level actions to the AI-agent tool call that caused them.
//
// The only stateful idea in here is `pid_tags`: a pid -> {session, tool_call} map that
// userspace seeds for the agent's root process, and that this program propagates on every
// fork. Because the tag lives in the kernel and is copied at fork time, it survives exec,
// shell wrappers, package managers and thread pools -- which is what makes attribution
// hold up on a real process tree instead of just a toy one.
//
// Every probe except the fork hook drops the event if the current task is untagged, so we
// pay nothing for the rest of the machine and the event stream contains only agent activity.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1  /* LSM hooks deny by returning -EPERM */

#define ARG_CAP  512  /* logical bytes we accumulate into event.buf */
#define BUF_SIZE 640  /* physical size; the slack lets the verifier prove masked writes */
#define COMM_LEN 16

#define EVT_FORK    1
#define EVT_EXEC    2
#define EVT_EXIT    3
#define EVT_OPEN    4
#define EVT_CONNECT 5
#define EVT_UNLINK  6

#define AF_UNIX_  1
#define AF_INET_  2
#define AF_INET6_ 10

#define ST_DROPPED 0
#define ST_EMITTED 1

#define HDR_SIZE __builtin_offsetof(struct event, buf)  /* header only (96), no buf */

/* Dynamic block rules pushed from the control plane into the block_rules map. The LSM hooks
 * consult them so a workspace's own policy can deny file opens / socket connects / execs /
 * unlinks in-kernel with a clean -EPERM. Kept small and bounded so
 * the verifier accepts the match loop and the per-open cost stays low. */
#define MAX_PAT   63   /* max pattern length; struct block_rule stays 68 bytes */
#define MAX_RULES 32   /* max dynamic rules consulted in-kernel */

#define REV_OPEN    1  /* rule.event: file open (LSM file_open) */
#define REV_CONNECT 2  /* rule.event: socket connect, unix path (LSM socket_connect) */
#define REV_EXEC    3  /* rule.event: exec, matched on the executable path (LSM bprm_check) */
#define REV_UNLINK  4  /* rule.event: unlink, matched on the target path (LSM path_unlink) */
#define ROP_SUFFIX  1
#define ROP_PREFIX  2
#define ROP_EQUALS  3

struct tag {
	__u64 session_id;
	__u64 call_seq;
};

/* Field order is chosen so the struct has no padding on any 64-bit arch; the Go side
 * decodes it with a matching layout. */
struct event {
	__u64 ts;
	__u64 session_id;
	__u64 call_seq;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 type;
	__u32 arg_len;
	__s32 flags;
	__u32 blocked;
	__u32 _pad;
	__u32 dport;
	__u32 af;
	__u8  daddr[16];
	char  comm[COMM_LEN];
	char  buf[BUF_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct tag);
} pid_tags SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Referencing these types from a global keeps them in BTF after stripping, which is how
 * bpf2go derives the Go-side layout. Without it the two definitions could drift silently. */
const struct event *unused_event __attribute__((unused));
const struct tag *unused_tag __attribute__((unused));

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		*v += 1;
}

/* Attribution is stored per-thread, because fork inheritance is per-thread. But a thread
 * that already existed when userspace tagged the process never inherited anything, so a
 * tid miss falls back to the thread group leader. Without this, work that a threaded agent
 * hands to a pre-existing worker thread (any Go, Node or JVM runtime) vanishes from the
 * recording -- and does so non-deterministically, depending on which thread the scheduler
 * picked. */
static __always_inline struct tag *tag_for(__u32 tid, __u32 tgid)
{
	struct tag *t = bpf_map_lookup_elem(&pid_tags, &tid);
	if (t)
		return t;
	if (tgid != tid)
		return bpf_map_lookup_elem(&pid_tags, &tgid);
	return NULL;
}

static __always_inline struct tag *cur_tag(__u64 *pt)
{
	*pt = bpf_get_current_pid_tgid();
	return tag_for((__u32)*pt, (__u32)(*pt >> 32));
}

/* ---------- enforcement ----------
 * config[0] != 0 turns enforcement on. The lsm hooks at the bottom of this file consult the
 * dynamic block_rules map (mirrored from the workspace's own "block" rules) and refuse a
 * matching action with a clean -EPERM; the agent keeps running. Requires the BPF LSM in the
 * kernel's active list (userspace sets config[2] when it attaches the hooks). There is no
 * tracepoint enforcement fallback and no built-in targets: only the user's rules deny. */
#define WATCH_MAX 8
#define WATCH_LEN 16

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);          /* [0]=enforce  [1]=watch  [2]=lsm_active  [3]=rule_count */
	__type(key, __u32);
	__type(value, __u32);
} ar_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} node_sess SEC(".maps");

static __always_inline int enforcing(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&ar_config, &k);
	return v && *v;
}

static __always_inline int watch_enabled(void)
{
	__u32 k = 1;
	__u32 *v = bpf_map_lookup_elem(&ar_config, &k);
	return v && *v;
}

static __always_inline __u64 node_session(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&node_sess, &k);
	return v ? *v : 0;
}

/* A dynamic policy rule, populated from userspace (which mirrors the workspace's enabled
 * "block" rules). Layout is all bytes so the Go and C structs agree without padding. */
struct block_rule {
	__u8 active;            /* 1 = slot in use */
	__u8 event;            /* REV_* */
	__u8 op;               /* ROP_* */
	__u8 len;              /* pattern length, 1..MAX_PAT */
	char pat[MAX_PAT + 1]; /* 64 bytes -> struct is 68 bytes, alignment 1 */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct block_rule);
} block_rules SEC(".maps");

/* Number of active dynamic rules (config[3]); bounds the match loop so an empty policy costs
 * nothing and the verifier still sees a constant upper bound of MAX_RULES. */
static __always_inline __u32 rule_count(void)
{
	__u32 k = 3;
	__u32 *v = bpf_map_lookup_elem(&ar_config, &k);
	__u32 c = v ? *v : 0;
	return c > MAX_RULES ? MAX_RULES : c;
}

/* Per-event active-rule count, indexed by REV_* (1..4). Lets an LSM hook fast-skip path
 * resolution and the whole scan when no rule targets that event type -- the common case for
 * a partial policy. Userspace publishes it in SetBlockRules with an over-estimate sandwich
 * (mark all events hot across the swap, then set exact counts) so a policy change never
 * transiently lets a denied action through. Default 0 = that event type is not enforced. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u32);
} rule_ev_count SEC(".maps");

static __always_inline __u32 ev_rule_count(__u32 ev)
{
	__u32 *v = bpf_map_lookup_elem(&rule_ev_count, &ev);
	return v ? *v : 0;
}

/* Prefix match of a map-resident pattern against buf[0..blen). `mask` must be capacity-1 with
 * capacity a power of two, so the verifier can prove every indexed read stays in bounds. */
static __always_inline int dpat_prefix(const char *buf, __u32 blen, const struct block_rule *r, __u32 mask)
{
	int slen = r->len;
	if (slen <= 0 || slen > MAX_PAT || (__u32)slen > blen || blen > mask + 1)
		return 0;
	/* Iterate the compile-time-constant MAX_PAT with no data-dependent exit so clang can fully
	 * unroll (a `break` on the runtime `slen` blocks the unroll) and the verifier sees no
	 * back-edge. Bytes past `slen` are guarded out of the comparison; every indexed read stays
	 * in bounds via the mask, so the guard is about correctness, not safety. */
	int ok = 1;
#pragma unroll
	for (int i = 0; i < MAX_PAT; i++) {
		if (i < slen && buf[(__u32)i & mask] != r->pat[i])
			ok = 0;
	}
	return ok;
}

/* Suffix match of a map-resident pattern against buf[0..blen). */
static __always_inline int dpat_suffix(const char *buf, __u32 blen, const struct block_rule *r, __u32 mask)
{
	int slen = r->len;
	if (slen <= 0 || slen > MAX_PAT || (__u32)slen > blen || blen > mask + 1)
		return 0;
	__u32 off = blen - (__u32)slen;
	int ok = 1;
#pragma unroll
	for (int i = 0; i < MAX_PAT; i++) {
		if (i < slen && buf[(off + (__u32)i) & mask] != r->pat[i])
			ok = 0;
	}
	return ok;
}

static __always_inline int dpat_match(const char *buf, __u32 blen, const struct block_rule *r, __u32 mask)
{
	if (r->op == ROP_SUFFIX)
		return dpat_suffix(buf, blen, r, mask);
	if (r->op == ROP_PREFIX)
		return dpat_prefix(buf, blen, r, mask);
	if (r->op == ROP_EQUALS)
		return blen == (__u32)r->len && dpat_prefix(buf, blen, r, mask);
	return 0;
}

/* Does any active dynamic rule for `event` match buf[0..blen)? Consulted by the LSM hooks to
 * decide whether to deny the operation. */
static __always_inline int dyn_blocked(const char *buf, __u32 blen, __u8 event, __u32 mask)
{
	__u32 cnt = rule_count();
	for (__u32 i = 0; i < MAX_RULES; i++) {
		if (i >= cnt)
			break;
		/* Copy the index into a separate key: passing &i (the loop counter's address) to the
		 * helper forces it to the stack and the verifier loses track of the induction variable
		 * advancing, which it then reports as an infinite loop. */
		__u32 key = i;
		struct block_rule *r = bpf_map_lookup_elem(&block_rules, &key);
		if (!r || !r->active || r->event != event)
			continue;
		if (dpat_match(buf, blen, r, mask))
			return 1;
	}
	return 0;
}

static __always_inline struct event *evt_start(struct tag *t, __u32 type, __u64 pt, __u64 rsz)
{
	struct event *e = bpf_ringbuf_reserve(&events, rsz, 0);
	if (!e) {
		bump(ST_DROPPED);
		return NULL;
	}

	e->ts         = bpf_ktime_get_ns();
	e->session_id = t->session_id;
	e->call_seq   = t->call_seq;
	e->pid        = pt >> 32;
	e->tid        = (__u32)pt;
	e->ppid       = 0;
	e->type       = type;
	e->arg_len    = 0;
	e->flags      = 0;
	e->blocked    = 0;
	e->_pad       = 0;
	e->dport      = 0;
	e->af         = 0;

	/* daddr and buf are left uninitialized on purpose: consumers read only buf[0..arg_len)
	 * and daddr per address family, so zeroing the full 640-byte buffer on every event was
	 * pure hot-path overhead. Each caller sets arg_len to exactly the bytes it wrote. */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void evt_send(struct event *e)
{
	bump(ST_EMITTED);
	bpf_ringbuf_submit(e, 0);
}

/* Emit a synthetic event recording that an LSM hook denied an operation with -EPERM. The
 * tracepoint fires on syscall *entry*, before any LSM verdict exists, so it can only record
 * the attempt; this adds a blocked=1 record carrying the resolved path/dest so the recording
 * shows the denial. The field layout mirrors the tracepoint's open/connect
 * events so the userspace decoder needs no special case. */
static __always_inline void emit_blocked(struct tag *t, const char *src, __u32 len, __u32 type, __s32 flags, __u16 af, __u64 pt)
{
	struct event *e = evt_start(t, type, pt, sizeof(struct event));
	if (!e)
		return;
	__u32 cp = len & 0x1ff;   /* src paths here are <= 256 bytes; mask bounds the copy for the verifier */
	bpf_probe_read_kernel(e->buf, cp, src);
	e->arg_len = cp;
	e->flags   = flags;
	e->af      = af;
	e->blocked = 1;
	evt_send(e);
}

/* ---------- process tree: this is where the tag propagates ---------- */

SEC("tp/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 ppid = (__u32)ctx->parent_pid;
	__u32 cpid = (__u32)ctx->child_pid;

	/* current is the forking task, so this picks up the thread-group fallback too. */
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	/* The child inherits the parent's session and tool call. Everything downstream --
	 * attribution through exec, through sh -c, through npm spawning 40 helpers -- falls
	 * out of this one copy. */
	struct tag child = *t;
	bpf_map_update_elem(&pid_tags, &cpid, &child, BPF_ANY);

	struct event *e = evt_start(t, EVT_FORK, pt, HDR_SIZE);
	if (!e)
		return 0;

	e->tid  = cpid;
	e->pid  = cpid;
	e->ppid = ppid;
	/* comm is left as the forking task's name (set in evt_start). We deliberately do NOT
	 * read ctx->child_comm: some kernels represent that tracepoint field as a __data_loc
	 * rather than a fixed char array, so referencing it fails to compile against their BTF.
	 * The child's real identity is captured at exec anyway. */
	evt_send(e);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int on_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 pt  = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pt;
	__u32 pid = pt >> 32;

	struct tag *t = bpf_map_lookup_elem(&pid_tags, &tid);
	if (!t)
		return 0;

	/* Only the thread group leader's exit is a process exit worth reporting. */
	if (tid == pid) {
		struct event *e = evt_start(t, EVT_EXIT, pt, HDR_SIZE);
		if (e)
			evt_send(e);
	}

	bpf_map_delete_elem(&pid_tags, &tid);
	return 0;
}

/* ---------- exec: filename + full argv ---------- */

static __always_inline int handle_exec(void *fname, void *argv_p)
{
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	struct tag adopt;
	if (!t) {
		if (!watch_enabled())
			return 0;
		/* node-wide watch: emit this exec as a candidate. Userspace matches the binary
		 * name and, on a hit, tags the pid so its descendants are captured in-kernel. */
		adopt.session_id = node_session();
		adopt.call_seq = pt >> 32;
		t = &adopt;
	}

	struct event *e = evt_start(t, EVT_EXEC, pt, sizeof(struct event));
	if (!e)
		return 0;

	__u32 off = 0;
	long n = bpf_probe_read_user_str(&e->buf[0], 256, fname);
	if (n > 0)
		off = (__u32)n;

	const char **argv = argv_p;

	for (int i = 0; i < 20; i++) {
		if (off > ARG_CAP)
			break;

		const char *p = NULL;
		if (bpf_probe_read_user(&p, sizeof(p), &argv[i]) != 0)
			break;
		if (!p)
			break;

		/* off is masked into [0, ARG_CAP-1] and we write at most 128 bytes, so the
		 * furthest byte touched is ARG_CAP-1+128 = 639 < BUF_SIZE. */
		n = bpf_probe_read_user_str(&e->buf[off & (ARG_CAP - 1)], 128, p);
		if (n <= 0)
			break;
		off += (__u32)n;
	}

	e->arg_len = off > BUF_SIZE ? BUF_SIZE : off;
	evt_send(e);
	return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec((void *)ctx->args[0], (void *)ctx->args[1]);
}

SEC("tp/syscalls/sys_enter_execveat")
int on_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec((void *)ctx->args[1], (void *)ctx->args[2]);
}

/* ---------- file access ---------- */

static __always_inline int handle_path(void *path, __s32 flags, __u32 type)
{
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	struct event *e = evt_start(t, type, pt, sizeof(struct event));
	if (!e)
		return 0;

	long n = bpf_probe_read_user_str(e->buf, 384, path);
	e->arg_len = n > 0 ? (__u32)n : 0;
	e->flags   = flags;
	evt_send(e);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_path((void *)ctx->args[1], (__s32)ctx->args[2], EVT_OPEN);
}

SEC("tp/syscalls/sys_enter_openat2")
int on_openat2(struct trace_event_raw_sys_enter *ctx)
{
	__u64 how_flags = 0;
	/* struct open_how { __u64 flags; __u64 mode; __u64 resolve; } */
	bpf_probe_read_user(&how_flags, sizeof(how_flags), (void *)ctx->args[2]);
	return handle_path((void *)ctx->args[1], (__s32)how_flags, EVT_OPEN);
}

SEC("tp/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_path((void *)ctx->args[1], 0, EVT_UNLINK);
}

/* ---------- network egress ---------- */

SEC("tp/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	void *uaddr = (void *)ctx->args[1];
	__u16 fam = 0;

	if (bpf_probe_read_user(&fam, sizeof(fam), uaddr) != 0)
		return 0;
	if (fam != AF_INET_ && fam != AF_INET6_ && fam != AF_UNIX_)
		return 0;

	/* Reserve size is a per-branch compile-time constant (the verifier rejects a variable
	 * size). AF_INET/INET6 put dest+port in the header, so they reserve HDR_SIZE; only the
	 * AF_UNIX arm writes buf, so it alone reserves the full record. */
	struct event *e;
	if (fam == AF_INET_ || fam == AF_INET6_) {
		e = evt_start(t, EVT_CONNECT, pt, HDR_SIZE);
		if (!e)
			return 0;
		e->af = fam;
		if (fam == AF_INET_) {
			__u16 port = 0;
			__u32 a4 = 0;
			bpf_probe_read_user(&port, sizeof(port), (char *)uaddr + 2);
			bpf_probe_read_user(&a4, sizeof(a4), (char *)uaddr + 4);
			e->dport = bpf_ntohs(port);
			__builtin_memcpy(e->daddr, &a4, 4);
		} else {
			__u16 port = 0;
			bpf_probe_read_user(&port, sizeof(port), (char *)uaddr + 2);
			bpf_probe_read_user(e->daddr, 16, (char *)uaddr + 8);
			e->dport = bpf_ntohs(port);
		}
	} else {
		/* AF_UNIX: sun_path into buf -- a connect to /var/run/docker.sock is one of the
		 * highest-signal things an agent can do -- so this arm reserves the full record. */
		e = evt_start(t, EVT_CONNECT, pt, sizeof(struct event));
		if (!e)
			return 0;
		e->af = fam;
		long n = bpf_probe_read_user_str(e->buf, 108, (char *)uaddr + 2);
		e->arg_len = n > 0 ? (__u32)n : 0;
	}

	evt_send(e);
	return 0;
}

/* ---------- BPF-LSM enforcement: clean pre-syscall deny ----------
 * Attached by userspace only when the kernel carries the BPF LSM in its active list
 * (config[2] is set at the same time). These refuse the operation itself: the syscall returns
 * -EPERM and the agent keeps running, so a denied action is indistinguishable from an ordinary
 * permission error. The policy is entirely the dynamic block_rules map, mirrored from the
 * workspace's enabled "block" rules -- there are no built-in targets.
 *
 * Both hooks receive the accumulated verdict of earlier LSMs as the trailing `ret`; we
 * propagate any existing denial and otherwise only ever tighten (0 -> -EPERM), never loosen.
 */

SEC("lsm/file_open")
int BPF_PROG(ar_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret;
	if (!enforcing())
		return 0;
	if (ev_rule_count(REV_OPEN) == 0)
		return 0;
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	char buf[256];
	long n = bpf_d_path(&file->f_path, buf, sizeof(buf));
	if (n > 1 && dyn_blocked(buf, (__u32)(n - 1), REV_OPEN, 255)) {
		emit_blocked(t, buf, (__u32)n, EVT_OPEN, (__s32)BPF_CORE_READ(file, f_flags), 0, pt);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(ar_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	if (ret != 0)
		return ret;
	if (!enforcing())
		return 0;
	if (ev_rule_count(REV_CONNECT) == 0)
		return 0;
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	__u16 fam = BPF_CORE_READ(address, sa_family);
	if (fam == AF_UNIX_) {
		char path[128];
		struct sockaddr_un *un = (struct sockaddr_un *)address;
		long n = bpf_probe_read_kernel_str(path, sizeof(path), un->sun_path);
		if (n > 1 && dyn_blocked(path, (__u32)(n - 1), REV_CONNECT, 127)) {
			emit_blocked(t, path, (__u32)n, EVT_CONNECT, 0, AF_UNIX_, pt);
			return -EPERM;
		}
	}
	return 0;
}

/* Exec: deny running a binary whose path matches a dynamic rule. bprm->filename is the target
 * passed to execve (absolute once libc has resolved $PATH), which avoids bpf_d_path's hook
 * allowlist. Matches the executable path, not argv -- a cmdline/regex rule stays detect-only. */
SEC("lsm/bprm_check_security")
int BPF_PROG(ar_bprm_check, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;
	if (!enforcing())
		return 0;
	if (ev_rule_count(REV_EXEC) == 0)
		return 0;
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	char buf[256];
	const char *fn = BPF_CORE_READ(bprm, filename);
	long n = bpf_probe_read_kernel_str(buf, sizeof(buf), fn);
	if (n > 1 && dyn_blocked(buf, (__u32)(n - 1), REV_EXEC, 255)) {
		emit_blocked(t, buf, (__u32)n, EVT_EXEC, 0, 0, pt);
		return -EPERM;
	}
	return 0;
}

/* Unlink: deny deleting a file whose name matches a dynamic rule. bpf_d_path needs a real
 * trusted `struct path *`; we only have the parent path + the target dentry, and a synthesized
 * stack path is rejected. So we match the dentry's filename (d_name) -- the highest-signal part
 * for delete-protection ("id_rsa", "*.key", "audit.log"). Rules should target the file name,
 * not a directory prefix. */
SEC("lsm/path_unlink")
int BPF_PROG(ar_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
	if (ret != 0)
		return ret;
	if (!enforcing())
		return 0;
	if (ev_rule_count(REV_UNLINK) == 0)
		return 0;
	__u64 pt;
	struct tag *t = cur_tag(&pt);
	if (!t)
		return 0;

	char buf[256];
	const char *nm = (const char *)BPF_CORE_READ(dentry, d_name.name);
	long n = bpf_probe_read_kernel_str(buf, sizeof(buf), nm);
	if (n > 1 && dyn_blocked(buf, (__u32)(n - 1), REV_UNLINK, 255)) {
		emit_blocked(t, buf, (__u32)n, EVT_UNLINK, 0, 0, pt);
		return -EPERM;
	}
	return 0;
}
