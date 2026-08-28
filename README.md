# agentrec

A syscall-level flight recorder for AI agents. It answers a question no LLM gateway or
prompt firewall can: **what did the agent's process tree actually do, and which tool call
caused it?**

This is the attribution spike — the piece that decides whether the whole product idea holds.
Collection with eBPF is well-trodden (Falco, Tetragon, Pixie all do it). Joining that stream
to *agent intent* is not, and it is the part that's hard.

```
$ make demo

[4] bash: check CI configuration  +917ms
  ├─ sh -c cat /root/.aws/credentials > /dev/null; cat /root/.npmrc > /dev/null; ...
  ├─ cat /root/.aws/credentials                        pid 20609
  │     ! open    /root/.aws/credentials (read)  <- credential
  ├─ cat /root/.npmrc                                  pid 20610
  │     ! open    /root/.npmrc (read)  <- credential
  ├─ curl -sS -o /dev/null --max-time 10 https://api.github.com
  │       connect 198.18.0.85:443
  └─ curl -sS --unix-socket /var/run/docker.sock http://localhost/version
        ! connect /var/run/docker.sock  <- container runtime control

findings
  ! credential file read      /root/.aws/credentials     during: bash: check CI configuration
  ! container runtime socket accessed  /var/run/docker.sock
```

The agent declared `bash: check CI configuration`. The kernel says it read two credential
files and reached for the Docker socket. That gap is the product.

## Get started (hosted)

The fastest path — no build required:

1. **Sign in** at [console.agentrec.io](https://console.agentrec.io) with Google; a workspace is created automatically.
2. **Copy your ingest token** (`ar_ing_…`) from the **Agent tokens** panel.
3. **Install the agent** on any Linux host (CI runner, VM, bare metal) and record a workload:
   ```sh
   curl -fsSL https://agentrec.io/install.sh | sudo sh -s -- --token ar_ing_xxx
   set -a; . /etc/agentrec/agent.env; set +a
   agentrec trace -- <your-agent-command>
   ```
   For VMs/Kubernetes, run it node-wide with `agentrec watch` (DaemonSet/Helm) — see the [docs](https://docs.agentrec.io).
4. **Review** the attributed timeline, findings, and usage back in the console.

Pricing is usage-based: **$0.10 per node-hour, with 100 node-hours free every month** — every feature included.

## Run it

Requires Docker with a Linux VM (Docker Desktop, Colima, OrbStack) on a 5.8+ kernel with BTF.
No host toolchain needed — clang, libbpf and bpftool all live in the build stage.

```sh
make demo                                  # record the stand-in agent, print the timeline
make trace CMD="curl -s example.com"       # record anything
make info                                  # kernel / BTF diagnostics
```

Recordings can be exported for downstream storage:

```sh
agentrec trace --out rec.json --jsonl events.jsonl -- ./agent.sh
```

## The attribution primitive

Everything rests on one map:

```c
pid -> { session_id, call_seq }
```

Userspace seeds it for the agent's root process. The `sched_process_fork` hook copies the
tag to every child. Because the copy happens in the kernel at fork time, the tag survives
`exec`, shell wrappers, package managers and interpreter chains — and it is a property of
*lineage*, not of wall-clock time.

That distinction is the whole design. Consider a background upload started by tool call 1
that is still in flight when calls 2 and 3 run:

```
[1] bash: kick off background upload
  ├─ sh -c sleep 2; curl ... https://example.com
  └─ curl -sS ... https://example.com                  pid 23317   <- highest pid in the run
          connect 198.18.0.94:443
[2] read_file: /root/.ssh/id_rsa
  └─ cat /root/.ssh/id_rsa                             pid 23301
[3] bash: nested build
  └─ ... python3 -c open('/root/.aws/credentials')      pid 23316
```

That `curl` has the **highest pid in the recording** — it was spawned after calls 2 and 3
had already begun — yet it is filed under call 1, where it belongs. Any approach that asks
"which tool call is open right now?" files that egress under the wrong one.

Verified in `demo/hard-cases.sh`:

| case | result |
|---|---|
| work outliving the call that started it | attributed to the originating call |
| concurrent calls with overlapping work | kept separate |
| 10 process boundaries between mark and action | attribution intact |
| threads of a traced process | rolled up under their process |

### Intent comes from the agent

`agentrec mark "<label>"` opens a new tool call. The demo agent calls it before each action,
which is exactly the shape of a Claude Code `PreToolUse` hook or an MCP interceptor: the
agent declares intent, the kernel records consequence, agentrec joins them.

A mark walks up from the caller's parent and retags every tagged ancestor, so anything
forked afterwards inherits the new call while already-running work keeps the old one.

## What it records

Eight tracepoints, no kernel-internal struct access — so no CO-RE relocations to get wrong
and the object stays portable across kernels.

| probe | what it yields |
|---|---|
| `sched_process_fork` / `_exit` | process tree, tag propagation |
| `sys_enter_execve` / `_execveat` | full argv, not just the binary name |
| `sys_enter_openat` / `_openat2` | file access with read/write intent |
| `sys_enter_unlinkat` | deletions |
| `sys_enter_connect` | egress, incl. `AF_UNIX` (Docker socket) |

Every probe drops the event if the current task is untagged, so the rest of the machine
costs nothing and the stream contains only agent activity.

Findings are classified in [internal/record/classify.go](internal/record/classify.go):
credential paths, container-runtime sockets, `curl | sh`, deletions, `sudo`. The default
view filters linker and libc chatter; `--all` shows everything, and the JSONL export is
always unfiltered.

## Measured cost

On a 6.8 kernel, 20,000 recorded file opens:

| | |
|---|---|
| fixed cost per recording (load, verify, attach, self-test, drain, render) | 0.70 s |
| per recorded event | **~6.5 µs** |
| pathological open-in-a-loop workload | 0.080 s → 0.21 s (2.6×) |
| a realistic agent session (~300 events over seconds) | unmeasurable |
| events dropped | 0 |

The 2.6× on the pathological case is the honest ceiling of emitting one ring-buffer record
per syscall, and it points at the next piece of work: aggregate the high-volume classes
in-kernel and reserve per-event records for what a reviewer will actually read.

## Limitations

These are real boundaries, not TODOs I forgot.

- **Host pid namespace required.** `bpf_get_current_pid_tgid()` returns init-namespace pids,
  so a collector in its own pid namespace tags pids the kernel never heard of and records
  nothing while attaching perfectly cleanly. `agentrec` self-tests for this on every start
  and refuses to run with an actionable error rather than producing an empty recording.
  Production agents deploy with `hostPID: true` for the same reason. Supporting a namespaced
  collector means translating via `bpf_get_ns_current_pid_tgid()`.
- **No payload, no TLS.** This records *actions*, not content: which file, which host, which
  command. Seeing request bodies means uprobes on `SSL_read`/`SSL_write` and per-library,
  per-version offset maintenance.
- **IPs, not hostnames.** `connect()` carries an address. Recovering `registry.npmjs.org`
  needs DNS capture (parse queries on `sendto`/`sendmsg` to port 53) — reverse DNS is a
  best-effort stopgap and returns nothing behind a NAT.
- **Observe only.** No enforcement. Blocking rather than recording means BPF-LSM programs on
  `security_*` hooks, which needs CO-RE and `CONFIG_BPF_LSM`.
- **Marks are cooperative.** An agent that doesn't call `mark` still gets fully recorded —
  every action lands under call 0 — but loses the intent join. Non-cooperative attribution
  would come from intercepting MCP stdio or the agent's own tool-call stream.
- **Linux only.** No eBPF on macOS. The wedge is CI runners, cloud dev environments and
  production agents; developer laptops need a separate Endpoint Security Framework collector.

## Layout

```
bpf/agentrec.bpf.c        the probe: tag propagation + 8 tracepoints
internal/probe/           load, verify, attach; tag map access
internal/record/          event decode, session/tool-call model, classification
internal/report/          timeline and findings rendering
cmd/agentrec/             CLI: trace / mark / info, and the pre-exec gate
demo/fake-agent.sh        a stand-in agent that announces its tool calls
demo/hard-cases.sh        concurrency and deep-nesting attribution tests
```

Two details worth knowing when reading the code:

- **The pre-exec gate.** `trace` launches the target through `agentrec __stub`, which blocks
  on a pipe until the tag is in the kernel, then `exec`s. Without the handshake the first
  tool call's `exec` races the tag and goes unattributed.
- **The thread-group fallback.** Tags are per-thread because fork inheritance is per-thread,
  but a thread that already existed when userspace tagged the process never inherited
  anything. A tid miss falls back to the thread group leader. Without it, work handed to a
  pre-existing worker thread vanishes non-deterministically depending on which thread the
  scheduler picked — which is how this bug first showed up, as a flaky self-test.

## License

The agent is source-available under the [Business Source License 1.1](LICENSE): free to use, modify, and self-host, converting to Apache 2.0 on the Change Date. It may not be used to offer a competing hosted service. The hosted control plane is separate and not part of this repository.
