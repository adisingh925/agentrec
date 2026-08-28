<div align="center">

# agentrec

### A flight recorder for AI agents

Every file, command, and network call your AI agents make — captured at the kernel with **eBPF**, and tied back to the exact tool call that caused it.
No SDK. No code changes. No trusting the agent's own logs.

[![License](https://img.shields.io/badge/license-BSL_1.1-2A2F3A.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/adisingh925/agentrec?color=F5622D)](https://github.com/adisingh925/agentrec/releases)
[![Platform](https://img.shields.io/badge/platform-Linux_5.8%2B-5FD0A0.svg)](#requirements)
[![Built with eBPF](https://img.shields.io/badge/eBPF-CO--RE-F5622D.svg)](#how-it-works)

**[Website](https://agentrec.io)** · **[Docs](https://docs.agentrec.io)** · **[Console](https://console.agentrec.io)**

</div>

---

## The problem

Your agent reports `bash: check CI configuration`. Prompt firewalls and LLM gateways see that sentence — and stop there. The kernel sees what actually happened:

```text
tool call ─ bash: check CI configuration

  ├─ cat /root/.aws/credentials                    ! read credential file
  ├─ cat /root/.npmrc                              ! read credential file
  └─ curl --unix-socket /var/run/docker.sock …     ! reached the Docker socket

findings
  ⚠  credential file read        /root/.aws/credentials
  ⚠  container runtime socket    /var/run/docker.sock
```

The agent said one thing. It read two secrets and reached for container control. **That gap is what agentrec records.**

## How it works

1. **The agent declares intent** — a one-line hook (a Claude Code `PreToolUse` hook, an MCP interceptor, or `agentrec mark`) announces each tool call.
2. **The kernel records the consequence** — eBPF tracepoints capture every process, file, command, and connection that tool call spawns.
3. **agentrec joins them** — each syscall is attributed to the tool call that caused it, through shells, subprocesses, and package managers — giving you a replayable, per-call timeline.

Because it reads the **kernel** and not the agent, it works the same across every agent and vendor, with nothing to install inside the agent itself.

## Quickstart

**Hosted** — record any Linux host in a couple of commands:

```sh
# get an ingest token from the console → Agent tokens
curl -fsSL https://agentrec.io/install.sh | sudo sh -s -- --token ar_ing_xxx

# record your agent, then review the timeline + findings in the console
agentrec trace -- ./your-agent
```

Running on VMs or Kubernetes? Capture a whole node with `agentrec watch` (DaemonSet / Helm) — see the **[docs](https://docs.agentrec.io)**.

**Local** — try it with Docker (a Linux VM on a 5.8+ kernel — Docker Desktop, Colima, or OrbStack):

```sh
make demo    # records a stand-in agent and prints the attributed timeline
```

## What it captures

| | |
|---|---|
| **Processes** | the full tree — every `fork`, `exec` (with complete argv), and exit |
| **Files**     | opens (read vs. write) and deletions |
| **Network**   | outbound connections, including Unix sockets like the Docker socket |
| **Findings**  | credential reads, container-runtime sockets, `curl \| sh`, deletions, `sudo` |

Every event is tied to a tool call **and** to process lineage — so background work kicked off by one call stays filed under that call, even if it finishes long after the call returns.

## Requirements

- **Linux 5.8+** with BTF (`/sys/kernel/btf/vmlinux`)
- Runs privileged, in the **host PID namespace** (`hostPID: true` on Kubernetes) — it needs init-namespace PIDs to attribute correctly
- x86-64 or arm64

## Good to know

- **Records actions, not content** — which file, which host, which command; not request bodies or decrypted TLS.
- **Observe-only** by default. In-kernel blocking (BPF-LSM) is available in beta on hosts that carry the BPF LSM.
- **Linux only** — the sweet spot is CI runners, cloud dev environments, and production agent nodes.

## Documentation

Full guides — install, `trace` vs. `watch`, custom detection rules, Kubernetes, and the API — live at **[docs.agentrec.io](https://docs.agentrec.io)**.

## License

Source-available under the **[Business Source License 1.1](LICENSE)** — free to use, modify, and self-host; it converts to Apache 2.0 on the Change Date. It may not be used to offer a competing hosted service. The hosted control plane is a separate, private component.
