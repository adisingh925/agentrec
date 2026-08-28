package probe

import "unsafe"

// EventSize is the size of `struct event` as reported by the probe's own BTF (the Go type
// is generated from it by bpf2go).
const EventSize = int(unsafe.Sizeof(agentrecEvent{}))
