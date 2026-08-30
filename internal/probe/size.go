package probe

import "unsafe"

/* EventSize is the size of `struct event`, from the bpf2go-generated Go type. */
const EventSize = int(unsafe.Sizeof(agentrecEvent{}))
