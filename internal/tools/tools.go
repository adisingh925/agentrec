//go:build tools

/* Package tools pins code generators so `go mod tidy` keeps them in go.mod; never compiled into the binary. */
package tools

import _ "github.com/cilium/ebpf/cmd/bpf2go"
