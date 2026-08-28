//go:build tools

// Package tools pins the code generators this build needs so `go mod tidy` keeps them in
// go.mod. It is never compiled into the binary.
package tools

import _ "github.com/cilium/ebpf/cmd/bpf2go"
