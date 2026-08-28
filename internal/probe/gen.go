package probe

// bpf2go compiles the probe and embeds the resulting object in this package. vmlinux.h is
// generated from the build host's BTF (see Dockerfile); because none of the programs touch
// kernel-internal structs, the object stays portable across kernels.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package probe -output-dir . -type event -type tag agentrec ../../bpf/agentrec.bpf.c -- -O2 -g -Wall -Werror
