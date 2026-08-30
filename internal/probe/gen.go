package probe

/* bpf2go compiles the probe and embeds the object; it stays portable across kernels since no program touches kernel-internal structs. */

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package probe -output-dir . -type event -type tag agentrec ../../bpf/agentrec.bpf.c -- -O2 -g -Wall -Werror
