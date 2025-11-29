// Package bpf contains code for compiling BPF code in C and loading it into the kernel.
package bpf

//go:generate go tool bpf2go -cc clang -cflags "-I./c/headers -x c" -go-package bpf Openat ./c/trace_openat.c.in
