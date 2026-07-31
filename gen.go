// Package main — generation directive for bpf2go.
//
// Run `go generate ./...` (or `make generate`) to compile the eBPF C
// program into a CO-RE object and generate Go bindings.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -Werror" shivashield ./ebpf/shivashield.bpf.c -- -I./ebpf/headers

package main
