package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type pkt_event bpf xdp_dns_kern.c -- -I./headers
