package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type pkt_event bpf ../ebpf/xdp_dns_kern.c -- -I../ebpf/headers
