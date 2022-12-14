#!/usr/bin/env bash

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.0.1

# The headers we want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/src/bpf_endian.h
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
)

# Fetch libbpf release and extract the desired headers
rm -rf headers/ && mkdir headers/ && cd headers/
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz --xform='s#.*/##' "${headers[@]}"

# generate vmlinux
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h