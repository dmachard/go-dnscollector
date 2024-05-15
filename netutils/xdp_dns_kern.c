
//go:build exclude

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// packet_info
struct pkt_event {
  __u64 timestamp;
  __u32 pkt_len;
  __u32 pkt_offset;
  __u16 ip_version;
  __u16 ip_proto;
  __u16 payload_offset;
  __u32 src_addr;
  __u32 src_addr6[4];
  __u16 src_port;
  __u32 dst_addr;
  __u32 dst_addr6[4];
  __u16 dst_port;
} __attribute__((packed));
struct pkt_event *unused_event __attribute__((unused));


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
  __uint(max_entries, 4);
} pkts SEC(".maps");

SEC("xdp")
int xdp_sniffer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 offset = sizeof(struct ethhdr);

    struct pkt_event pkt = {};
    pkt.timestamp = bpf_ktime_get_ns(); 
    pkt.pkt_len = data_end - data;
    pkt.pkt_offset = sizeof(struct pkt_event);

    // enough data to read ethernet header ?
    if (data + offset > data_end)
        return XDP_PASS;

    // handle ethernet packet
    struct ethhdr  *eth  = data;
    pkt.ip_version = bpf_htons(eth->h_proto);

    // handle only IPv4 or IPv6 traffic 
    if (pkt.ip_version != ETH_P_IP &&  pkt.ip_version != ETH_P_IPV6)
        return XDP_PASS;

    // IPv4 - get L4 protocol
    if (pkt.ip_version == ETH_P_IP) {
        if (data + offset + sizeof(struct iphdr) > data_end)
            return XDP_PASS;

        struct iphdr   *ip4h   = (data + offset);
        pkt.ip_proto = ip4h->protocol;
        pkt.src_addr = bpf_htonl(ip4h->saddr);
        pkt.dst_addr = bpf_htonl(ip4h->daddr);

        offset += sizeof(struct iphdr);
    }

    // IPv6 - get L4 protocol
    if (pkt.ip_version == ETH_P_IPV6) {
        if (data + offset + sizeof(struct ipv6hdr) > data_end)
            return XDP_PASS;

        struct ipv6hdr *ip6h = (data + offset) ;
        pkt.ip_proto = ip6h->nexthdr;

        offset += sizeof(struct ipv6hdr);

        __builtin_memcpy(pkt.src_addr6, ip6h->saddr.in6_u.u6_addr32, sizeof(pkt.src_addr6));
        __builtin_memcpy(pkt.dst_addr6, ip6h->daddr.in6_u.u6_addr32, sizeof(pkt.dst_addr6));
    }

    // handle only UDP or TCP traffic 
    if (pkt.ip_proto != IPPROTO_UDP &&  pkt.ip_proto != IPPROTO_TCP) 
        return XDP_PASS;

    // TCP - get destination and source port
    if (pkt.ip_proto == IPPROTO_TCP) {
        if (data + offset + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;

        struct tcphdr *tcp  = data + offset;
        pkt.src_port = bpf_ntohs(tcp->source);
        pkt.dst_port = bpf_ntohs(tcp->dest);

        u8 tcp_flags = ((u8 *)tcp)[13];

        // ignore syn and ack packet
        if (tcp_flags != 0x18) {
            return XDP_PASS;
        }

        offset += tcp->doff*4;
    }

    // UDP - get destination and source port
    if (pkt.ip_proto == IPPROTO_UDP) {
        if (data + offset + sizeof(struct udphdr) > data_end)
            return XDP_PASS;

        struct udphdr *udp  = data + offset;
        pkt.src_port = bpf_ntohs(udp->source);
        pkt.dst_port = bpf_ntohs(udp->dest);

        offset += sizeof(struct udphdr);
    }

    // handle only dns packet
    if ( pkt.src_port != 53 && pkt.dst_port != 53)
        return XDP_PASS;

    pkt.payload_offset = offset;
    // write data in perf event
    int ret = bpf_perf_event_output(ctx, &pkts, 
                        BPF_F_CURRENT_CPU | ((__u64)pkt.pkt_len << 32), 
                        &pkt, sizeof(pkt));
    return XDP_PASS;
}