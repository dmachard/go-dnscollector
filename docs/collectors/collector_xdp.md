# Collector: Live Capture with eBPF XDP

Packets live capture close to NIC through eBPF `eXpress Data Path (XDP)`.
XDP is the lowest layer of the Linux kernel network stack, It is present only on the RX path.

Support on Linux only.

Capabilities:

- cap_sys_resource is required to release the rlimit memlock which is necessary to be able to load BPF programs
- cap_perfmon is required to create a kernel perf buffer for exporting packet data into user space

```bash
sudo setcap cap_sys_resource,cap_net_raw,cap_perfmon+ep go-dnscollector
```

Options:

* `device` (str)
  > Interface name to use for XDP sniffing.

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

Defaults:

```yaml
- name: sniffer
  xdp-sniffer:
    device: wlp2s0
    chan-buffer-size: 65535
```
