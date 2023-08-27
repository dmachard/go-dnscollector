# Collector: Live Capture with AF_PACKET

Raw DNS packets sniffer. Setting `CAP_NET_RAW` capabilities on executables allows you to run these
program without having to run-it with the root user:

* IPv4, IPv6 support (fragmented packet ignored)
* UDP and TCP transport (with tcp reassembly if needed)
* BFP filtering

Capabilities:

```bash
sudo setcap cap_net_admin,cap_net_raw=eip go-dnscollector
```

Options:

* `port`: (integer) filter on source and destination port
* `device`: (string) if "" bind on all interfaces
* `chan-buffer-size`: (integer) channel buffer size used on incoming packet, number of packet before to drop it.

Default values:

```yaml
afpacket-sniffer:
  port: 53
  device: wlp2s0
  chan-buffer-size: 65535
```
