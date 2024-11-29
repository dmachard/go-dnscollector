# Collector: Live Capture with AF_PACKET

Raw DNS packets sniffer. Setting `CAP_NET_RAW` capabilities on executables allows you to run these program without having to run-it with the root user:

* IPv4, IPv6 support (fragmented packet ignored)
* UDP and TCP transport (with tcp reassembly if needed)
* BFP filtering
* GRE tunnel support

Capabilities:

```bash
sudo setcap cap_net_admin,cap_net_raw=eip go-dnscollector
```

Options:

* `port` (int)
  > filter on source and destination port.

* `device` (str)
  > Interface name to sniff. If value is empty, bind on all interfaces.

* `enable-rawip` (bool)
  > Enable the decoding of raw IP traffic (without ethernet layer), enable this option to sniff gre interface

* `enable-gre` (bool)
  > Enable GRE decoding protocol support

* `enable-fragment-support` (bool)
  > Enable IP defrag support

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Defaults values:

```yaml
- name: sniffer
  afpacket-sniffer:
    port: 53
    device: wlp2s0
    enable-rawip: false
    enable-gre: false
    enable-defrag-ip: true
    chan-buffer-size: 0
```

This configuration is designed to enable traffic capture on a GRE interface (e.g., gre1) in Raw IP mode, 
meaning Ethernet headers will not be present.

```yaml
- name: sniffer_gre
  afpacket-sniffer:
    port: 53
    device: gre1
    enable-rawip: true
```

This configuration is used to capture and decode GRE traffic passing through a physical interface:

```yaml
- name: sniffer_gre
  afpacket-sniffer:
    port: 53
    device: wlp2s0
    enable-gre: true
```