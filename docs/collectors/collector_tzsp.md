# Collector: TZSP sniffer

This collector receives TZSP (TaZmen Sniffer Protocol) packets that contain a full DNS packet, meaning Ethernet, IPv4/IPv6, UDP, then DNS.
Its primary purpose is to suppport DNS packet capture from Mikrotik brand devices. These devices allow cloning of packets and sending them via TZSP to remote hosts.

Options:

- `listen-ip` (str)
  > Set the local address that the server will bind to.

- `listen-port` (int)
  > Set the local port that the server will bind to.

- `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

Defaults:

```yaml
- name: sniffer
  tzsp:
    listen-ip: 0.0.0.0
    listen-port: 10000
    chan-buffer-size: 65535
```

Example rules for Mikrotik brand devices to send the traffic (only works if routed or the device serves as DNS server).

```routeros
/ipv6 firewall mangle
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (TCP)" dst-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (TCP)" src-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (UDP)" dst-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (UDP)" src-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (TCP)" dst-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (TCP)" src-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (UDP)" dst-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (UDP)" src-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
/ip firewall mangle
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (TCP)" dst-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (TCP)" src-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (UDP)" dst-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=prerouting comment="Sniff DNS (UDP)" src-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (TCP)" dst-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (TCP)" src-port=53 \
    protocol=tcp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (UDP)" dst-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
add action=sniff-tzsp chain=output comment="Sniff DNS (UDP)" src-port=53 \
    protocol=udp sniff-target=10.0.10.2 sniff-target-port=10000
```
