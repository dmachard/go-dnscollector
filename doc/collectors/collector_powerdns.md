# Collector: Protobuf PowerDNS

Collector to logging protobuf streams from PowerDNS servers. More details [here](powerdns.md).

Options:

- `listen-ip`: (string) listen on ip
- `listen-port`: (integer) listening on port
- `tls-support:`: (boolean) to enable, set to true
- `tls-min-version`: (string) min tls version
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `sock-rcvbuf`: (integer) sets the socket receive buffer in bytes SO_RCVBUF, set to zero to use the default system value
- `reset-conn`: (bool) Reset TCP connection on exit
- `chan-buffer-size`: (integer) channel buffer size used on incoming packet, number of packet before to drop it.
- `add-dns-payload`: (boolean) generate and add fake DNS payload

Default values:

```yaml
powerdns:
  listen-ip: 0.0.0.0
  listen-port: 6001
  tls-support: false
  tls-min-version: 1.2
  cert-file: ""
  key-file: ""
  add-dns-payload: false
  sock-rcvbuf: 0
  reset-conn: true
  chan-buffer-size: 65535
  add-dns-payload: false
```