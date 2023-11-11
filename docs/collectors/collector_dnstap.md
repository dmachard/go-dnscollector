# Collector: DNStap

## DNS tap

Collector to logging DNStap stream from DNS servers.
The traffic can be a tcp or unix DNStap stream. TLS is also supported.

Options:

- `listen-ip`: (string) listen on ip
- `listen-port`: (integer) listening on port
- `sock-path`: (string) unix socket path
- `tls-support:`: (boolean) to enable, set to true
- `tls-min-version`: (string) min tls version
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `sock-rcvbuf`: (integer) sets the socket receive buffer in bytes SO_RCVBUF, set to zero to use the default system value
- `reset-conn`: (bool) Reset TCP connection on exit
- `chan-buffer-size`: (integer) channel buffer size used on incoming packet, number of packet before to drop it.
- `disable-dnsparser"`: (bool) disable the minimalist DNS parser

Default values:

```yaml
dnstap:
  listen-ip: 0.0.0.0
  listen-port: 6000
  sock-path: null
  tls-support: false
  tls-min-version: 1.2
  cert-file: ""
  key-file: ""
  sock-rcvbuf: 0
  reset-conn: true
  chan-buffer-size: 65535
  disable-dnsparser: false
```

## DNS tap Proxifier

Collector that receives DNSTAP traffic and relays it without decoding or transformations.
This collector must be used with the DNStap logger.

Dnstap stream collector can be a tcp or unix socket listener. TLS is also supported.

For config examples, take a look to the following [one](../_examples/use-case-12.yml)

Options:

- `listen-ip`: (string) listen on ip
- `listen-port`: (integer) listening on port
- `sock-path`: (string) unix socket path
- `tls-support:`: (boolean) to enable, set to true
- `tls-min-version`: (string) min tls version
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file

Default values:

```yaml
dnstap-relay:
  listen-ip: 0.0.0.0
  listen-port: 6000
  sock-path: null
  tls-support: false
  tls-min-version: 1.2
  cert-file: ""
  key-file: ""
```
