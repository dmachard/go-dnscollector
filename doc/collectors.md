# DnsCollector - Collectors Guide

- [DNS tap](#dns-tap)
- [DNStap Proxifier](#dnstap-proxifier)
- [Protobuf PowerDNS](#protobuf-powerdns)
- [Tail](#tail)
- [Live capture](#live-capture)
- [Ingest Pcap](#ingest-pcap)

## Collectors

### DNS tap

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
- `cache-support`: (boolean) disable or enable the cache dns, this feature can be enabled if your dns server doesn't add the latency
- `query-timeout`: (integer) in second, max time to keep the query record in memory
- `quiet-text`: (boolean) Quiet text mode to reduce the size of the logs

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
  cache-support: false
  query-timeout: 5.0
  quiet-text: false
```

The following dnstap flag message will be replaced with the small form:
- AUTH_QUERY: `AQ`
- AUTH_RESPONSE: `AR`
- RESOLVER_QUERY: `RQ`
- RESOLVER_RESPONSE: `RR`
- CLIENT_QUERY: `CQ`
- CLIENT_RESPONSE: `CR`
- FORWARDER_QUERY: `FQ`
- FORWARDER_RESPONSE: `FR`
- STUB_QUERY: `SQ`
- STUB_RESPONSE: `SR`
- TOOL_QUERY: `TQ`
- TOOL_RESPONSE: `TR`

The following dns flag message will be replaced with the small form:
- QUERY: `Q`
- REPLY: `R`

### DNStap Proxifier

Collector that receives DNSTAP traffic and relays it without decoding or transformations.
This collector must be used with the DNStap logger. 
Please to find a complete example [here](./example-config/use-case-12.yml).

Dnstap stream collector can be a tcp or unix socket listener. TLS is also supported.

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

### Live Capture

Raw DNS packets sniffer. Setting `CAP_NET_RAW` capabilities on executables allows you to run these
program without having to run-it with the root user:
* IPv4, IPv6 support (fragmented packet ignored)
* UDP and TCP transport
* BFP filtering

```
sudo setcap cap_net_admin,cap_net_raw=eip go-dnscollector
```

Options:
- `port`: (integer) filter on source and destination port
- `device`: (string) if "" bind on all interfaces
- `drop-queries`: (boolean) drop all queries
- `drop-replies`: (boolean) drop all replies
- `cache-support`: (boolean) disable or enable the cache dns to compute latency between queries and replies
- `query-timeout`: (integer) in second, max time to keep the query record in memory

Default values:

```yaml
sniffer:
  port: 53
  device: wlp2s0
  drop-queries: false
  drop-replies: false
  cache-support: true
  query-timeout: 5.0
```

### Tail

The tail collector enable to read DNS event from text files.
DNS servers log server can be followed; any type of server is supported!
* Read DNS events from the tail of text files
* Regex support


Enable the tail by provided the path of the file to follow

Options:
- `file-path`: (string) file to follow
- `time-layout`: (string)  Use the exact layout numbers described https://golang.org/src/time/format.go
- `pattern-query`: (string) regexp pattern for queries
- `pattern-reply`: (string) regexp pattern for replies

Default values:

```yaml
tail:
  file-path: null
  time-layout: "2006-01-02T15:04:05.999999999Z07:00"
  pattern-query: "^(?P<timestamp>[^ ]*) (?P<identity>[^ ]*) (?P<qr>.*_QUERY) (?P<rcode>[^ ]*) (?P<queryip>[^ ]*) (?P<queryport>[^ ]*) (?P<family>[^ ]*) (?P<protocol>[^ ]*) (?P<length>[^ ]*)b (?P<domain>[^ ]*) (?P<qtype>[^ ]*) (?P<latency>[^ ]*)$"
  pattern-reply: "^(?P<timestamp>[^ ]*) (?P<identity>[^ ]*) (?P<qr>.*_RESPONSE) (?P<rcode>[^ ]*) (?P<queryip>[^ ]*) (?P<queryport>[^ ]*) (?P<family>[^ ]*) (?P<protocol>[^ ]*) (?P<length>[^ ]*)b (?P<domain>[^ ]*) (?P<qtype>[^ ]*) (?P<latency>[^ ]*)$"
```

### Protobuf PowerDNS

[Protobuf Logging](https://dnsdist.org/reference/protobuf.html) support for PowerDNS's products.

Options:
- `listen-ip`: (string) listen on ip
- `listen-port`: (integer) listening on port
- `quiet-text`: (boolean) Quiet text mode to reduce the size of the logs
- `tls-support:`: (boolean) to enable, set to true
- `tls-min-version`: (string) min tls version
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file

Default values:

```yaml
powerdns:
  listen-ip: 0.0.0.0
  listen-port: 6001
  quiet-text: false
  tls-support: false
  tls-min-version: 1.2
  cert-file: ""
  key-file: ""
```

Example to enable logging in your **dnsdist**

```lua
rl = newRemoteLogger("<dnscollectorip>:6001")
addAction(AllRule(),RemoteLogAction(rl, nil, {serverID="dnsdist"}))
addResponseAction(AllRule(),RemoteLogResponseAction(rl, nil, true, {serverID="dnsdist"}))
addCacheHitResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, true, {serverID="dnsdist"}))
```

Example to enable logging in your **pdns-recursor**

*/etc/pdns-recursor/recursor.conf*

```lua
lua-config-file=/etc/pdns-recursor/recursor.lua
```

*/etc/pdns-recursor/recursor.lua*

```lua
protobufServer("<dnscollectorip>:6001", {exportTypes={pdns.A, pdns.AAAA, pdns.CNAME}})
outgoingProtobufServer("<dnscollectorip>:6001")
```

with RPZ

```lua
rpzFile("/etc/pdns-recursor/basic.rpz", {
  policyName="custom",
  tags={"tag"}
})
```

### Ingest Pcap

This collector enable to ingest multiple pcap files by watching a directory.
Make sure the PCAP is complete before moving the file to the directory so that file data is not truncated. 

Options:
- `watch-dir`: (string) directory to watch for pcap files ingest
- `dns-port`: (integer) dns source or destination port
- `drop-queries`: (boolean) drop all queries if enabled
- `drop-replies:`: (boolean) drop all replies if enabled
- `delete-after:`: (boolean) delete pcap file after ingest

Default values:

```yaml
pcap:
  watch-dir: /tmp
  dns-port: 53
  drop-queries: false
  drop-replies: false
  delete-after: false
```
