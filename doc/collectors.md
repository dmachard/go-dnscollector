# DnsCollector - Collectors Guide

- [DNS tap](#dns-tap)
- [DNS sniffer](#dns-sniffer)
- [Tail](#tail)
- [Protobuf PowerDNS](#protobuf-powerdns)

## Collectors

### DNS tap

Dnstap stream collector:
* tcp or unix socket listener
* tls support

Options:
- `listen-ip`: (string) listen on ip
- `listen-port`: (integer) listening on port
- `sock-path`: (string) unix socket path
- `tls-support:`: (boolean) to enable, set to true
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `cache-support`: (boolean) disable or enable the cache dns, this feature can be enabled if your dns server doesn't add the latency
- `query-timeout`: (integer) in second, max time to keep the query record in memory
- `quiet-text`: (boolean) Quiet text mode to reduce the size of the logs

```yaml
dnstap:
  listen-ip: 0.0.0.0
  listen-port: 6000
  sock-path: null
  tls-support: false
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

### DNS sniffer

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
- `capture-dns-queries`: (boolean) capture dns queries
- `capture-dns-replies`: (boolean) capture dns replies
- `cache-support`: (boolean) disable or enable the cache dns to compute latency between queries and replies
- `query-timeout`: (integer) in second, max time to keep the query record in memory

```yaml
dns-sniffer:
  port: 53
  device: wlp2s0
  capture-dns-queries: true
  capture-dns-replies: true
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
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file

```yaml
powerdns:
  listen-ip: 0.0.0.0
  listen-port: 6001
  quiet-text: false
  tls-support: false
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