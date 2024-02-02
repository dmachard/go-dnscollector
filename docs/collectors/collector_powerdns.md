# Collector: Protobuf PowerDNS

Collector to logging protobuf streams from PowerDNS servers. The DNS-collector has a full [Protobuf Logging](https://dnsdist.org/reference/protobuf.html) support for PowerDNS's products.

Settings:

- `listen-ip` (String) Local address to bind to. Defaults to `0.0.0.0`.
- `listen-port` (Integer) Local port to bind to. Defaults to `6001`.
- `tls-support:` (Boolean) Set to true to enable TLS. Defaults to `false`.
- `tls-min-version` (String) Minimun TLS version to use. Default to `1.2`.
- `cert-file` (String) path to a certificate server file to use. Default to `(empty)`.
- `key-file`(String) path to a key server file to use. Default to `(empty)`.
- `sock-rcvbuf` (Integer) Sets the socket receive buffer in bytes SO_RCVBUF. Default to `0`. Set to zero to use the default system value.
- `reset-conn` (Boolean) Reset TCP connection on exit. Default to `true`.
- `chan-buffer-size` (Integer) Channel buffer size used on incoming packet, number of packet before to drop it. Default to `65535`.
- `add-dns-payload` (Boolean) Generate and add fake DNS payload. Default to `false`.

## Custom text format

If you logs your DNS traffic in basic text format, you can use the specific directives:

- `powerdns-tags[:INDEX]`: get all tags separated by comma, or the tag according to the provided INDEX
- `powerdns-original-request-subnet`: get original request subnet like edns subclient
- `powerdns-applied-policy`: get applied policy
- `powerdns-metadata[:KEY]`: get  all metadata separated by comma or specific one if a valid [KEY](https://dnsdist.org/rules-actions.html#RemoteLogAction) is provided

Configuration example:

```ini
- name: console
  stdout:
    mode: text
    text-format: "timestamp-rfc3339ns identity qr qname qtype powerdns-metadata:selected_pool"
```

## JSON format

If you logs your DNS traffic in JSON output, the following part will be added in your DNS logging messages.

```json
  "powerdns": {
    "tags": [],
    "original-request-subnet": "",
    "applied-policy": "",
    "metadata": {
        "agent":"Go-http-client/1.1",
        "selected_pool":"pool_internet"
    }
  }
```

## Dnsdist configuration

Example to enable logging in your **dnsdist**

```lua
rl = newRemoteLogger("<dnscollectorip>:6001")

local metadata = {  selected_pool='pool',  agent='doh-header:user-agent'  }

addAction(AllRule(),RemoteLogAction(rl, nil, {serverID="dnsdist"}, metadata))
addResponseAction(AllRule(),RemoteLogResponseAction(rl, nil, true, {serverID="dnsdist"}, metadata))
addCacheHitResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, true, {serverID="dnsdist"}, metadata))
```

## PDNS-recursor configuration

Example to enable logging in your **pdns-recursor**

*/etc/pdns-recursor/recursor.conf*

```lua
lua-config-file=/etc/pdns-recursor/recursor.lua
```

*****/etc/pdns-recursor/recursor.lua*

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
