# Collector: Protobuf PowerDNS

Collector to logging protobuf streams from PowerDNS servers. The DNS-collector has a full [Protobuf Logging](https://dnsdist.org/reference/protobuf.html) support for PowerDNS's products.

Settings:

- `listen-ip` (str) local address to bind to. Defaults to `0.0.0.0`.
  > Set the local address that the server will bind to. If not provided, the server will bind to all available network interfaces (0.0.0.0).
- `listen-port` (int) local port to bind to. Defaults to `6001`.
  > Set the local port that the server will listen on. If not provided, the default port is 6001.
- `tls-support` (bool) set to true to enable TLS. Defaults to `false`.
  > Enables or disables TLS (Transport Layer Security) support. If set to true, TLS will be used for secure communication.
- `tls-min-version` (str) Minimun TLS version to use. Default to `1.2`.
  > Specifies the minimum TLS version that the server will support.
- `cert-file` (str) path to a certificate server file to use. Default to `(empty)`.
  > Specifies the path to the certificate file to be used for TLS. This is a required parameter if TLS support is enabled.
- `key-file`(str) path to a key server file to use. Default to `(empty)`.
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.
- `sock-rcvbuf` (int) sets the socket receive buffer in bytes SO_RCVBUF. Default to `0`.
  > Set to zero to use the default system value.
- `reset-conn` (bool) reset TCP connection on exit. Default to `true`.
  > Set whether to send a TCP Reset to force the cleanup of the connection on the remote side when the server exits.
- `chan-buffer-size` (int) incoming channel size, number of packet before to drop it. Default to `65535`.
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.
- `add-dns-payload` (bool) generate and add fake DNS payload. Default to `false`.
  > PowerDNS protobuf message does not contain a DNS payload; use this setting to add a fake DNS payload.

## Custom text format

If you logs your DNS traffic in basic text format, you can use the specific directives:

- `powerdns-tags[:INDEX]`: get all tags separated by comma, or the tag according to the provided INDEX
- `powerdns-original-request-subnet`: get original request subnet like edns subclient
- `powerdns-applied-policy`: get applied policy
- `powerdns-applied-policy-hit`: get applied policy hit
- `powerdns-applied-policy-kind`: get applied policy kind
- `powerdns-applied-policy-trigger`: get applied policy trigger
- `powerdns-applied-policy-type`: get applied policy type
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
    "applied-policy": "rpzbasic",
    "applied-policy-hit": "local-a.org",
    "applied-policy-kind": "Custom",
    "applied-policy-trigger": "local-a.org.",
    "applied-policy-type": "QNAME",
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
