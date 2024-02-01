# Collector: Protobuf PowerDNS

Collector to logging protobuf streams from PowerDNS servers.

Options:

- `listen-ip`:
  - string
  - default: 0.0.0.0
  
> Local address to bind to

- `listen-port`: (integer) listening on port
  > default value to `6001`
- `tls-support:`: (boolean) to enable, set to true
  > default value to `false`
- `tls-min-version`: (string) min tls version
  > default value to `1.2`
- `cert-file`: (string) certificate server file to use
  > default value is empty
- `key-file`: (string) private key server file to use
  > default value is empty
- `sock-rcvbuf`: (integer) sets the socket receive buffer in bytes SO_RCVBUF, set to zero to use the default system value
  > default value to `0`
- `reset-conn`: (bool) Reset TCP connection on exit
  > default value to `true`
- `chan-buffer-size`: (integer) channel buffer size used on incoming packet, number of packet before to drop it.
  > default value to `65535`
- `add-dns-payload`: (boolean) generate and add fake DNS payload
  > default value to `false`

The DNS-collector has a full [Protobuf Logging](https://dnsdist.org/reference/protobuf.html) support for PowerDNS's products.

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
