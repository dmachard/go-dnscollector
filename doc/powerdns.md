# DnsCollector - PowerDNS collector

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

# JSON format

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