# Collector: DNSMessage

Collector to match specific DNS messages.

Options:

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

* `matching` (map)
    * `include` (map)
    > Defines the list of fields (flat-json) which must be present in the DNS message (regex are supported).

    * `exclude` (map)
    > Defines the list of fields (flat-json) which must not be present in the DNS message (regex are supported).


The matching functionality support any type of values. For each fields, the advanced settings can be  used:
* `greater-than` (int) 
> Enable to match an integer value greater than the provided value.

* `match-source` (string) 
>  This specifies a URL or local file containing a list of strings to match string field

* `source-kind` (string) 
> This indicates that the `match-source`  is a list of strings or a list of regular expressions.
> expected values: `regexp_list`, `string_list`


To match specific answers only with a TTL greater than 300 and RDATA equal to a list of IPs.

```yaml
include:
  dns.resource-records.an.*.ttl:
    greater-than: 300
  dns.resource-records.an.*.rdata:
    - "^142\\.250\\.185\\.(196|132)$"
    - "^143\\.251\\.185\\.(196|132)$"
```
Second example to match a tag at position 0

```yaml
include:
  atags.tags.0: "TXT:apple"
```

Finally a complete full example:

```yaml
  - name: filter
    dnsmessage:
      matching:
        include:
          dns.flags.qr: false
          dns.opcode: 0
          dns.length:
            greater-than: 50
          dns.qname:
            match-source: "file://./testsdata/filtering_keep_domains_regex.txt"
            source-kind: "regexp_list"
          dnstap.operation:
            match-source: "http://127.0.0.1/operation.txt"
            source-kind: "string_list"
        exclude:
          dns.qtype: [ "TXT", "MX" ]
          dns.qname:
            - ".*\\.github\\.com$"
            - "^www\\.google\\.com$"
    transforms:
      atags:
        tags: [ "TXT:apple", "TXT:google" ]
    routing-policy:
      dropped: [ outputfile ]
      default: [ console ]
```