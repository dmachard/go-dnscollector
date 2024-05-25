# Collector: DNSMessage

Collector to match specific DNS messages.

Options:

* `matching` (map)
    * `include` (map)
    > Defines the list of fields (flat-json) which must be present in the DNS message (regex are supported).

    * `exclude` (map)
    > Defines the list of fields (flat-json) which must not be present in the DNS message (regex are supported).

For each fields, the advanced settings can be  used:
* `greater-than` (int) 
> Enable to match an integer value greater than the provided value.

* `match-source` (string) 
>  This specifies a URL or local file containing a list of strings to match string field

* `source-kind` (string) 
> This indicates that the `match-source`  is a list of strings or a list of regular expressions.
> expected values: `regexp_list`, `string_list`

Below a advanced example:

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
```