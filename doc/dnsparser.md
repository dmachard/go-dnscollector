# DnsCollector - DNS parser

A DNS parser is embedded to extract some informations from queries and replies.

The `UNKNOWN` string is used when the RCODE or RDATATYPES are not supported.

The following Rdatatypes will be decoded, otherwise the `-` value will be used:
- A
- AAAA
- CNAME
- MX
- SRV
- NS
- TXT
- PTR
- SOA