# Transformer: Traffic Filtering

The filtering feature can be used to ignore some queries or replies according to:

- qname
- return code
- query ip
- sampling rate

This feature can be useful to increase logging performance..

Options:

- `drop-fqdn-file`: (string) path file to a fqdn drop list, domains list must be a full qualified domain name
- `drop-domain-file`: (string) path file to domain drop list, domains list can be a partial domain name with regexp expression
- `keep-fqdn-file`: (string) path file to a fqdn keep list (all others are dropped), domains list must be a full qualified domain name
- `keep-domain-file`: (string) path file to domain keep list (all others are dropped), domains list can be a partial domain name with regexp expression
- `drop-queryip-file`: (string) path file to the query ip or ip prefix drop list
- `keep-queryip-file`: (string) path file to the query ip or ip prefix keep list, addresses in both drop and keep are always kept
- `drop-rcodes`: (list of string) rcode list, empty by default
- `log-queries`: (boolean) drop all queries on false
- `log-replies`: (boolean)  drop all replies on false
- `downsample`: (integer) only keep 1 out of every `downsample` records, e.g. if set to 20, then this will return every 20th record, dropping 95% of queries

Default values:

```yaml
transforms:
  filtering:
    drop-fqdn-file: ""
    drop-domain-file: ""
    keep-fqdn-file: ""
    keep-domain-file: ""
    drop-queryip-file: ""
    keep-queryip-file: ""
    drop-rcodes: []
    log-queries: true
    log-replies: true
    downsample: 0
```

Domain list with regex example:

```bash
(mail|wwww).google.com
github.com
```
