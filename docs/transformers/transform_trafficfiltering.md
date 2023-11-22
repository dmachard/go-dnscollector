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
- `keep-queryip-file`: (string) path file to the query ip or ip prefix keep list
- `keep-rdataip-file`: (string) path file to the answer ip or ip prefix keep list. If the answer set includes ips both in drop and keep list, an error is thrown
- `drop-rcodes`: (list of string) rcode list, empty by default
- `log-queries`: (boolean) drop all queries on false
- `log-replies`: (boolean)  drop all replies on false
- `downsample`: (integer) set the sampling rate, only keep 1 out of every `downsample` records, e.g. if set to 20, then this will return every 20th record (sampling at 1:20 or dropping 95% of queries).

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
    keep-rdataip-file: ""
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

Specific text directive(s) available for the text format:

- `filtering-samplerate`: display the rate applied

When the feature is activated, the following JSON fields are populated in your DNS message:

```json
{
  "filtering": {
    "sample-rate": 20,
  }
}
```
