# Transformer: Relabeling

Use this transformer to remove or rename some JSON keys.
This transformation is only applied to the [`flat-json`](../dnsjson.md#flat-json-format-recommended) output format.

Options:

* `rename` (list)
  > A list key to rename

* `remove` (list)
  > A list of key to remove

Configuration example

```yaml
- name: console
  stdout:
    mode: flat-json
  transforms:
    relabeling:
      rename:
        - regex: "dnstap\\.timestamp-rfc3339ns"
          replacement: "timestamp"
        - regex: "dns\\.qname"
          replacement: "query"
        - regex: "network\\.query-ip"
          replacement: "client"
        - regex: "network\\.response-ip"
          replacement: "server"
        - regex: "dnstap\\.identity"
          replacement: "client_id"
        - regex: "^dns\\.resource-records\\.an\\..*\\.rdata$"
          replacement: "answers_rdata"
      remove:
        - regex: "dns"
        - regex: "network"
```

This config produces the following flat-json ouput:

Query:

```json
{
  "client": "192.168.1.210",
  "client_id": "dnsdist1",
  "query": "www.google.co",
  "server": "192.168.1.210",
  "timestamp": "2024-03-10T19:58:30.881076563Z"
}
```

Reply:

```json
{
  "answers_rdata": [
    "172.217.20.206",
    "www3.l.google.com"
  ],
  "client": "192.168.1.210",
  "client_id": "dnsdist1",
  "query": "www.google.co",
  "server": "192.168.1.210",
  "timestamp": "2024-03-10T19:58:30.903063148Z"
}
```
