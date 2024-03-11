# Transformer: Relabeling

Use this transformer to remove or rename some JSON keys.
Only works on [`flat-json`](../dnsjson.md) output format.

Configuration example

```yaml
  loggers:
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