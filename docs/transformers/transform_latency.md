
# Transformer: Latency Computing

Use this feature to compute latency and detect queries timeout

Options:

- `measure-latency` (boolean)
  > measure latency between replies and queries

- `unanswered-queries` (boolean)
  > Detect evicted queries

- `queries-timeout` (integer)
  > timeout in second for queries

```yaml
transforms:
  latency:
    measure-latency: false
    unanswered-queries: false
    queries-timeout: 2
```

Example of DNS messages in text format

- **latency**

```bash
2023-04-11T18:23:45.564128Z unbound CLIENT_QUERY NOERROR 127.0.0.1 35255 IPv4 UDP 50b google.fr A 0.000000
2023-04-11T18:23:45.56424Z unbound FORWARDER_QUERY NOERROR 0.0.0.0 34329 IPv4 UDP 38b google.fr A 0.000000
2023-04-11T18:23:45.57501Z unbound FORWARDER_RESPONSE NOERROR 0.0.0.0 34329 IPv4 UDP 54b google.fr A 0.010770
2023-04-11T18:23:45.575113Z unbound CLIENT_RESPONSE NOERROR 127.0.0.1 35255 IPv4 UDP 54b google.fr A 0.010985
```

- **unanswered queries**

```bash
2023-04-11T18:42:50.939138364Z dnsdist1 CLIENT_QUERY NOERROR 127.0.0.1 52376 IPv4 UDP 54b www.google.fr A 0.000000
2023-04-11T18:42:50.939138364Z dnsdist1 CLIENT_QUERY TIMEOUT 127.0.0.1 52376 IPv4 UDP 54b www.google.fr A -
```
