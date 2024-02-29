
# Logger: ElasticSearch client

ElasticSearch client to remote ElasticSearch server

Options:

- `server`: (string) Elasticsearch server url
- `index`: (string) Elasticsearch index
- `bulk-size`: (integer) Bulk size to be used for bulk batches in bytes
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it
- `flush-interval`: (integer) interval in seconds before to flush the buffer

```yaml
elasticsearch:
  server: "http://127.0.0.1:9200"
  index:  "dnscollector"
  bulk-size: 1048576
  chan-buffer-size: 2048
  flush-interval: 10
```
