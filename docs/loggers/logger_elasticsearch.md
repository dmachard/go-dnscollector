
# Logger: ElasticSearch client

ElasticSearch client to remote ElasticSearch server

Options:
- `server`: (string) Elasticsearch server url
- `index`: (string) Elasticsearch index
- `bulk-size`: (integer) Bulk size to be used for bulk batches
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it

```yaml
elasticsearch:
  server: "http://127.0.0.1:9200"
  index:  "indexname"
  bulk-size: 100
  chan-buffer-size: 65535
```
