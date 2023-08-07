
# Logger: ElasticSearch client

ElasticSearch client to remote ElasticSearch server

Options:
- `url`: (string) Elasticsearch _doc url
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.

```yaml
elasticsearch:
  url: "http://127.0.0.1:9200/indexname/_doc"
  chan-buffer-size: 65535
```
