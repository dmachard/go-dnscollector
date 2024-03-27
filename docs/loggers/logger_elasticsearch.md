
# Logger: ElasticSearch client

ElasticSearch client to remote ElasticSearch server

Options:

- `server` (string)
  > Elasticsearch server url.
  > Specify the URL of your Elasticsearch server.

- `index` (string)
  > Elasticsearch index.
  > Define the name of the Elasticsearch index to use.

- `bulk-size` (integer)
  > Bulk size to be used for bulk batches in bytes.
  > Set the maximum size of each bulk batch before sending it to Elasticsearch.

- `bulk-channel-size` (integer)
  > Maximum number of bulk messages in buffer.
  > Specifies the maximun number of bulk messages in buffer before to drop it.

- `compression`  (string)
  > Compression for bulk messages: `none`, `gzip`.
  > Specifies the compression algorithm to use.

- `chan-buffer-size` (integer)
  > Channel buffer size used on incoming dns message, number of messages before to drop it.
  > Adjust the size of the channel buffer. If you encounter the error message buffer is full, xxx packet(s) dropped, consider increasing this parameter to prevent message drops.

- `flush-interval` (integer)
  > Interval in seconds before to flush the buffer.
  > Set the maximum time interval before the buffer is flushed. If the bulk batches reach this interval before reaching the maximum size, they will be sent to Elasticsearch.

Defaults:

```yaml
- name: elastic
  elasticsearch:
    server: "http://127.0.0.1:9200/"
    index:  "dnscollector"
    chan-buffer-size: 4096
    bulk-size: 1048576 # 1MB
    flush-interval: 10 # in seconds
    compression: none
    bulk-channel-size: 10
```
