
# Logger: Scalyr client

Client for the Scalyr/DataSet [`addEvents`](https://app.eu.scalyr.com/help/api#addEvents) API endpoint.

Options:
- `server-url`: (string) Scalyr API Host
- `apikey`: (string, required) API Token with Log Write permissions
- `mode`: (string) text, json, or flat-json
- `parser`: (string) When using text or json mode, the name of the parser Scalyr should use
- `flush-interval`: (integer) flush batch every X seconds
- `batch-size`: (integer) batch size for log entries in bytes
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `proxy-url`: (string) Proxy URL
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version
- `session-info`: (map) Any "session" or server information for Scalyr. e.g. 'region', 'serverHost'. If 'serverHost' is not included, it is set using the hostname.
- `attrs`: (map) Any extra attributes that should be added to the log's fields.

The client can send the data in 3 formats: text (using `text-format`), json (by including the whole DNS message in the `message` field), or flat-json.
The first two formats (text, json) require setting the `parser` option and needs a corresponding parser defined in the Scalyr backend.
As Scalyr's JSON parsers (like 'dottedJSON') will not expand nested JSON and require one or more 'rewrite' statements, the Scalyr client supports a `flat-json` mode.

Defaults:
```yaml
scalyrclient:
  server-url: app.scalyr.com
  apikey: ""
  mode: text
  text-format: "timestamp-rfc3339ns identity operation rcode queryip queryport family protocol length qname qtype latency"
  sessioninfo: {}
  attrs: {}
  parser: ""
  flush-interval: 30
  proxy-url: ""
  tls-insecure: false
  tls-min-version: 1.2
```
