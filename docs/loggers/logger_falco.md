# Logger: Falco

Falco plugin Logger - Currently available here https://github.com/SysdigDan/dnscollector-falco-plugin

Options:

- `url` (string)
  > Falco Plugin endpoint url "http://127.0.0.1:9200"
- `chan-buffer-size` (integer)
  > channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
falco:
  url: "http://127.0.0.1:9200/events"
  chan-buffer-size: 65535
```
