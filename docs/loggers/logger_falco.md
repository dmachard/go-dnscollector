# Logger: Falco

Falco plugin Logger - Currently available here https://github.com/SysdigDan/dnscollector-falco-plugin

Options:

* `url` (string)
  > Falco Plugin endpoint url "http://127.0.0.1:9200"

* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Default values:

```yaml
falco:
  url: "http://127.0.0.1:9200/events"
  chan-buffer-size: 0
```
