# Logger: Stdout

Print to your standard output, all DNS logs received

* in text or json format
* custom text format
* binary mode (pcap)

Options:

* `mode` (string)
  > output format: `text`, `json`, `flat-json` or `pcap`

* `text-format` (string)
  > output text format, please refer to the default text format to see all available [directives](../configuration.md#custom-text-format), use this parameter if you want a specific format

* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Default values:

```yaml
stdout:
  mode: text
  text-format: ""
  chan-buffer-size: 0
```

Example:

```bash
2021-08-07T15:33:15.168298439Z dnscollector CQ NOERROR 10.0.0.210 32918 INET UDP 54b www.google.fr A 0.000000
2021-08-07T15:33:15.457492773Z dnscollector CR NOERROR 10.0.0.210 32918 INET UDP 152b www.google.fr A 0.28919
```
