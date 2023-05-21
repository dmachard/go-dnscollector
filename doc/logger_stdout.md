# Logger: Stdout

Print to your standard output, all DNS logs received
* in text or json format
* custom text format

Options:
- `mode`: (string) output format: text, json, or flat-json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
stdout:
  mode: text
  text-format: ""
  chan-buffer-size: 65535
```

Example:

```
2021-08-07T15:33:15.168298439Z dnscollector CQ NOERROR 10.0.0.210 32918 INET UDP 54b www.google.fr A 0.000000
2021-08-07T15:33:15.457492773Z dnscollector CR NOERROR 10.0.0.210 32918 INET UDP 152b www.google.fr A 0.28919
```
