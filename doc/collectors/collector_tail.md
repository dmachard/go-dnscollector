# Collector: Tail

The tail collector enable to read DNS event from text files.
DNS servers log server can be followed; any type of server is supported!

* Read DNS events from the tail of text files
* Regex support


Enable the tail by provided the path of the file to follow

Options:

- `file-path`: (string) file to follow
- `time-layout`: (string)  Use the exact layout numbers described https://golang.org/src/time/format.go
- `pattern-query`: (string) regexp pattern for queries
- `pattern-reply`: (string) regexp pattern for replies

Default values:

```yaml
tail:
  file-path: null
  time-layout: "2006-01-02T15:04:05.999999999Z07:00"
  pattern-query: "^(?P<timestamp>[^ ]*) (?P<identity>[^ ]*) (?P<qr>.*_QUERY) (?P<rcode>[^ ]*) (?P<queryip>[^ ]*) (?P<queryport>[^ ]*) (?P<family>[^ ]*) (?P<protocol>[^ ]*) (?P<length>[^ ]*)b (?P<domain>[^ ]*) (?P<qtype>[^ ]*) (?P<latency>[^ ]*)$"
  pattern-reply: "^(?P<timestamp>[^ ]*) (?P<identity>[^ ]*) (?P<qr>.*_RESPONSE) (?P<rcode>[^ ]*) (?P<queryip>[^ ]*) (?P<queryport>[^ ]*) (?P<family>[^ ]*) (?P<protocol>[^ ]*) (?P<length>[^ ]*)b (?P<domain>[^ ]*) (?P<qtype>[^ ]*) (?P<latency>[^ ]*)$"
```

