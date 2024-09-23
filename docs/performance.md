# Performance tuning

All loggers and collectors are based on buffered channels.
The size of these buffers can be configured with `buffer-size` in global section.
If you encounter the following warning message in your logs, it indicates that you need to increase the buffer size:

```bash
logger[elastic] buffer is full, 7855 packet(s) dropped
```

## CPU usage

The conversion of DNS logs to JSON, text, or PCAP can incur CPU costs. Here's a list ordered by ns/op.

```bash
./dnsutils$ go test -bench=.
goos: linux
goarch: amd64
pkg: github.com/dmachard/go-dnscollector/dnsutils
cpu: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz 
BenchmarkDnsMessage_ToTextFormat-4               2262946               518.8 ns/op            80 B/op          4 allocs/op
BenchmarkDnsMessage_ToPacketLayer-4              1241736               926.9 ns/op          1144 B/op         12 allocs/op
BenchmarkDnsMessage_ToDNSTap-4                    894579              1464 ns/op             592 B/op         18 allocs/op
BenchmarkDnsMessage_ToExtendedDNSTap-4            608203              2342 ns/op            1056 B/op         25 allocs/op
BenchmarkDnsMessage_ToJSON-4                      130080              7749 ns/op            3632 B/op          3 allocs/op
BenchmarkDnsMessage_ToFlatten-4                   117115              9227 ns/op            8369 B/op         29 allocs/op
BenchmarkDnsMessage_ToFlatJSON-4                   21238             54535 ns/op           20106 B/op        219 allocs/op
BenchmarkDnsMessage_ToFlatten_Relabelling-4        35614             32544 ns/op            8454 B/op         30 allocs/op
BenchmarkDnsMessage_ToJinjaFormat-4                 9840            120301 ns/op           50093 B/op        959 allocs/op
```

## Memory usage

The main sources of memory usage in DNS-collector are:

- Buffered channels
- Prometheus logger with LRU cache
