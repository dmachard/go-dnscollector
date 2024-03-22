# Performance tuning

All loggers and collectors are based on buffered channels.
The size of these buffers can be configured with `chan-buffer-size`.
If you encounter the following error message in your logs, it indicates that you need to increase the chan-buffer-size:

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
BenchmarkDnsMessage_ToTextFormat-4               2555529             450.2 ns/op              80 B/op          4 allocs/op
BenchmarkDnsMessage_ToPacketLayer-4              1138892             952.0 ns/op            1144 B/op         12 allocs/op
BenchmarkDnsMessage_ToDNSTap-4                   1036468              1136 ns/op             592 B/op         18 allocs/op
BenchmarkDnsMessage_ToExtendedDNSTap-4            612438              1970 ns/op            1056 B/op         25 allocs/op
BenchmarkDnsMessage_ToJSON-4                      188379              6724 ns/op            3632 B/op          3 allocs/op
BenchmarkDnsMessage_ToFlatten-4                   121525             10151 ns/op            8215 B/op         29 allocs/op
BenchmarkDnsMessage_ToFlatJSON-4                   20704             58365 ns/op           22104 B/op        220 allocs/op
```

## Memory usage

The main sources of memory usage in DNS-collector are:

- Buffered channels
- Prometheus logger with LRU cache
