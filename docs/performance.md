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
BenchmarkDnsMessage_ToTextFormat-4               2600718             460.7 ns/op
BenchmarkDnsMessage_ToPacketLayer-4              1171467             969.5 ns/op
BenchmarkDnsMessage_ToDNSTap-4                    993242              1130 ns/op
BenchmarkDnsMessage_ToExtendedDNSTap-4            618400              1951 ns/op
BenchmarkDnsMessage_ToJSON-4                      190939              6584 ns/op
BenchmarkDnsMessage_ToFlatJSON-4                   19868             55533 ns/op
```

## Memory usage

The main sources of memory usage in DNS-collector are:

- Buffered channels
- Prometheus logger with LRU cache
