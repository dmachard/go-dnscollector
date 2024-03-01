# Performance tuning

All loggers and collectors are based on buffered channels.
The size of these buffers can be configured with `chan-buffer-size`.
If you encounter the following error message in your logs, it indicates that you need to increase the chan-buffer-size:

```bash
logger[elastic] buffer is full, 7855 packet(s) dropped
```

## Memory usage

The main sources of memory usage in DNS-collector are:

- Buffered channels
- Prometheus logger with LRU cache
