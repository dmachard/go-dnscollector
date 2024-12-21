# Transformer: Reordering

Use this transformer to reorder DNS messages based on their timestamp. This can be useful when processing logs that may not be ordered correctly, ensuring they are sorted before further processing.

The transformer buffers DNS messages and periodically flushes them based on a configurable interval. The messages are sorted by timestamp before being passed to the next workers.

Options:

* `flush-interval` (int)
  > Defines the interval (in seconds) at which the buffer will be flushed automatically. A smaller value will lead to more frequent flushing.

* `max-buffer-size` (int)
  > Defines the maximum number of messages that can be buffered before the transformer triggers a flush. Once this limit is reached, the buffer will be flushed regardless of the flush interval.

```yaml
transforms:
  reordering:
    flush-interval: 30
    max-buffer-size: 100
```