# DNS-collector - Running mode

The DNScollector can be configured with multiple loggers and collectors at the same time

- [Pipelining](#pipelining)

## Pipelining

The `pipelining` mode offers several enhancements compared to the old multiplexer mode. 
It provides the same functionalities with added flexibility:

- Simplified syntax
- Conditional statement-based log routing: dropped packet can be send to another stanza
- Ability to add metadata in DNS messages.

With this mode, you can create pipelines and connect [collectors](./collectors.md) and [loggers](./loggers.md) using the new `routing-policy` definition.

```yaml
pipelines:
  - name: <stanza1>
    ...(collector or logger config)..
    routing-policy:
      forward: [ <logger1> ]
      dropped: [ <logger2> ]

  - name: <stanza2>
    ...(collector or logger config)..
```

The routing policy support 2 modes:
- `forward`: [ list of next stanza ]
- `dropped`: [ list of next stanza ]
