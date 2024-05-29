# DNS-collector - Running mode

- [Pipelining](#pipelining)
- [Multiplexer](#multiplexer)

## Pipelining

The `pipelining` mode offers several enhancements regarding the old one (multiplexer).
You can do exactly the same but with more flexibility:

- a simplified syntax,
- conditional statement-based log routing, dropped packet can be send to another stanza
- flexibility to add metadata in DNS messages.

With this mode you can create pipeline and connect [collectors](./collectors.md) and [loggers](./loggers.md) with the `routing-policy` definition.

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


## Multiplexer (DEPRECATED)

> NOTE: THIS MODE IS DEPRECATED

The dns collector can be configured with multiple loggers and collectors at the same time.

You must defined the list of

- `collectors`: list of running inputs
- `loggers`: list of running outputs
- `routes`: routing definition

List of supported [collectors](./collectors.md)

```yaml
multiplexer:
  collectors: 
    - name: <collector_name>
      .....
```

List of supported [loggers](./loggers.md)

```yaml
multiplexer:
  loggers: 
    - name: <logger_name>
      ...
```

Defines the routing to use between all of them according to the name.
You can connect one collector to multiple loggers and you can also
connect multiple collectors to the same logger.

```yaml
multiplexer:
  routes: ...
    - from: [ list of collectors by name ]
      to: [ list of loggers by name ]
```
