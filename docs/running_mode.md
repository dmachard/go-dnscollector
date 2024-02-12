# DNS-collector - Running mode

- [Pipelining](#pipelining)
- [Multiplexer](#multiplexer)

## Pipelining

> NOTE: EXPERIMENTAL, NOT YET SUITABLE FOR PRODUCTION

The `pipelining` mode is akin to the multiplexer but offers several enhancements:

- a simplified syntax,
- conditional statement-based log routing,
- flexibility to add metadata.

With this mode you can create pipeline with supported [collectors](./collectors.md) and [loggers](./loggers.md).

```yaml
pipelines:
  - name: <collector1_name>
    .....
    routing-policy:
      default: [ <collector2_name> ]

  - name: <collector2_name>
    .....
```

## Multiplexer

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
