# DNS-collector - Running mode

- [Multiplexer](#multiplexer)
  - [Collectors](#collectors)
  - [Loggers](#loggers)
  - [Routes](#routes)

## Pipelining

> EXPERIMENTAL

## Multiplexer

The dns collector can be configured with multiple loggers and collectors at the same time.

You must defined the list of

- `collectors`: list of running inputs
- `loggers`: list of running outputs
- `routes`: routing definition

### Collectors

List of supported [collectors](./collectors.md)

```yaml
multiplexer:
  collectors: 
    - name: <collector_name>
      .....
```

### Loggers

List of supported [loggers](./loggers.md)

```yaml
multiplexer:
  loggers: 
    - name: <logger_name>
      ...
```

### Routes

Then defines the routing to use between all of them according to the name.
You can connect one collector to multiple loggers and you can also
connect multiple collectors to the same logger.

```yaml
multiplexer:
  routes: ...
    - from: [ list of collectors by name ]
      to: [ list of loggers by name ]
```

