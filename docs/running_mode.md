# DNS-collector - Running mode

The DNScollector can be configured to operate with multiple loggers and collectors simultaneously, 
allowing for versatile logging and data collection strategies.

## Pipelining

The `pipelining` mode offers several enhancements compared to the old multiplexer mode. 
It provides the same functionalities with added flexibility:

- **Simplified Syntax**: Easier to read and maintain configuration files.
- **Conditional Log Routing**: Dropped packets can be directed to alternative processing stanzas.
- **Metadata Enrichment**: Ability to attach metadata to DNS messages for enhanced logging and analysis.

With this mode, you can create pipelines and connect [collectors](./collectors.md) and [loggers](./loggers.md) using the new `routing-policy` definition.


## Routing Policy Modes

The routing policy supports two modes:
- forward: A list of stanzas where packets that are successfully processed will be sent.
- dropped: A list of stanzas where packets that are dropped or failed will be redirected.

This flexible routing mechanism allows you to implement tailored logging strategies based on specific conditions and processing outcomes.

## Example Configuration

```yaml
pipelines:
  - name: <stanza1>
    # Configuration for collector or logger
    ...(collector or logger config)..
    routing-policy:
      forward: [ <logger1> ]  # Specify loggers for forwarded packets
      dropped: [ <logger2> ]  # Specify loggers for dropped packets

  - name: <stanza2>
    # Configuration for another collector or logger
    ...(collector or logger config)..
```

