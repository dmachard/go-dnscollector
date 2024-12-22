# DNS-collector - Enhanced DNStap

The DNScollector adds enhancements to the DNStap protocol with compression, TLS and extended metadata support.
These features can be only used between two `DNS-collector` instance.

## Compression

> ref: https://github.com/dmachard/go-dnscollector/issues/490

DNSTAP messages are highly compressible. They can be sent in reasonably large blocks, which enables significant compression for transmission over long-haul network links. While DNSTAP does not natively support compression, it seems not unreasonable that `DNS-collector` could have a configurable compression flag that would mark a stream as being compressed with one of the different models of compression that are supported in other areas of the code currently. This would allow a much more efficient transmission of DNSTAP-based messages through various components.

The following codec are supported:

- gzip
- lz4
- snappy
- std

## Extended metadata

DNSTAP message can be extended by incorporating additional metadata added through transformations, such as filtering, geo, ATags.

These metadata are encoded in the extra field with the following [protobuf structure](../dnsutils/extended_dnstap.proto).

The following transformers are supported:

- atags
- filtering
- normalize
- geoip

## TLS encryption

DNSTAP messages contains sensitive data. `DNS-collector` have a configurable flag to enable TLS encryption.

## Configuration

How to enable it on the collector side ?

```yaml
- name: dnstap_collector
  dnstap:
   extended-support: true
   compression: gzip
   tls-support: true
```

How to enable it on the sender side ?

```yaml
- name: dnstap_sender
  dnstapclient:
   extended-support: true
   compression: gzip
   transport: tcp+tls
```
