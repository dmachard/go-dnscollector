# DNS-collector - Extended DNStap

If this feature is enabled, DNScollector will extend the DNStap protocol by incorporating additional metadata added through transformations, such as filtering, geo, ATags.
These metadata are encoded in the extra field with the following [protobuf structure](./../../dnsutils/extended_dnstap.proto).

This feature can be only used between two `DNS-collector` instance.

How to enable it on the collector side ?

```yaml
- name: dnstap_collector
  dnstap:
   extended-support: true
```

How to enable it on the sender side ?

```yaml
- name: dnstap_sender
  dnstapclient:
   extended-support: true
```
