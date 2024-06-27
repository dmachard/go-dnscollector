# Transformer: Rewrite

Use this transformer to rewrite the content of DNS messages [structure](../dnsjson.md#dns-collector---json-encoding).

Options:

* `identifiers` (map)
  > Expect a key/value where the key is the namf of the field to rewrite (Please refer  to the [`flat-json`](../dnsjson.md#flat-json-format-recommended) output to see all identifiers keys ) and the value is the new one.

Config example to remove the DNStap version and update the identity name.

```yaml
- name: tap
dnstap:
    listen-ip: 0.0.0.0
    listen-port: 6000
transforms:
    rewrite:
    identifiers:
        dnstap.version: ""
        dnstap.identity: "foo"
```