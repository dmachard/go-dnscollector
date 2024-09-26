# Transformer: Rewrite

Use this transformer to rewrite the content of DNS messages according to the [structure](../dnsjson.md#dns-collector---json-encoding).
For more details, see the feature request [here](https://github.com/dmachard/go-dnscollector/issues/527).

> Only fields with int and string types are supported.

Options:

* `identifiers` (map)
  > Expect a key/value where the key is the name of the field to rewrite (Please refer  to the [`flat-json`](../dnsjson.md#flat-json-format-recommended) output to see all identifiers keys ) and the value is the new one.

Config example to remove the DNStap version and update the identity name.

```yaml
transforms:
  rewrite:
    identifiers:
      dnstap.version: ""
      dnstap.identity: "foo"
```
