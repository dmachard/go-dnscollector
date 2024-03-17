
# Transformer: Data Extractor

Use this transformer to extract the raw dns payload encoded in base64:

Options:

- `add-payload`: (boolean) add base64 encoded dns payload

Default:

```yaml
transforms:
  extract:
    add-payload: false
```

Specific directive(s) available for the text format:

- `extracted-dns-payload`: add the base64 encoded of the dns message

When the feature is enabled, an "extracted" field appears in the DNS message and is populated with a "dns_payload" field:

```json
{
    "extracted": {
      "dns_payload":"P6CBgAABAAEAAAABD29yYW5nZS1zYW5ndWluZQJmcgAAAQABwAwAAQABAABUYAAEwcvvUQAAKQTQAAAAAAAA"
      }
}
```
