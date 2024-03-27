# Transformer: Normalize

This transformer can be used:

- to convert all domain to lowercase. For example: `Wwww.GooGlE.com` will be equal to `www.google.com`
- to add top level domain. For example for `books.amazon.co.uk`, the `TLD`
is `co.uk` and the `TLD+1` is `amazon.co.uk`.
- to use small text form. For example: `CLIENT_QUERY` will be replaced by `CQ`

Options:

- `qname-lowercase` (boolean)
  > enable or disable lowercase

- `add-tld` (boolean)
  > add top level domain

- `add-tld-plus-one` (boolean)
  > add top level domain plus one label

- `quiet-text` (boolean)
  > Quiet text mode to reduce the size of the logs

```yaml
transforms:
  normalize:
    qname-lowercase: true
    add-tld: false
    add-tld-plus-one: false
    quiet-text: false
```

The following dnstap flag message will be replaced with the small form:

- AUTH_QUERY: `AQ`
- AUTH_RESPONSE: `AR`
- RESOLVER_QUERY: `RQ`
- RESOLVER_RESPONSE: `RR`
- CLIENT_QUERY: `CQ`
- CLIENT_RESPONSE: `CR`
- FORWARDER_QUERY: `FQ`
- FORWARDER_RESPONSE: `FR`
- STUB_QUERY: `SQ`
- STUB_RESPONSE: `SR`
- TOOL_QUERY: `TQ`
- TOOL_RESPONSE: `TR`

The following dns flag message will be replaced with the small form:

- QUERY: `Q`
- REPLY: `R`

If one of add-tld  options is enable then the following json field are populated in your DNS message:

Example:

```json
"publicsuffix": {
  "etld+1": "eu.org",
  "tld": "org",
  "managed-icann": true
}
```

Specific directives added for text format:

- `publicsuffix-tld`: [Public Suffix](https://publicsuffix.org/) of the DNS QNAME
- `publicsuffix-etld+1`: [Public Suffix](https://publicsuffix.org/) plus one label of the DNS QNAME
- `publicsuffix-managed-icann`: [Public Suffix](https://publicsuffix.org/) flag for managed icann domains
