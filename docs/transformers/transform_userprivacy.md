# Transformer: User Privacy

Use this feature to protect user privacy. This feature can be used to anonymize all IP queries and reduce all qnames to second level.
For example:

- QueryIP 8.8.8.8 will be replaced by 8.8.0.0. IP-Addresses are anonymities by zeroing the host-part of an address.
- Qname mail.google.com be replaced by google.com

Options:

* `anonymize-ip` (boolean)
  > enable or disable anomymiser ip

* `anonymize-v4bits` (string)
  > summarize IPv4 down to the /integer level, default is `/16`

* `anonymize-v6bits` (string)
  > summarize IPv6 down to the /integer level, default is `::/64`

* `hash-query-ip` (boolean)
  > hashes the query IP with the specified algorithm.

* `hash-reply-ip` (boolean)
  > hashes the response IP with the specified algorithm.

* `hash-ip-algo` (string)
  > algorithm to use for IP hashing, currently supported `sha1` (default), `sha256`, `sha512`

* `minimaze-qname` (boolean)
  > keep only the second level domain

```yaml
transforms:
  user-privacy:
    anonymize-ip: false
    anonymize-v4bits: "/16"
    anonymize-v6bits: "::/64"
    hash-query-ip: false
    hash-reply-ip: false
    hash-ip-algo: "sha1"
    minimaze-qname: false
```
