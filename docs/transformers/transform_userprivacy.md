# Transformer: User Privacy

Use this feature to protect user privacy. This feature can be used to anonymize all IP queries and reduce all qnames to second level.
For example:

- QueryIP 8.8.8.8 will be replaced by 8.8.0.0. IP-Addresses are anonymities by zeroing the host-part of an address.
- Qname mail.google.com be replaced by google.com

Options:

- `anonymize-ip`: (boolean) enable or disable anomymiser ip
- `hash-ip`: (boolean) hash query and response IP with sha1
- `minimaze-qname`: (boolean) keep only the second level domain

```yaml
transforms:
  user-privacy:
    anonymize-ip: false
    hash-ip: false
    minimaze-qname: false
```