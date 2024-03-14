# Transformer: ATags

Use this transformer to add additional flag in your DNS logs.

Configuration example:

```yaml
- name: filter
    dnsmessage:
    matching:
        include:
        dns.qname: "^.*\\.google\\.com$"
    transforms:
    atags:
        tags: [ "google"]
    routing-policy:
    dropped: [ outputfile ]
    default: [ central ]
```
