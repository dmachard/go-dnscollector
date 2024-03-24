# Transformer: ATags

Use this transformer to add additional tags in your DNS logs.

This transformation can be valuable in the `pipeline` mode, where it's possible to match specific traffic. 
In such cases, you can include a tag for identification."

A list of string is expected in the `tag` field.

Configuration example:

```yaml
transforms:
  atags:
    tags: [ "TXT:google", "MX:apple" ]
```

When the feature is enabled, the following json field are populated in your DNS message:

Flat JSON:

```json
{
  "atags.tags.0": "TXT:google",
  "atags.tags.1": "MX:apple"
}

Default JSON structure:

```json

```

Complete example with the `dnsmessage` collector

```yaml
pipelines:
  - name: filter
    dnsmessage:
      matching:
        include:
          dns.qname: "^.*\\.google\\.com$"
    transforms:
      atags:
        tags: [ "google"]
```
