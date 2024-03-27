
# Transformer: Traffic Reducer

Use this transformer to detect repetitive traffic.
A query or reply is repeated when the following criterias are the same.

The following criterias are used:

- server identity
- operation
- qname or qname+1
- query ip
- qtype

Options:

- `repetitive-traffic-detector` (boolean)
  > detect repetitive traffic

- `qname-plus-one` (boolean)
  > use qname+1 instead of the complete one

- `watch-interval` (integer)
  > watch interval in seconds

Default values:

```yaml
transforms:
  reducer:
    repetitive-traffic-detector: true
    qname-plus-one: false
    watch-interval: 5
```

Specific text directive(s) available for the text format:

- `reducer-occurrences`: display the number of detected duplication
- `cumulative-length`: sum of the length of each occurrences

When the feature is enabled, the following json field are populated in your DNS message:

Example:

```json
{
  "reducer": {
    "occurrences": 1,
    "cumulative-length": 47
  }
}
```
