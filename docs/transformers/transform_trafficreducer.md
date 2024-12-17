
# Transformer: Traffic Reducer

Use this transformer to detect repetitive traffic.
A query or reply is considered repeated  when the specified criteria match.

The following criteria can be configured for detecting repetitions (default one):

- Server identity
- Operation
- Qname or Qname+1
- Query IP
- Qtype

Options:

* `repetitive-traffic-detector` (boolean)
  > Detect repetitive traffic

* `qname-plus-one` (boolean)
  > Use qname+1 instead of the full Qname for matching.

* `watch-interval` (integer)
  > Interval in seconds to aggregate and process the traffic.

* `unique-fields` (array of strings)  
  > Define custom fields for uniqueness matching (limited to string and integer values). 
  > This allows greater flexibility in detecting repetitive traffic.
  > Complete list of [fields](../dnsconversions.md#json-encoding) available.

Default values:

```yaml
transforms:
  reducer:
    repetitive-traffic-detector: true
    qname-plus-one: false
    watch-interval: 2
    unique-fields:
    - dnstap.identity
    - dnstap.operation
    - network.query-ip
    - network.response-ip
    - dns.qname
    - dns.qtype
```

Specific directives available for the text output format:

* `reducer-occurrences`: display the number of detected duplication
* `cumulative-length`: sums the lengths of all occurrences.

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
