# DNS-collector - Transformers

**Transformers** can be used to add some metadata to your traffic or some modifications on it (drop).
This subprocessing can be applied on inputs with collectors or on outputs with loggers.

## Processing order

Transformers processing is currently in this order :

1. Normalize
2. Traffic Filtering
3. Traffic Reducer
4. Finally all other transformations to do.

## Supported transformers

| Transformers                                                      | Descriptions                                |
| :-----------------------------------------------------------------|:--------------------------------------------|
| [Normalize](transformers/transform_normalize.md)                  | Quiet Text<br />Qname to lowercase<br />Add TLD and TLD+1            |
| [Traffic Filtering](transformers/transform_trafficfiltering.md)   | Downsampling<br />Dropping per Qname, QueryIP or Rcode               |
| [Suspicious Traffic Detector](transformers/transform_suspiciousdetector.md)   | Malformed and large packet<br />Uncommon Qtypes used< br/>Unallowed chars in Qname<br/>Excessive number of labels<br/>Long Qname |
| [Traffic Reducer](transformers/transform_trafficreducer.md)       | Detect repetitive queries/replies and log it only once        |
| [User Privacy](transformers/transform_userprivacy.md)             | Anonymize QueryIP<br />Minimaze Qname<br />Hash Query and Response IP with SHA1                      |
| [Latency Computing](transformers/transform_latency.md)            | Compute latency between replies and queries<br />Detect and count unanswered queries |
| [GeoIP metadata](transformers/transform_geoip.md)                 | Country and City                         |
| [Data Extractor](transformers/transform_dataextractor.md)         | Add base64 encoded dns payload                        |
| [Traffic Prediction](transformers/transform_trafficprediction.md) | Features to train machine learning models              |
| [Additionnal Tags](transformers/transform_atags.md)               | Add additionnal tags |
| [JSON relabeling](transformers/transform_relabeling.md)           | JSON relabeling to rename or remove keys |
| [DNS message rewrite](transformers/transform_rewrite.md)                      | Rewrite value for DNS messages structure |
| [Newly Observed Domains](transformers/transform_newdomaintracker.md)          | Detect Newly Observed Domains |
| [Reordering](transformers/transform_reordering.md)                            | Reordering DNS messages based on timestamps |
