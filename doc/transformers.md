# DNS-collector - Supported transformers

| Transformers                                                      | Descriptions                                |
| :-----------------------------------------------------------------|:--------------------------------------------|
| [Normalize](transformers/transform_normalize.md)                  | Lowercase qname                             |
| [Traffic Filtering](transformers/transform_trafficfiltering.md)   | Filtering queries and replies               |
| [Suspicious Traffic Detector](transformers/transform_suspiciousdetector.md)   | Supicious traffic detector               |
| [Traffic Reducer](transformers/transform_trafficreducer.md)       | Detect repetitive queries/replies and log it only once        |
| [User Privacy](transformers/transform_userprivacy.md)             | Apply IP anonymization                      |
| [Latency Computing](transformers/transform_latency.md)            | Compute latency between replies and queries<br />Detect and count unanswered queries |
| [GeoIP metadata](transformers/transform_geoip.md)                 | Add GeoIP metadata                          |
| [Data Extractor](transformers/transform_dataextractor.md)         | Add base64 encoded dns payload                        |
| [Traffic Prediction](transformers/transform_trafficprediction.md) | Features to train machine learning models              |

## Processing oder

Transformers processing is currently in this order :

1. Normalize
2. Traffic Filtering
3. Traffic Reducer
4. Finally all other transformations to do.
