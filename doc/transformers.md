# DNS-collector - Supported transformers

| Transformers                                                      | Descriptions                                |
| :-----------------------------------------------------------------|:--------------------------------------------|
| [Normalize](transformers/transform_normalize.md)                  | Lowercase qname                             |
| [Traffic Filtering](transformers/transform_trafficfiltering.md)   | Filtering queries and replies               |
| [Traffic Reducer](transformers/transform_trafficreducer.md)       | Detect duplicated queries or replies        |
| [User Privacy](transformers/transform_userprivacy.md)             | Apply IP anonymization                      |
| [Latency Computing](transformers/transform_latency.md)            | Compute latency between queries and replies |
| [GeoIP metadata](transformers/transform_geoip.md)                 | Add GeoIP metadata                          |
| [Data Extractor](transformers/transform_dataextractor.md)         | Extract DNS payload                         |
| [Traffic Prediction](transformers/transform_trafficprediction.md) | Features for Machine learning               |

## Processing oder

Transformers processing is currently in this order :

1. Normalize
2. Traffic Filtering
3. Traffic Reducer
4. Finally all other transformations to do.
