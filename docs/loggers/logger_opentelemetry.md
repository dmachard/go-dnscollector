# Logger: OpenTelemetry

OpenTelemetry plugin Logger

**Experimental**: This feature is experimental and currently works only with the DNSDist and Recursor products from PowerDNS.

Options:
* `otel-endpoint` (string)
  > Specifies the endpoint for sending telemetry data to an OpenTelemetry collector. 
  > The endpoint should be specified in the format `host:port`.

Default values:

```yaml
opentelemetry:
  otel-endpoint: ""
```

Exemple of result with Tempo from Grafana

<p align="center">
  <img src="../_images/otel_tracing.png" alt="dnscollector"/>
</p>

Exemple with DNS error (NXDOMAIN)

<p align="center">
  <img src="../_images/otel_tracing_error.png" alt="dnscollector"/>
</p>
