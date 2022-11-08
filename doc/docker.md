# DNS-collector - Docker

Docker run with a custom configuration:

```bash
docker run -d dmachard/go-dnscollector -v $(pwd)/config.yml:/etc/dnscollector/config.yml
```
