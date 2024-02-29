
# Start elastic and kibana

```bash
sudo docker compose up -d
```

Go to kibana web interface through `http://127.0.0.1:5601`

Click on `Explore on my own` and `Discover`
Finally create index pattern `dnscollector` and choose `dnstap.timestamp-rfc33939ns`

Run DNScollector from source:

```bash
go run . -config docs/_integration/elasticsearch/config.yml
```
