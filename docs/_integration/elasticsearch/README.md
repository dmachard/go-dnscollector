
# DNS-collector with Elastic and Kibana

- Download the `[docker-compose](https://github.com/dmachard/go-dnscollector/blob/doc_atags/docs/_integration/elasticsearch/docker-compose.yml)` file

- Create the `data` folder.

- Start the docker stack:

    ```bash
    sudo docker compose up -d
    ```

- Go to kibana web interface through `http://127.0.0.1:5601`

- Click on `Explore on my own` and `Discover`

- Finally create index pattern `dnscollector` and choose `dnstap.timestamp-rfc33939ns`

- Finally, run DNScollector from source and generate some DNS logs from your DNS server with DNStap protocol.

    ```bash
    go run . -config docs/_integration/elasticsearch/config.yml
    ```
