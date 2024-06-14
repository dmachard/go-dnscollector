
# DNS-collector with Prometheus

- Download the [`docker-compose`](https://github.com/dmachard/go-dnscollector/blob/doc_atags/docs/_integration/prometheus/docker-compose.yml) file

- Create the `data` folder.

    ```bash
    mkdir -p ./data
    ```

- Configure targets on prometheus.yml with IP of your DNScollector and start the docker stack:

    ```bash
    sudo docker compose up -d
    ```

- Finally, run DNScollector from source and generate some DNS logs from your DNS server with DNStap protocol.

    ```bash
    go run . -config docs/_integration/prometheus/config.yml
    ```

- Import build-in dashboards
