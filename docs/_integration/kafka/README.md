
# DNS-collector with Kafka

- Download the `[docker-compose](https://github.com/dmachard/go-dnscollector/blob/doc_atags/docs/_integration/kafka/docker-compose.yml)` file

- Create the `data` folder.

- Start the docker stack:

    ```bash
    sudo docker compose up -d
    ```

- Go to Apache Kafka interface through `http://127.0.0.1:8080`

- The `dnscollector` topic should be available.

- Finally, run DNScollector from source and generate some DNS logs from your DNS server with DNStap protocol.

    ```bash
    go run . -config docs/_integration/kafka/config.yml
    ```
