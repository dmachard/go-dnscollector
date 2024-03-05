
# DNS-collector with Kafka

- Copy folder [./docs/_integration/kafka] and start the docker stack:

    ```bash
    sudo docker compose up -d
    ```

- Go to Apache Kafka interface through `http://127.0.0.1:8080`

- The `dnscollector` topics should be available.

- Finally, run DNScollector from source:

    ```bash
    go run . -config docs/_integration/kafka/config.yml
    ```
