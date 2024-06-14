
# DNS-collector with Loki

- Download the [`docker-compose`](https://github.com/dmachard/go-dnscollector/blob/doc_atags/docs/_integration/loki/docker-compose.yml) file

- Create the `data` folder.

    ```bash
    mkdir -p ./data
    ```

- Start the docker stack:

    ```bash
    sudo docker compose up -d
    ```

- Finally, run DNScollector from source and generate some DNS logs from your DNS server with DNStap protocol.

    ```bash
    go run . -config docs/_integration/loki/config.yml
    ```

- Connect to the web interface of grafana through http://127.0.0.1:3000
  Go to the menu `Explorer`, your DNS logs will be here.
