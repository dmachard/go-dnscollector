
# DNS-collector with InfluxDB

- Download the [`docker-compose`](https://github.com/dmachard/go-dnscollector/blob/doc_atags/docs/_integration/influxdb/docker-compose.yml) file

- Create the `data` folder.

    ```bash
    mkdir -p ./data
    ```

- Start the docker stack:

    ```bash
    sudo docker compose up -d

    sudo docker compose logs
    ...
    influxdb-1    | ts=2024-06-13T18:38:18.131480Z lvl=info msg=Listening log_id=0plj8Rp0000 service=tcp-listener transport=http addr=:8086 port=8086
    ```

- Go to http://127.0.0.1:8086 to create initial user with
    organization: dnscollector
    bucket: db_dns
  Copy/paste the token in the DNScollector config.

- Finally, run DNScollector from source and generate some DNS logs from your DNS server with DNStap protocol.

    ```bash
    go run . -config docs/_integration/influxdb/config.yml
    ```

