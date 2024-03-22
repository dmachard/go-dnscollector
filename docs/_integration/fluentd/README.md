
# DNS-collector with Fluentd

- Create the `data` folder.

- Start the docker stack:

    ```bash
    sudo docker compose up -d

    sudo docker compose logs
    ...
    fluentd  | 2024-03-06 05:46:12.930048059 +0000 fluent.info: {"port":24224,"bind":"0.0.0.0","message":"[input1] listening port port=24224 bind=\"0.0.0.0\""}
    fluentd  | 2024-03-06 05:46:12 +0000 [warn]: #0 no patterns matched tag="fluent.info"
    fluentd  | 2024-03-06 05:46:12.933055666 +0000 fluent.info: {"worker":0,"message":"fluentd worker is now running worker=0"}
    ```

- Finally, run DNScollector from source and generate some DNS logs from your DNS server with DNStap protocol.

    ```bash
    go run . -config docs/_integration/fluentd/config.yml
    ```

- Logs are available in ./data
