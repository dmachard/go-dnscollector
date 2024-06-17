
# Logger: ClickHouse client

Clickhouse client to remote ClickHouse server

Options:

* `url` (string)
  > Clickhouse server url

* `user` (string)
  > Clickhouse database user

* `password` (string)
  > Clickhouse database user password

* `table` (string)
  > Clickhouse table name

* `database` (string)
  > Clickhouse database name

* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Defaults:

```yaml
clickhouse:
  url: "http://localhost:8123"
  user: "default"
  password: "password"
  table: "records"
  database: "dnscollector"
  chan-buffer-size: 0
```
