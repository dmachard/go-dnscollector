
# Logger: ClickHouse client

Clickhouse client to remote ClickHouse server

Options:

- `url`: (string) Clickhouse server url
- `user`: (string) Clickhouse database user
- `password`: (string) Clickhouse database user password
- `table`: (string) Clickhouse table name
- `database`: (string) Clickhouse database name

Defaults:

```yaml
clickhouse:
  url: "http://localhost:8123"
  user: "default"
  password: "password"
  table: "records"
  database: "dnscollector"
```
