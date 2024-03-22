
# Logger: Clickhouse client

Clickhouse client to remote Clickhouse server

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
