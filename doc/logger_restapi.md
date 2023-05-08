
# Logger: REST API

Build-in webserver with REST API to search domains, clients and more...
Basic authentication supported.

See the [swagger](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/doc/swagger.yml) documentation.

Options:
- `listen-ip`: (string) listening IP
- `listen-port`: (integer) listening port
- `basic-auth-enable`: (boolean) enable or disable basic authentication
- `basic-auth-login`: (string) default login for basic auth
- `basic-auth-pwd`: (string) default password for basic auth
- `tls-support`: (boolean) tls support
- `tls-min-version`: (string) min tls version, default to 1.2
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `top-n`: (string) default number of items on top

Default values:

```yaml
restapi:
  listen-ip: 0.0.0.0
  listen-port: 8080
  basic-auth-enable: true
  basic-auth-login: admin
  basic-auth-pwd: changeme
  tls-support: true
  tls-min-version: 1.2
  cert-file: "./testsdata/server.crt"
  key-file: "./testsdata/server.key"
  top-n: 100
```