# DnsCollector Configuration Guide

See [config](https://github.com/dmachard/go-dnscollector/blob/main/config.yml) file.

- [Collectors](#Collectors)
  - [Dnstap TCP](#Dnstap-TCP)
  - [Dnstap Unix](#Dnstap-Unix)
- [Generators](#Generators)
  - [Stdout](#Stdout)
  - [Build-in Webserver](#Build-in-Webserver)
  - [Log File](#Log-File)
  - [Dnstap TCP](#Dnstap-TCP-Generator)
  - [Dnstap Unix](#Dnstap-Unix-Generator)
  
## Collectors

### DNStap TCP

Dnstap TCP stream collector.

```yaml
dnstap-tcp:
    enable: true
    listen-ip: 0.0.0.0
    listen-port: 6000
```

### DNStap Unix

Similar to the previous one, but uses a unix socket instead of a tcp socket.

```yaml
dnstap-unix:
    enable: false
    sock-path: null
```

## Generators

### Stdout

Print to your standard output, all DNS logs received.

```yaml
stdout:
    enable: false
```

### Build-in Webserver

Build-in webserver to retrieve somes statistics like top domains, clients and more...
Basic authentication supported.

```yaml
webserver:
    enable: true
    listen-ip: 0.0.0.0
    listen-port: 8080
    top-max-items: 100
    basic-auth-login: admin
    basic-auth-pwd: changeme
```


### Log File

Enable this generator if you want to log to a file.

```yaml
logfile:
    enable: false
    file-path: null
    max-size: 100
    max-files: 10
    log-queries: true
    log-replies: true
```

### DNStap TCP Generator

DNStap tcp stream generator to a remote destination.

```yaml
dnstap-tcp:
    enable: false
    remote-ip: 10.0.0.1
    remote-port: 6000
    retry: 5
    dnstap-identity: dnscollector
```

### DNStap Unix Generator

Same the previous one but uses a unix socket instead of a tcp socket
```yaml
dnstap-unix:
    enable: false
    sock-path: null
    retry: 5
    dnstap-identity: dnscollector
```