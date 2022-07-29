# DnsCollector - Logs routing / Multiplexer

The dns collector can be configured with multiple loggers and collectors at the same time.

You must defined the list of 
- loggers
- collectors 

And then defines the routing to use between all of them according to the name.
You can connect one collector to multiple loggers and you can also
connect multiple collectors to the same logger.

```
multiplexer:
  collectors:
    - name: tap
      dnstap:
        listen-ip: 0.0.0.0
        listen-port: 6000
        tls-support: false
    - name: tap_tls
      dnstap:
        listen-ip: 0.0.0.0
        listen-port: 6001
        tls-support: true
        cert-file: "/etc/dnscollector/dnscollector.crt"
        key-file: "/etc/dnscollector/dnscollector.key"

  loggers:
    - name: file
      logfile:
        file-path:  "/var/run/dnscollector/dnstap.log"
        max-size: 100
        max-files: 10
        mode: text

  routes:
    - from: [ tap, tap_tls ]
      to: [ file ]
```

