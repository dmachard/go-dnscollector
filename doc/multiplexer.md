# DnsCollector - Multiplexer

The dns collector can be configured with multiple loggers and collectors at the same time.
And also with the multiple identical loggers for example.


You must defined the list of 
- loggers
- collectors 

```
multiplexer:
  collectors:
    - name: tap_in
      dnstap:
        listen-ip: 0.0.0.0
        listen-port: 6000
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
```

And then the routing to use between all of them.

```
  routes:
    - from: [ tap_in ]
      to: [ file ]
```

