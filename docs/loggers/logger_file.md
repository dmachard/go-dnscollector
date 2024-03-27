# Logger: File

Enable this logger if you want to log your DNS traffic to a file in plain text mode or binary mode.

* with rotation file support
* supported format: `text`, `json` and `flat json`, `pcap` or `dnstap`
* gzip compression
* execute external command after each rotation
* custom text format

For config examples, take a look to the following links:

* [`text`](../_examples/use-case-7.yml)
* [`dnstap`](../_examples/use-case-13.yml)
* [`pcap`](../_examples/use-case-1.yml)

Options:

* `file-path` (string)
  > output logfile name

* `max-size`: (integer)
  > maximum size in megabytes of the file before rotation, 
  > A minimum of max-size*max-files megabytes of space disk must be available.

* `max-files` (integer)
  > maximum number of files to retain. Set to zero if you want to disable this feature

* `flush-interval` (integer)
  > flush buffer to log file every X seconds

* `compress` (boolean)
  > compress log file

* `compress-interval` (integer)
  > checking every X seconds if new log files must be compressed

* `compress-command` (string)
  > run external script after file compress step

* `mode` (string)
  > output format: text, json, flat-json, pcap or dnstap

* `text-format` (string)
  > output text format, please refer to the default text format to see all
  > available directives, use this parameter if you want a specific format.

* `postrotate-command` (string)
  > run external script after file rotation

* `postrotate-delete-success` (boolean)
  > delete file on script success

* `chan-buffer-size` (integer)
  > channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
logfile:
  file-path: null
  max-size: 100
  max-files: 10
  flush-interval: 10
  compress: false
  compress-interval: 5
  compress-command: null
  mode: text
  text-format: ""
  postrotate-command: null
  postrotate-delete-success: false
  chan-buffer-size: 65535
```

The `postrotate-command` can be used to execute a script after each file rotation.
Your script will take in argument the path file of the latest log file and then you will can do what you want on it.
If the compression is enabled then the postrotate command will be executed after that too.

Basic example to use the postrotate command:

```yaml
logfile:
  postrotate-command: "/home/dnscollector/postrotate.sh"
```

Script to move the log file to a specific folder

```bash
#!/bin/bash

DNSCOLLECTOR=/var/dnscollector/
BACKUP_FOLDER=$DNSCOLLECTOR/$(date +%Y-%m-%d)
mkdir -p $BACKUP_FOLDER

mv $1 $BACKUP_FOLDER
```

For the `PCAP` mode, currently the DNS protocol over UDP is used to log the traffic, the following translations are done.

| Origin protocol        | Translated to                  |
| -----------------------|--------------------------------|
| DNS/53 over UDP        | DNS UDP/53                     |
| DNS/53 over TCP        | DNS TCP/53                     |
| DoH/443                | DNS UDP/443 (no cipher)        |
| DoT/853                | DNS UDP/853 (no cipher)        |
| DoQ                    | Not yet supported              |
