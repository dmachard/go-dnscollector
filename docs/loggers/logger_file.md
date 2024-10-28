# Logger: File

Enable this logger if you want to log your DNS traffic to a file in plain text mode or binary mode.

* with rotation file support
* supported format: `text`, `jinja`, `json` and `flat json`, `pcap` or `dnstap`
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

* `max-batch-size` (integer)
  > accumulate data before writing it to the file

* `flush-interval` (integer)
  > flush buffer to log file every X seconds

* `compress` (boolean)
  > compress log file

* `mode` (string)
  > output format: text, jinja, json, flat-json, pcap or dnstap

* `text-format` (string)
  > output text format, please refer to the default text format to see all
  > available directives, use this parameter if you want a specific format.

* `postrotate-command` (string)
  > run external script after file rotation

* `postrotate-delete-success` (boolean)
  > delete file on script success

* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Default values:

```yaml
logfile:
  file-path: null
  max-size: 100
  max-files: 10
  max-batch-size: 65536
  flush-interval: 1
  compress: false
  mode: text
  text-format: ""
  postrotate-command: null
  postrotate-delete-success: false
  chan-buffer-size: 0
```

### Log Compression

When enabled, gzip log compression runs asynchronously for each completed log file. 
During the rotation process, files are initially renamed with a `tocompress-` prefix, e.g., `tocompress-dnstap-1730099215373568947.log`, 
indicating they’re pending compression. Once compression finishes, the file is renamed to `dnstap-1730099215373568947.log.gz`, 
replacing the `tocompress-` prefix and adding the `.gz` suffix to mark completion.

> Only one compression task runs at a time to optimize system performance, ensuring sequential compression of files.

To enable log compression, set `compress` to `true` in your configuration file:

```yaml
logfile:
  compress: true
```

### Postrotate command

The `postrotate-command` option allows you to specify a **script** to execute after each file rotation. During the post-rotate process, files are temporarily renamed with a `toprocess-` prefix, for example, `toprocess-dnstap-1730099215373568947.log`. The script receives three arguments:
- The full path to the log file
- The directory path containing the log file
- The filename without the toprocess- prefix

**Example Configuration**

To specify a post-rotate command, add the following configuration:

```yaml
logfile:
  postrotate-command: "/home/dnscollector/postrotate.sh"
```

**Example Script**

Here’s a sample script that moves the log file to a date-specific backup folder:

```bash
#!/bin/bash

DNSCOLLECTOR=/var/dnscollector/
BACKUP_FOLDER=$DNSCOLLECTOR/$(date +%Y-%m-%d)
mkdir -p $BACKUP_FOLDER

# Move the log file to the backup folder, excluding the 'toprocess-' prefix from the filename
mv $1 $BACKUP_FOLDER/$3
```

> Note: If compression is enabled, the postrotate-command will run only after compression completes.

### Save to PCAP files

For the `PCAP` mode, currently the DNS protocol over UDP is used to log the traffic, the following translations are done.

| Origin protocol        | Translated to                  |
| -----------------------|--------------------------------|
| DNS/53 over UDP        | DNS UDP/53                     |
| DNS/53 over TCP        | DNS TCP/53                     |
| DoH/443                | DNS UDP/443 (no cipher)        |
| DoT/853                | DNS UDP/853 (no cipher)        |
| DoQ                    | Not yet supported              |
