# Logger: File

## Overview

The File Logger allows you to log DNS traffic to a file in various formats, with support for rotation, compression, custom formatting, and the ability to execute scripts after file rotation.

## Key Features
- **File Rotation**: Automatically rotates log files based on size.
- **Supported Formats**: Supports multiple output formats - `text`, `jinja`, `json` and `flat json`, `pcap` or `dnstap`
- **Compression**: Optional gzip compression for rotated log files.
- **Post-Rotate Command**: Run external scripts after each file rotation.
- **Custom Text Formatting**: Configure custom output text formats.

## Configuration Options

* `file-path` (string)
  > output logfile name

* `mode` (string)
  > output format: `text`, `jinja`, `json` and `flat json`, `pcap` or `dnstap`

* `max-size`: (integer)
  > maximum size in megabytes of the file before rotation, 
  > A minimum of max-size*max-files megabytes of space disk must be available.

* `max-files` (integer)
  > maximum number of files to retain. Set to zero if you want to disable this feature

* `max-batch-size` (integer)
  > Buffers data up to the specified size (in bytes) before writing to the file.

* `flush-interval` (integer)
  > flush buffer to log file every X seconds

* `compress` (boolean)
  > Enables gzip compression for rotated log files.

* `text-format` (string)
  > output text format, please refer to the default text format to see all
  > available directives, use this parameter if you want a specific format.

* `jinja-format` (string)
  > jinja template, please refer [Jinja encoding](../dns2jinja.md) to see all available directives 

* `postrotate-command` (string)
  > Specifies a command or script to run after each file rotation.

* `postrotate-delete-success` (boolean)
  > Deletes the rotated file if the post-rotate script completes successfully.s

* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

**Default configuration**:

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
  jinja-format: ""
  postrotate-command: null
  postrotate-delete-success: false
  chan-buffer-size: 0
```

## Full configuration examples

* [`Text format`](../_examples/use-case-7.yml)
* [`Dnstap format`](../_examples/use-case-13.yml)
* [`PCAP format`](../_examples/use-case-1.yml)


## Log Compression

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

## Postrotate command

The `postrotate-command` option allows you to specify a **script** to execute after each file rotation. During the post-rotate process, files are temporarily renamed with a `toprocess-` prefix, for example, `toprocess-dnstap-1730099215373568947.log`. The script receives three arguments:
- Arg. 1: The full path to the log file
- Arg. 2: The directory path containing the log file
- Arg. 3: The filename without the toprocess- prefix

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
