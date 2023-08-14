# Collector: File Ingestor

This collector enable to ingest multiple  files by watching a directory.
This collector can be configured to search for PCAP files or DNSTAP files.
Make sure the PCAP is complete before moving the file to the directory so that file data is not truncated. 

If you are in PCAP mode, the collector search for files with the `.pcap` extension.
If you are in DNSTap mode, the collector search for files with the `.fstrm` extension.

For config examples, take a look to the following links:

- [dnstap](https://github.com/dmachard/go-dns-collector/blob/main/example-config/use-case-14.yml)
- [pcap](https://github.com/dmachard/go-dns-collector/blob/main/example-config/use-case-15.yml)

Options:

- `watch-dir`: (string) directory to watch for pcap files ingest
- `watch-mode`: (string) watch the directory pcap file with *.pcap extension or dnstap stream with*.fstrm extension, pcap or dnstap expected
- `pcap-dns-port`: (integer) dns source or destination port
- `delete-after:`: (boolean) delete pcap file after ingest
- `chan-buffer-size`: (integer) channel buffer size used on incoming packet, number of packet before to drop it.

Default values:

```yaml
file-ingestor:
  watch-dir: /tmp
  watch-mode: pcap
  pcap-dns-port: 53
  delete-after: false
  chan-buffer-size: 65535
```
