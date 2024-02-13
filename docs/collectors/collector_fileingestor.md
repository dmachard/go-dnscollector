# Collector: File Ingestor

This collector enable to ingest multiple  files by watching a directory.
This collector can be configured to search for PCAP files or DNSTAP files.
Make sure the PCAP is complete before moving the file to the directory so that file data is not truncated. 

If you are in PCAP mode, the collector search for files with the `.pcap` extension.
If you are in DNSTap mode, the collector search for files with the `.fstrm` extension.

For config examples, take a look to the following links:

- [dnstap](../examples/use-case-14.yml)
- [pcap](../examples/use-case-15.yml)

Options:

- `watch-dir` (str) directory to watch for pcap files ingest. Defaults to `/tmp`.
  > Specifies the directory where pcap files are monitored for ingestion.
- `watch-mode` (str) watch the directory pcap or dnstap file. Defaults to `pcap`.
  >  `*.pcap` extension or dnstap stream with `*.fstrm` extension are expected.
- `pcap-dns-port` (int) dns source or destination port. Defaults port to `53`.
  > Expects a port number use for DNS communication.
- `delete-after:` (boolean) delete pcap file after ingest. Default to `false`.
  > Determines whether the pcap file should be deleted after ingestion.
- `chan-buffer-size` (int) incoming channel size, number of packet before to drop it. Default to `65535`.
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.
