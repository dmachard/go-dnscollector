
# DNS-collector - Configuration examples

You will find below some examples of configurations to manage your DNS logs.

- **Pipelines running mode with DNS Message filters**
  - [x] [Advanced example with DNSmessage collector](./_examples/use-case-24.yml)
  - [x] [How can I log only slow responses and errors?"](./_examples/use-case-25.yml)
  - [x] [Filter DNStap messages where the response ip address is 0.0.0.0](./_examples/use-case-26.yml)

- **Capture DNS traffic from incoming DNSTap streams**
  - [x] [Read from UNIX DNSTap socket and forward it to TLS stream](./_examples/use-case-5.yml)
  - [x] [Transform DNSTap as input to JSON format as output](./_examples/use-case-3.yml)
  - [x] [Relays DNSTap stream to multiple remote destination without decoding](./_examples/use-case-12.yml)
  - [x] [Aggregate several DNSTap stream and forward it to the same file](./_examples/use-case-7.yml)
  - [x] [Send to syslog TLS](./_examples/use-case-23.yml)

- **Captue DNS traffic and make format conversion on it**
  - [x] [Convert to text format output](./_examples/use-case-28.yml)
  - [x] [Convert to CSV output style](./_examples/use-case-30.yml)
  - [x] [Convert to text format with dig style, based on Jinja templating](./_examples/use-case-27.yml)
  - [x] [Convert to JSON format output](./_examples/use-case-29.yml)

- **Capture DNS traffic from PowerDNS products**
  - [x] [Capture multiple PowerDNS streams](./_examples/use-case-8.yml)

- **Observe your DNS traffic from logs**
  - [x] [Observe DNS metrics with Prometheus and Grafana](./_examples/use-case-2.yml)
  - [x] [Follow DNS traffic with Loki and Grafana](./_examples/use-case-4.yml)

- **Apply some transformations**
  - [x] [Capture DNSTap stream and apply user privacy on it](./_examples/use-case-6.yml)
  - [x] [Filtering incoming traffic with downsample and whitelist of domains](./_examples/use-case-9.yml)
  - [x] [Transform all domains to lowercase](./_examples/use-case-10.yml)
  - [x] [Add geographical metadata with GeoIP](./_examplesuse-case-11.yml)
  - [x] [Count the number of evicted queries](./_examples/use-case-18.yml)
  - [x] [Detect repetitive traffic and log it only once](./_examples/use-case-20.yml)

- Capture DNS traffic from FRSTRM/dnstap files
  - [x] [Save incoming DNStap streams to file (frstrm)](./_examples/use-case-13.yml)
  - [x] [Watch for DNStap files as input](./_examples/use-case-14.yml)

- Capture DNS traffic from PCAP files
  - [x] [Capture DNSTap stream and backup-it to text and pcap files](./_examples/use-case-1.yml)
  - [x] [Watch for PCAP files as input and JSON as output](./_examples/use-case-15.yml)

- Capture DNS traffic from Mikrotik device
  - [x] [Capture TZSP packets containing DNS packets and process them as json](./_examples/use-case-17.yml)

- Security: suspicious traffic detector
  - [x] [Capture DNS packets and flag suspicious traffic](./_examples/use-case-19.yml)
