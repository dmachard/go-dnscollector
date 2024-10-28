# DNS-collector - Jinja enconding

## Overview

the DNS to Jinja encoding is very powerfull but is slow, so use it only on specific conditions.


Jinja template is only available with 
- console logger
- log file console

## Full configuration examples

* [`Dig style output`](../_examples/use-case-27.yml)

Here an example to format the output in dig style


```
text-jinja: |+
    ;; Got {% if dm.DNS.Type == "QUERY" %}query{% else %}answer{% endif %} from {{ dm.NetworkInfo.QueryIP }}#{{ dm.NetworkInfo.QueryPort }}:
    ;; ->>HEADER<<- opcode: {{ dm.DNS.Opcode }}, status: {{ dm.DNS.Rcode }}, id: {{ dm.DNS.ID }}
    ;; flags: {{ dm.DNS.Flags.QR | yesno:"qr ," }}{{ dm.DNS.Flags.RD | yesno:"rd ," }}{{ dm.DNS.Flags.RA | yesno:"ra ," }}; QUERY: {{ dm.DNS.QdCount }}, ANSWER: {{ dm.DNS.AnCount }}, AUTHORITY: {{ dm.DNS.NsCount }}, ADDITIONAL: {{ dm.DNS.ArCount }}
    
    ;; QUESTION SECTION:
    ;{{ dm.DNS.Qname }}		{{ dm.DNS.Qclass }}	{{ dm.DNS.Qtype }}

    ;; ANSWER SECTION: {% for rr in dm.DNS.DNSRRs.Answers %}
    {{ rr.Name }}		{{ rr.TTL }} {{ rr.Class }} {{ rr.Rdatatype }} {{ rr.Rdata }}{% endfor %}

    ;; WHEN: {{ dm.DNSTap.Timestamp }}
    ;; MSG SIZE  rcvd: {{ dm.DNS.Length }}
```