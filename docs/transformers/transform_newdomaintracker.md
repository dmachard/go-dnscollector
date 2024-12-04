#  Transformer: New Domain Tracker Transformer

The **New Domain Tracker** transformer identifies domains that are newly observed within a configurable time window. It is particularly useful for detecting potentially malicious or suspicious domains in DNS traffic, such as those used for phishing, malware, or botnets.

## Features

- **Configurable Time Window**: Define how long a domain is considered new.
- **LRU-based Memory Management**: Ensures efficient memory usage with a finite cache size.

- **Persistence**: Optionally save the domain cache to disk for continuity after restarts.
- **Whitelist Support**: Exclude specific domains or patterns from detection.

## How It Works

1. When a DNS query is processed, the transformer checks if the queried domain exists in its cache.
2. If the domain is not in the cache or has not been seen within the specified TTL, it is marked as newly observed.
3. The domain is added to the cache with a timestamp of when it was last seen.
4. Whitelisted domains are ignored and never marked as new.

## Configuration:

* `ttl` (integer)
  > time window in seconds (e.g., 1 hour)

* `cache-size` (integer)
  > Maximum number of domains to track

* `white-domains-file` (string)
  > path file to domain white list, domains list can be a partial domain name with regexp expression


```yaml
transforms:
  new-domain-tracker:
    ttl: 3600 
    cache-size: 100000
    white-domains-file: ""
```

## Cache

The New Domain Tracker uses an **LRU Cache** to manage memory consumption efficiently. You can configure the maximum number of domains stored in the cache using the max_size parameter. Once the cache reaches its maximum size, the least recently used entries will be removed to make room for new ones.
The LRU Cache ensures finite memory usage but may cause some domains to be forgotten if the cache size is too small.


## Whitelist

Example of configuration to load a whitelist of domains to ignore.

```yaml
transforms:
  new-domain-tracker:
    ttl: 3600 
    cache-size: 100000
    white-domains-file: /tmp/whitelist_domain.txt
```

Example of content for the file `/tmp/whitelist_domain.txt`

```
(mail|wwww).google.com
github.com
```

## Persistence

To ensure continuity across application restarts, you can enable the persistence feature by specifying a file path (persistence). The transformer will save the domain cache to this file and reload it on startup.

