# dnspeep

`dnspeep` lets you spy on the DNS queries your computer is making.

Here's some example output:

```
$ sudo dnspeep
query name                           server IP       response
A     incoming.telemetry.mozilla.org 192.168.1.1     CNAME: telemetry-incoming.r53-2.services.mozilla.com, CNAME: pipeline-incoming-prod-elb-149169523.us-west-2.elb.amazonaws.com, A: 52.39.144.189, A: 54.191.136.131, A: 34.215.151.143, A: 54.149.208.57, A: 44.226.235.191, A: 52.10.174.113, A: 35.160.138.173, A: 44.238.190.78
AAAA  incoming.telemetry.mozilla.org 192.168.1.1     CNAME: telemetry-incoming.r53-2.services.mozilla.com, CNAME: pipeline-incoming-prod-elb-149169523.us-west-2.elb.amazonaws.com
A     www.google.com                 192.168.1.1     A: 172.217.13.132
AAAA  www.google.com                 192.168.1.1     AAAA: 2607:f8b0:4020:807::2004
A     www.neopets.com                192.168.1.1     CNAME: r9c3n8d2.stackpathcdn.com, A: 151.139.128.11
AAAA  www.neopets.com                192.168.1.1     CNAME: r9c3n8d2.stackpathcdn.com
```

### Installing

1. Download recent release of `dnspeep` from [the GitHub releases page](https://github.com/dnspeep/dnspeep/releases)
2. Unpack it
3. Put the `dnspeep` binary in your PATH (for example in `/usr/local/bin`)

### How it works

It uses `libpcap` to capture packets on port 53, and then matches up DNS
request and response packets so that it can show the request and response
together on the same line.

It also tracks DNS queries which didn't get a response within 1 second and
prints them out with the response `<no response>`.

### Limitations

* Only supports the DNS query types supported by the `dns_parser` crate ([here's a list](https://docs.rs/dns-parser/0.8.0/dns_parser/))
* Doesn't support TCP DNS queries, only UDP
* It can't show DNS-over-HTTPS queries (because it would need to MITM the HTTPS connection)
