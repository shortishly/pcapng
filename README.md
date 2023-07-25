<br>

<p align="center">
    <a href="https://shortishly.github.io/pcapng/cover/">
      <img alt="Test Coverage" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fshortishly.github.io%2Fpcapng%2Fcover%2Fcoverage.json&query=%24.total&suffix=%25&style=flat-square&label=Test%20Coverage&color=green">
    </a>
    <a href="https://shortishly.github.io/pcapng/ct/">
      <img alt="Test Results" src="https://img.shields.io/badge/Tests-Common%20Test-green?style=flat-square">
    </a>
    <a href="https://shortishly.github.io/pcapng/edoc/">
      <img alt="edoc" src="https://img.shields.io/badge/Documentation-edoc-green?style=flat-square">
    </a>
    <a href="https://erlang.org/">
      <img alt="Erlang/OTP 25+" src="https://img.shields.io/badge/Erlang%2FOTP-25%2B-green?style=flat-square">
    </a>
    <a href="https://www.apache.org/licenses/LICENSE-2.0">
      <img alt="Apache-2.0" src="https://img.shields.io/github/license/shortishly/pcapng?style=flat-square">
    </a>
</p>

<div align="center">
# PCAPNG 
![build passing](https://github.com/shortishly/pcapng/actions/workflows/main.yml/badge.svg)
</div>

## Why?

Convert Wireshark packet capture (pcap) files into something that is
easily usable by an Erlang project.

## What?

Run an interactive shell with  `make shell`:

```erlang
1> {ok, B} = file:read_file("test/pcapng_SUITE_data/dns.pcap").
{ok,<<10,13,13,10,148,0,0,0,77,60,43,26,1,0,0,0,255,255,
      255,255,255,255,255,255,3,0,46,...>>}
4> [inet_dns:decode(UDP) || #{packet := #{ip := #{udp := #{data := UDP}}}} <- pcapng:parse(B)].
[{ok,{dns_rec,{dns_header,60751,false,query,false,false,
                          true,false,false,0},
              [{dns_query,"p05-keyvalueservice.icloud.com.akadns.net",a,
                          in,false}],
              [],[],[]}}, ...]
```

A list of terms is returned, containing the packet data which can then
be further processed by the relevant protocol handler.
