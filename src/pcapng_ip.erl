%% Copyright (c) 2015 Peter Morgan <peter.james.morgan@gmail.com>
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(pcapng_ip).
-export([decode/1]).

-define(ICMP, 1).
-define(IGMP, 2).
-define(TCP, 6).
-define(UDP, 17).
-define(ENCAP, 41).
-define(OSPF, 89).
-define(SCTP, 132).

decode(<<4:4, IHL:4, _:6, _:2, _TotalLength:16, _/binary>> = Packet) ->
    Size=IHL*4,
    <<Header:Size/binary, Data/binary>> = Packet,
    decode(header(Header), Data);

decode(<<
         6:4,
         TrafficClass:8,
         FlowLabel:20,
         PayloadLength:16,
         NextHeader:8,
         HopLimit:8,
         Source:128,
         Destination:128,
         _/binary
       >>) ->
    #{traffic_class => TrafficClass,
      flow_label => FlowLabel,
      payload_length => PayloadLength,
      next_header => NextHeader,
      hop_limit => HopLimit,
      source => Source,
      destination => Destination
     }.


header(<<
         4:4,
         IHL:4,
         DSCP:6,
         ECN:2,
         TotalLength:16,
         Identification:16,
         Flags:3,
         FragmentOffset:13,
         TTL:8,
         Protocol:8,
         CheckSum:16,
         S1:8,
         S2:8,
         S3:8,
         S4:8,
         D1:8,
         D2:8,
         D3:8,
         D4:8>>) ->
    #{ihl => IHL,
      dscp => DSCP,
      ecn => ECN,
      total_length => TotalLength,
      identification => Identification,
      flags => Flags,
      fragment_offset => FragmentOffset,
      ttl => TTL,
      protocol => Protocol,
      check_sum => CheckSum,
      source => {S1, S2, S3, S4},
      destination => {D1, D2, D3, D4}
     }.

decode(#{protocol := ?UDP} = Header, Packet) ->
    #{header => Header, udp => pcapng_ip_udp:decode(Packet)};

decode(#{protocol := ?TCP} = Header, Packet) ->
    #{header => Header, tcp => pcapng_ip_tcp:decode(Packet)}.
