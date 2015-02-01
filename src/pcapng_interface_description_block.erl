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

-module(pcapng_interface_description_block).
-export([parse/2]).
-export([if_filter/1]).

-spec parse(binary(), fun((binary()) -> integer())) -> map().
parse(Body, I) ->
    <<
      LinkType:16/bits,
      _:16/bits,
      SnapLen:32/bits,
      Options/binary
    >> = Body,

    #{type => interface_description,
      link_type => maps:get(I(LinkType), link_types(), I(LinkType)),
      snap_len => I(SnapLen),
      options => pcapng_options:parse(Options, I, options())
     }.

if_filter(<<0:8, Filter/binary>>) ->
    Filter.


options() ->
    #{2 => if_name,
      3 => {if_description, #{module => pcapng_options,
                              function => null_terminated}},
      4 => if_ip_v4_addr,
      5 => if_ip_v6_addr,
      6 => if_mac_addr,
      7 => if_eui_addr,
      8 => if_speed,
      9 => if_tsresol,
      10 => if_tzone,
      11 => {if_filter, #{module => pcapng_interface_description_block,
                          function => if_filter}},
      12 => if_os,
      13 => if_fcslen,
      14 => if_tsoffset
     }.

link_types() ->
    #{0 => null,
     1 => ethernet,
     2 => exp_ethernet,
     3 => ax25,
     4 => pronet,
     5 => chaos,
     6 => token_ring,
     7 => arcnet,
     8 => slip,
     9 => ppp,
     10 => fddi,
     50 => ppp_hdlc,
     51 => ppp_ether,
     99 => symantec_firewall,
     100 => atm_rfc1483,
     101 => raw,
     102 => slip_bsdos,
     103 => ppp_bsdos,
     104 => c_hdlc,
     105 => ieee802_11,
     106 => atm_clip,
     107 => frelay,
     108 => loop,
     109 => enc,
     110 => lane8023,
     111 => hippi,
     112 => hdlc,
     113 => linux_sll,
     114 => ltalk,
     115 => econet,
     116 => ipfilter,
     117 => pflog,
     118 => cisco_ios,
     119 => prism_header,
     120 => aironet_header,
     121 => hhdlc,
     122 => ip_over_fc,
     123 => sunatm,
     124 => rio,
     125 => pci_exp,
     126 => aurora,
     127 => ieee802_11_radio,
     128 => tzsp,
     129 => arcnet_linux,
     130 => juniper_mlppp,
     131 => juniper_mlfr,
     132 => juniper_es,
     133 => juniper_ggsn,
     134 => juniper_mfr,
     135 => juniper_atm2,
     136 => juniper_services,
     137 => juniper_atm1,
     138 => apple_ip_over_ieee1394,
     139 => mtp2_with_phdr,
     140 => mtp2,
     141 => mtp3,
     142 => sccp,
     143 => docsis,
     144 => linux_irda,
     145 => ibm_sp,
     146 => ibm_sn}.
