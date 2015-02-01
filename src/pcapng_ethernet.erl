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

-module(pcapng_ethernet).
-export([decode/1]).

-define(IPV4, 16#0800).
-define(IPV6, 16#86DD).
-define(ARP, 16#0806).

decode(<<_:48, _:48, ?IPV4:16, _/binary>> = Frame) ->
    decode(Frame, ip, pcapng_ip);

decode(<<_:48, _:48, ?IPV6:16, _/binary>> = Frame) ->
    decode(Frame, ip, pcapng_ip);

decode(<<_:48, _:48, ?ARP:16, _/binary>> = Frame) ->
    decode(Frame, arp, pcapng_arp);
decode(Frame) ->
    #{unknown => Frame}.



decode(<<Destination:48, Source:48, _:16, IP/binary>>, Protocol, Decoder) ->
    #{Protocol => Decoder:decode(IP),
      destination => integer_to_binary(Destination, 16),
      source => integer_to_binary(Source, 16)}.
