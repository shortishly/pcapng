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

-module(pcapng_ip_tcp).
-export([decode/1]).


decode(<<
         Source:16,
         Destination:16,
         Sequence:32,
         Acknowledgement:32,
         DataOffset:4,
         0:3,
         NS:1,
         CWR:1,
         ECE:1,
         URG:1,
         ACK:1,
         PSH:1,
         RST:1,
         SYN:1,
         FIN:1,
         _/binary
       >>) ->
    #{source => Source,
      destination => Destination,
      sequence => Sequence,
      acknowledgement => Acknowledgement,
      data_offset => DataOffset,
      ns => NS,
      cwr => CWR,
      ece => ECE,
      urg => URG,
      ack => ACK,
      psh => PSH,
      rst => RST,
      syn => SYN,
      fin => FIN
     }.
