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

-module(pcapng_arp).
-export([decode/1]).

decode(<<
         HTYPE:16,
         PTYPE:16,
         HLEN:8,
         PLEN:8,
         OPER:16,
         SHA:HLEN/unit:8,
         SPA:PLEN/unit:8,
         THA:HLEN/unit:8,
         TPA:PLEN/unit:8,
         _/binary
       >>) ->
    #{
       htype => HTYPE,
       ptype => PTYPE,
       hlen => HLEN,
       plen => PLEN,
       oper => OPER,
       sha => SHA,
       spa => SPA,
       tha => THA,
       tpa => TPA
     }.
