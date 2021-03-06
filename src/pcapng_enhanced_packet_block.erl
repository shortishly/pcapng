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

-module(pcapng_enhanced_packet_block).
-export([parse/2]).


-spec parse(binary(), fun((binary()) -> integer())) -> map().

parse(Body, I) ->
    <<
      InterfaceID:32/bits,
      TimestampHigh:32/bits,
      TimestampLow:32/bits,
      CapturedLen:32/bits,
      PacketLen:32/bits,
      PacketOptionsData/binary
    >> = Body,

    #{body := Packet,
      remainder := Options} = pcapng:variable_length(PacketOptionsData,
                                                     I(CapturedLen)),
    #{
       type => enhanced_packet_block,
       interface_id => I(InterfaceID),
       timestamp_high => I(TimestampHigh),
       timestamp_low => I(TimestampLow),
       captured_len => I(CapturedLen),
       packet_len => I(PacketLen),
       packet => pcapng_ethernet:decode(Packet),
       options => pcapng_options:parse(Options, I)
     }.
