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

-module(pcapng_interface_statistics_block).
-export([parse/2]).

-spec parse(binary(), fun((binary()) -> integer())) -> map().
parse(Body, I) ->
    <<
      InterfaceID:32/bits,
      TimestampHigh:32/bits,
      TimestampLow:32/bits,
      Options/binary
    >> = Body,
    #{type => interface_statistics,
      interface_id => InterfaceID,
      timestamp_high => TimestampHigh,
      timestamp_low => TimestampLow,
      options => pcapng_options:parse(Options, I, mapping(I))
     }.


mapping(I) ->
    #{2 => isb_start_time,
      3 => isb_end_time,
      4 => {isb_if_recv, I},
      5 => {isb_if_drop, I},
      6 => isb_filter_accept,
      7 => isb_os_drop,
      8 => is_usr_deliv
     }.
