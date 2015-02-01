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

-module(pcapng_section_header_block).
-export([parse/2]).


-spec parse(binary(), fun((binary()) -> integer())) -> map().

parse(Body, I) ->
    <<_:32, Major:16/bits, Minor:16/bits, _:64, Options/binary>> = Body,
    #{
       type => section_header,
       major_version => I(Major),
       minor_version => I(Minor),
       options => pcapng_options:parse(Options, I, options())
     }.

options() ->
    #{2 => shb_hardware,
      3 => {shb_os, fun pcapng_options:null_terminated/1},
      4 => {shb_userappl, fun pcapng_options:null_terminated/1}}.
