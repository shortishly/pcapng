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

-module(pcapng_name_resolution_block).
-export([parse/2]).


-define(NRES_IP4RECORD, 1).
-define(NRES_IP6RECORD, 2).


-spec parse(binary(), fun((binary()) -> integer())) -> map().

parse(Data, I) ->
    records(Data, I).


records(Data, I) ->
    records(Data, I, #{}).

records(<<0:16, 0:16, Options/binary>>, I, Records) ->
    #{type => name_resolution_block,
      records => Records,
      options => pcapng_options:parse(Options, I)};

records(<<Type:16/bits, Length:16/bits, Data/binary>>, I, Records) ->
    case {I(Type), pcapng:variable_length(Data, I(Length))} of
        {?NRES_IP4RECORD,
         #{body := <<A1:8, A2:8, A3:8, A4:8, Names/binary>>,
           remainder := Remainder}} ->
            records(Remainder, I, maps:put({A1, A2, A3, A4}, split(Names),
                                           Records));

        {?NRES_IP6RECORD,
         #{body := <<IP:16/bytes, Names/binary>>, remainder := Remainder}} ->
            records(Remainder, I, maps:put(IP, split(Names), Records))
    end.

split(Names) ->
    lists:droplast(binary:split(Names, <<0:8>>, [global])).
