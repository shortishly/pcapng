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

-module(pcapng).
-export([get_env/1]).
-export([parse/1]).
-export([process/1]).
-export([variable_length/2]).
-export([variable_length/3]).

-define(SECTION_HEADER, 16#0A0D0D0A).
-define(BYTE_ORDER_MAGIC, 16#1A2B3C4D).
-define(INTERFACE_DESCRIPTION, 1).
-define(PACKET, 2).
-define(SIMPLE_PACKET, 3).
-define(NAME_RESOLUTION, 4).
-define(INTERFACE_STATISTICS, 5).
-define(ENHANCED_PACKET, 6).


process(Filename) ->
    {ok, PCAPNG} = file:read_file(Filename),
    write_file(filename:rootname(Filename) ++ ".terms",
               parse(PCAPNG)).


write_file(Filename, Terms) ->
    {ok, Header} = file:read_file("HEADER.txt"),

    file:write_file(
      Filename,
      [io_lib:fwrite("%% -*- mode: erlang -*-~n", []),
       Header,
       [io_lib:fwrite("~n~p.~n", [Term]) || Term <- Terms]]).


parse(<<
        ?SECTION_HEADER:32,
        _:32,
        ?BYTE_ORDER_MAGIC:32/little,
        _/binary>> = Data) ->
    parse(Data, conversion(little));

parse(<<
        ?SECTION_HEADER:32,
        _:32,
        ?BYTE_ORDER_MAGIC:32/big,
        _/binary>> = Data) ->
    parse(Data, conversion(big)).

parse(Data, I) ->
    case block(Data, I) of
        #{block := Block, remainder := <<>>} ->
            [Block];

        #{block := Block, remainder := Remainder} ->
            [Block | parse(Remainder, I)]
    end.


block(<<Type:32/bits, _/binary>> = Data, I) ->
    block(I(Type), Data, I).

block(Type, Data, I) ->
    #{body := Body, remainder := Remainder} = body(Type, Data, I),
    #{block => decode(Type, Body, I), remainder => Remainder}.

body(3, <<_:32/bits, TotalLength:32/bits, _/binary>> = Data, I) ->
    BodyLength = I(TotalLength) - 11,
    <<
      _:32/bits,
      TotalLength:32/bits,
      Body:BodyLength/bytes,
      TotalLength:32/bits,
      Remainder/binary
    >> = Data,
    #{body => Body, remainder => Remainder};

body(_, <<_:32/bits, TotalLength:32/bits, _/binary>> = Data, I) ->
    BodyLength = I(TotalLength) - 12,
    <<
      _:32/bits,
      TotalLength:32/bits,
      Body:BodyLength/bytes,
      TotalLength:32/bits,
      Remainder/binary
    >> = Data,
    #{body => Body, remainder => Remainder}.


blocks() ->
    #{
       ?SECTION_HEADER => pcapng_section_header_block,
       ?INTERFACE_DESCRIPTION => pcapng_interface_description_block,
       ?PACKET => pcapng_packet_block,
       ?SIMPLE_PACKET => pcapng_simple_packet_block,
       ?NAME_RESOLUTION => pcapng_name_resolution_block,
       ?INTERFACE_STATISTICS => pcapng_interface_statistics_block,
       ?ENHANCED_PACKET => pcapng_enhanced_packet_block
     }.


decode(BlockType, BlockBody, I) ->
    (maps:get(BlockType, blocks())):parse(BlockBody, I).

variable_length(Packet, Length) ->
    variable_length(Packet, Length, 4).

variable_length(Packet, Length, Alignment) when Length rem Alignment =:= 0 ->
    <<Aligned:Length/bytes, Remainder/binary>> = Packet,
    #{body => Aligned, remainder => Remainder};

variable_length(Packet, Length, Alignment) ->
    Padding = (Alignment - (Length rem Alignment)) * 8,
    <<Aligned:Length/bytes, _:Padding, Remainder/binary>> = Packet,
    #{body => Aligned, remainder => Remainder}.

conversion(little) ->
    fun
        (Binary) ->
            Size = bit_size(Binary),
            <<I:Size/little>> = Binary,
            I
    end;
conversion(big) ->
    fun
        (Binary) ->
            Size = bit_size(Binary),
            <<I:Size/big>> = Binary,
            I
    end.

get_env(Par) ->
    case application:get_env(?MODULE, Par) of
        {ok, Val} ->
            Val;

        undefined ->
            #{}
    end.
