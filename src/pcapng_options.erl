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

-module(pcapng_options).
-export([parse/2]).
-export([parse/3]).

-export([null_terminated/1]).


-spec parse(binary(), fun((binary()) -> integer())) -> map().

parse(<<>>, _) ->
    #{};

parse(Packet, I) ->
    parse(Packet, I, #{}).


-spec parse(binary(), fun((binary()) -> integer()), map()) -> map().

parse(<<>>, _, _) ->
    #{};

parse(Packet, I, Mapping) ->
    options(Packet, I, maps:merge(Mapping, mapping()), #{}).


options(<<0:16, 0:16>>, _, _, Options) ->
    Options;

options(<<Code:16/bits, Length:16/bits, Remainder/binary >>, I, Mapping,
        Options) ->
    #{body := Value,
      remainder := OtherOptions} = pcapng:variable_length(Remainder, I(Length)),

    case maps:get(I(Code), Mapping, I(Code)) of
        {Name, #{module := Module, function := Function}}  ->
            options(OtherOptions, I, Mapping,
                    Options#{Name => Module:Function(Value)});

        {Name, Transform} when is_function(Transform) ->
            options(OtherOptions, I, Mapping,
                    Options#{Name => Transform(Value)});

        Name ->
            options(OtherOptions, I, Mapping, maps:put(Name, Value, Options))
    end.



mapping() ->
    #{1 => {opt_comment, fun null_terminated/1}}.

-spec null_terminated(binary()) -> binary().

null_terminated(Comment) ->
    ZeroTerminated = byte_size(Comment) - 1,
    case binary:match(Comment, <<0>>) of
        {ZeroTerminated, 1} ->
            binary:part(Comment, 0, ZeroTerminated);
        nomatch ->
            Comment
    end.
