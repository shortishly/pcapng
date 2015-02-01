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

-module(pcapng_SUITE).
-include_lib("common_test/include/ct.hrl").
-compile(export_all).

all() ->
        [{group, samples},
         {group, wiki_wireshark_org},
         {group, packetlife_net}].

groups() ->
    [{samples, [parallel], [
                            capture0000_test,
                            capture0001_test,
                            dns_test,
                            dns_018_test
                           ]},

     {packetlife_net, [parallel], [
                                   open_network_connection_test,
                                   gmail_test,
%                                  address_withdrawal_ldp_test,
                                   dns_question_and_answer_test
                                  ]},

     {wiki_wireshark_org, [parallel], [
%                                      http_littleendian_pcapng_test,
                                       test001_test,
                                       test002_test,
                                       test003_test,
                                       test004_test,
                                       test005_test,
%                                      test006_test,
%                                      test007_test,
                                       test008_test,
                                       test009_test
%                                      test010_test,
%                                      icmp2_test
                                      ]}].

init_per_suite(Config) ->
    application:start(pcapng),
    Config.

parse(Config, Name) ->
    pcapng:parse(read_file(Config, Name)).

read_file(Config, Name) ->
    {ok, Packet} = file:read_file(filename:join(?config(data_dir, Config),
                                                Name)),
    Packet.

capture0000_test(Config) ->
    [#{type := section_header},
     #{type := interface_description},
     #{type := enhanced_packet_block},
     #{type := interface_statistics}] = parse(Config, "capture0000.pcapng").

capture0001_test(Config) ->
    [#{type := section_header},
     #{type := interface_description} | _] = parse(Config,
                                                   "capture0001.pcapng").

http_littleendian_pcapng_test(Config) ->
    ok = parse(Config, "http.littleendian.pcapng").

test001_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{},
       type := section_header}] = parse(Config, "test001.pcapng").

test002_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{},
       type := section_header},
     #{link_type := null,
       options := #{},
       snap_len := 0,
       type := interface_description}] = parse(Config, "test002.pcapng").

test003_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{},
       type := section_header},
     #{link_type := 1240,
       options := #{},
       snap_len := 124,
       type := interface_description}] = parse(Config, "test003.pcapng").

test004_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{shb_os := <<"Windows XP">>,
                    shb_userappl := <<"Test004.exe">>},
       type := section_header}] = parse(Config, "test004.pcapng").

test005_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{},
       type := section_header},
     #{link_type := 1240,
       options := #{if_description := <<"Stupid ethernet interface">>,
                    if_speed := <<0,228,11,84,2,0,0,0>>},
       snap_len := 124,
       type := interface_description}] = parse(Config, "test005.pcapng").

test006_test(Config) ->
    ok = parse(Config, "test006.pcapng").

test007_test(Config) ->
    ok = parse(Config, "test007.pcapng").

test008_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{opt_comment := <<"Hello world">>},
       type := section_header},
     #{link_type := 1240,
       options := #{if_description := <<"Stupid ethernet interface">>,
                    if_speed := <<0,228,11,84,2,0,0,0>>},
       snap_len := 124,
       type := interface_description},
     #{major_version := 1,
       minor_version := 0,
       options := #{opt_comment := <<"Hello world">>},
       type := section_header},
     #{link_type := 1240,
       options := #{if_description := <<"Stupid ethernet interface">>,
                    if_speed := <<0,228,11,84,2,0,0,0>>},
       snap_len := 124,
       type := interface_description}] = parse(Config, "test008.pcapng").

test009_test(Config) ->
    [#{major_version := 1,
       minor_version := 0,
       options := #{opt_comment := <<"Hello world">>},
       type := section_header},
     #{link_type := 1240,
       options := #{if_description := <<"Stupid ethernet interface">>,
                    if_speed := <<0,228,11,84,2,0,0,0>>},
       snap_len := 124,
       type := interface_description}] = parse(Config, "test009.pcapng").

test010_test(Config) ->
    ok = parse(Config, "test010.pcapng").

open_network_connection_test(Config) ->
    [#{type := section_header},
     #{type := interface_description} | _] = parse(Config, "Open Network Connection.pcapng").

gmail_test(Config) ->
    [#{type := section_header},
     #{type := interface_description} | _] = parse(Config, "gmail.pcapng").

address_withdrawal_ldp_test(Config) ->
    ok = parse(Config, "address withdrawal ldp.pcapng").

dns_question_and_answer_test(Config) ->
    [#{type := section_header},
     #{type := interface_description} | _]  = parse(Config, "DNS Question & Answer.pcapng").

icmp2_test(Config) ->
    ok = parse(Config, "icmp2.pcapng").

dns_test(Config) ->
    [#{type := section_header},
     #{type := interface_description} | _] = parse(Config, "dns.pcapng").

dns_018_test(Config) ->
    [#{type := section_header},
     #{type := interface_description} | _] = parse(Config, "dns-018.pcapng").
