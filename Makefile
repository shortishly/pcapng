#-*- mode: makefile-gmake -*-
# Copyright (c) 2012-2015 Peter Morgan <peter.james.morgan@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
PROJECT = pcapng
PROJECT_DESCRIPTION = PCAP Next Generation Dump File Format
PROJECT_VERSION = ${shell git describe --tags}

COVER = 1
COVER_REPORT_DIR = _site/cover
CT_LOGS_DIR = _site/ct
EDOC_OPTS = {preprocess, true}, {dir, "_site/edoc"}

SHELL_DEPS += sync
SHELL_OPTS += +pc unicode
SHELL_OPTS += -s sync

PLT_APPS += compiler
PLT_APPS += crypto
PLT_APPS += stdlib


include $(if $(ERLANG_MK_FILENAME),$(ERLANG_MK_FILENAME),erlang.mk)
