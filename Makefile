# Copyright (c) 2019, tini2p
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Parts used from The Kovri I2P Router Project Copyright (c) 2013-2018

SHELL := $(shell which bash)

cmake_target = all

cmake-tini2p  =

cmake-debug      = cmake -D CMAKE_BUILD_TYPE=Debug
cmake-debug      = cmake -D CMAKE_BUILD_TYPE=Release
cmake-coverage   = -D WITH_COVERAGE=ON
cmake-tests      = -D WITH_TESTS=ON
cmake-net-tests  = -D WITH_NET_TESTS=ON

noise-c = deps/noise-c
libressl = deps/libressl

build = build/

# cmake builder macro (courtesy of Kovri project)
define CMAKE
  cmake -E make_directory $1
	cmake -E chdir $1 $2 ../
endef

define PREP_NOISE_C
  cd $(noise-c); \
	autoreconf -i; \
	if [[! -d build ]]; then mkdir build; fi;
endef

define PREP_LIBRESSL
  cd $(libressl); \
	if [[! -d build ]]; then mkdir build; fi;
endef

define CLEAN_NOISE_C
  cd $(noise-c); \
  rm -rf build/*; \
	make clean;
endef

define CLEAN_LIBRESSL
  cd $(libressl); \
  rm -rf build/*; \
	make clean;
endef

deps:
	$(call PREP_NOISE_C)
	$(call PREP_LIBRESSL)

all: deps

tests: all
	$(eval cmake-tini2p += $(cmake-debug) $(cmake-tests))
	$(call CMAKE,$(build),$(cmake-tini2p)) && ${MAKE} -C $(build) $(cmake_target)

net-tests: all
	$(eval cmake-tini2p += $(cmake-debug) $(cmake-tests) $(cmake-net-tests))
	$(call CMAKE,$(build),$(cmake-tini2p)) && ${MAKE} -C $(build) $(cmake_target)

coverage: all
	$(eval cmake-tini2p += $(cmake-debug) $(cmake-coverage) $(cmake-tests) $(cmake-net-tests))
	$(call CMAKE,$(build),$(cmake-tini2p)) && ${MAKE} -C $(build) $(cmake_target)

clean:
	rm -rf $(build)

clean-deps:
	$(call CLEAN_NOISE_C)
	$(call CLEAN_LIBRESSL)

.PHONY: all tests net-tests coverage clean clean-deps
