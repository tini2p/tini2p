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

set(NOISEC_ROOT ${PROJECT_SOURCE_DIR}/deps/noise-c)

add_library(NoiseC::NoiseC STATIC IMPORTED)

set(NOISEC_INC ${NOISEC_ROOT}/include)

find_path(NoiseC_INCLUDE_DIR
  NAMES cipherstate.h errors.h handshakestate.h hashstate.h protocol.h
  PATHS ${NOISEC_INC}/noise
  PATH_SUFFIXES keys protocol
  NO_DEFAULT_PATH)

set_target_properties(NoiseC::NoiseC PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${NoiseC_INCLUDE_DIR}")

target_include_directories(NoiseC::NoiseC INTERFACE ${NOISEC_INC})

include(ProcessorCount)
ProcessorCount(ThreadNum)
if (NOT N EQUAL 0)
  set(MAKE_ARGS -j${TheadNum})
endif()

set(NOISEC_BUILD "${NOISEC_ROOT}/build")

set(BYPRODUCT
  ${NOISEC_BUILD}/lib/libnoisekeys.a
  ${NOISEC_BUILD}/lib/libnoiseprotobufs.a
  ${NOISEC_BUILD}/lib/libnoiseprotocol.a)

include(ExternalProject)
ExternalProject_Add(noisec
  SOURCE_DIR ${NOISEC_ROOT}
  BUILD_IN_SOURCE TRUE
  INSTALL_DIR "${NOISEC_BUILD}"
  CONFIGURE_COMMAND autoreconf -i && ./configure --prefix=<INSTALL_DIR>
  BUILD_COMMAND $(MAKE) ${MAKE_ARGS}
  COMMAND ""
  INSTALL_COMMAND $(MAKE) install)

add_dependencies(NoiseC::NoiseC noisec)

set_target_properties(NoiseC::NoiseC PROPERTIES
  IMPORTED_LOCATION "${NOISEC_BUILD}/lib/libnoiseprotocol.a"
  IMPORTED_LINK_INTERFACE_LANGUAGES "C")

target_link_libraries(NoiseC::NoiseC INTERFACE
  ${NOISEC_BUILD}/lib/libnoisekeys.a
  ${NOISEC_BUILD}/lib/libnoiseprotobufs.a
  ${NOISEC_BUILD}/lib/libnoiseprotocol.a)

unset(BYPRODUCT)
unset(ThreadNum)
unset(MAKE_ARGS)
unset(NOISEC_BUILD)
unset(NOISEC_INC)
unset(NOISEC_ROOT)
