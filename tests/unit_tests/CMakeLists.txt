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

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(tini2p-tests CXX)

add_executable(tini2p-tests
  main.cc

  bytes.cc

  crypto/aes.cc
  crypto/chacha_poly1305.cc
  crypto/codecs.cc
  crypto/ecies/x25519.cc
  crypto/eddsa/eddsa_sha512.cc
  crypto/siphash.cc
  crypto/x25519.cc

  data/blocks/date_time.cc
  data/blocks/i2np.cc
  data/blocks/info.cc
  data/blocks/options.cc
  data/blocks/padding.cc
  data/blocks/termination.cc

  data/router/address.cc
  data/router/certificate.cc
  data/router/identity.cc
  data/router/info.cc
  data/router/lease_set.cc
  data/router/mapping.cc

  ntcp2/meta.cc

  ntcp2/session_request/kdf.cc
  ntcp2/session_request/session_request.cc

  ntcp2/session_created/kdf.cc
  ntcp2/session_created/session_created.cc
  
  ntcp2/session_confirmed/kdf.cc
  ntcp2/session_confirmed/session_confirmed.cc

  ntcp2/data_phase/kdf.cc
  ntcp2/data_phase/data_phase.cc

  mock/handshake.h)


target_include_directories(tini2p-tests PRIVATE
  ${PROJECT_SOURCE_DIR}/deps/cryptopp
  ${PROJECT_SOURCE_DIR}/deps/noise-c/lib
  ${PROJECT_SOURCE_DIR}/deps/noise-c/include)

target_link_libraries(tini2p-tests PRIVATE tini2p-core tini2p-priv)

install(TARGETS tini2p-tests RUNTIME DESTINATION ${CMAKE_CURRENT_BINARY_DIR}) 
