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
project(tini2p-core CXX)

add_library(tini2p-core
  bytes.h
  time.h

  # Crypto
  crypto/aes.h
  crypto/blake.h
  crypto/chacha_poly1305.h
  crypto/ecies.h
  crypto/eddsa.h
  crypto/hkdf.h
  crypto/keys.h
  crypto/rand.h
  crypto/radix.h
  crypto/sha.h
  crypto/x25519.h
  crypto/dh/x3dh.h

  # Blocks
  data/blocks/blocks.h

  # Router
  data/router/address.h
  data/router/identity.h
  data/router/info.h
  data/router/mapping.h
  data/router/meta.h

  # Exception handling
  exception/exception.h

  # NTCP2
  ntcp2/session_request/session_request.h  # Session Request
  ntcp2/session_created/session_created.h  # Session Created
  ntcp2/session_confirmed/session_confirmed.h  # Session Confirmed
  ntcp2/data_phase/data_phase.h  # Data Phase

  # Session
  ntcp2/session/listener.h
  ntcp2/session/manager.h
  ntcp2/session/session.h)

set_target_properties(tini2p-core PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(tini2p-core PRIVATE tini2p-priv)
