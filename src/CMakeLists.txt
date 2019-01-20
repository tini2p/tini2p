# copyright (c) 2018, tini2p
# all rights reserved.
# 
# redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# this software is provided by the copyright holders and contributors "as is"
# and any express or implied warranties, including, but not limited to, the
# implied warranties of merchantability and fitness for a particular purpose are
# disclaimed. in no event shall the copyright holder or contributors be liable
# for any direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute goods or
# services; loss of use, data, or profits; or business interruption) however
# caused and on any theory of liability, whether in contract, strict liability,
# or tort (including negligence or otherwise) arising in any way out of the use
# of this software, even if advised of the possibility of such damage.

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(tini2p-core CXX)

add_library(tini2p-core
  # Crypto
  crypto/aes.h
  crypto/ed25519.h
  crypto/elgamal.h
  crypto/key.h
  crypto/rand.h
  crypto/radix.h

  exception/exception.h

  ntcp2/bytes.h
  ntcp2/meta.h
  ntcp2/messenger.h
  ntcp2/noise.h
  ntcp2/role.h
  ntcp2/time.h

  # Blocks
  ntcp2/blocks/block.h
  ntcp2/blocks/date_time.h
  ntcp2/blocks/meta.h
  ntcp2/blocks/options.h
  ntcp2/blocks/router_info.h

  # Router
  ntcp2/router/address.h
  ntcp2/router/identity.h
  ntcp2/router/info.h
  ntcp2/router/mapping.h
  ntcp2/router/meta.h
  ntcp2/router/meta/address.h
  ntcp2/router/meta/certificate.h
  ntcp2/router/meta/identity.h
  ntcp2/router/meta/info.h
  ntcp2/router/meta/mapping.h

  # Session Request
  ntcp2/session_request/kdf.h
  ntcp2/session_request/meta.h
  ntcp2/session_request/options.h
  ntcp2/session_request/session_request.h

  # Session Created
  ntcp2/session_created/kdf.h
  ntcp2/session_created/meta.h
  ntcp2/session_created/options.h
  ntcp2/session_created/session_created.h

  # Session Confirmed
  ntcp2/session_confirmed/kdf.h
  ntcp2/session_confirmed/meta.h
  ntcp2/session_confirmed/session_confirmed.h

  # Data Phase
  ntcp2/data_phase/kdf.h
  ntcp2/data_phase/data_phase.h

  # Session
  ntcp2/session/manager.h
  ntcp2/session/session.h)

set_target_properties(tini2p-core PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(tini2p-core PRIVATE tini2p-priv)
