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

set(LibreSSL_ROOT ${PROJECT_SOURCE_DIR}/deps/libressl)

add_library(LibreSSL::LibreSSL SHARED IMPORTED)

set(LibreSSL_INC ${LibreSSL_ROOT}/include/openssl)

find_path(LibreSSL_INCLUDE_DIR
  NAMES evp.h crypto.h ssl.h
  PATHS ${LibreSSL_INC}
  NO_DEFAULT_PATH)

set_target_properties(LibreSSL::LibreSSL PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${LibreSSL_INCLUDE_DIR}")

target_include_directories(LibreSSL::LibreSSL INTERFACE ${LibreSSL_INCLUDE_DIR})

include(ProcessorCount)
ProcessorCount(ThreadNum)
if (NOT N EQUAL 0)
  set(MAKE_ARGS -j${TheadNum})
endif()

set(LibreSSL_BUILD "${LibreSSL_ROOT}/build")

set(BYPRODUCT
  ${LibreSSL_BUILD}/crypto/libcrypto.a
  ${LibreSSL_BUILD}/ssl/libssl.a
  ${LibreSSL_BUILD}/tls/libtls.a)

include(ExternalProject)
ExternalProject_Add(libressl
  SOURCE_DIR ${LibreSSL_ROOT}
  BUILD_IN_SOURCE TRUE
  INSTALL_DIR "${LibreSSL_BUILD}"
  CONFIGURE_COMMAND cd ${LibreSSL_BUILD} && cmake .. -DENABLE_NC=off -DLIBRESSL_APPS=off -DCMAKE_BUILD_TYPE=Shared
  BUILD_COMMAND $(MAKE) ${MAKE_ARGS}
  COMMAND ""
  INSTALL_COMMAND "")

add_dependencies(LibreSSL::LibreSSL libressl)
