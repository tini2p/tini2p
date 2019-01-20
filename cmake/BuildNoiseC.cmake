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
#
# Partly based on BuildCryptoPP.cmake from Kovri Project

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
