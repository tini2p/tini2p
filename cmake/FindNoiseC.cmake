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

set(NOISEC_ROOT "${PROJECT_SOURCE_DIR}/deps/noise-c/build")

find_path(NoiseC_INCLUDE_DIR
  NAME protocol.h
  PATHS ${NOISEC_ROOT}/include
  PATH_SUFFIXES noise
  NO_DEFAULT_PATH)

find_path(NoiseC_LIBRARIES
  NAME libnoiseprotocol
  PATHS ${NOISEC_ROOT}/lib
  NO_DEFAULT_PATH)

if (EXISTS "${NoiseC_INCLUDE_DIR}" AND EXISTS "${NoiseC_LIBRARIES}" AND NOT TARGET NoiseC::NoiseC)
  add_library(NoiseC::NoiseC STATIC IMPORTED)

  set_target_properties(NoiseC::NoiseC PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${NoiseC_INCLUDE_DIR};${NoiseC_INCLUDE_DIR}/..")

  set_target_properties(NoiseC::NoiseC PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${NoiseC_LIBRARIES}")
endif()
