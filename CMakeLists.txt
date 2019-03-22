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
# Parts used from the Kovri I2p Router Project Copyright (c) 2013-2018

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(tini2p-priv CXX)

option(WITH_COVERAGE "Build with coverage instrumentation" OFF)
option(WITH_TESTS "Build test suite" OFF)
option(WITH_NET_TESTS "Build net test suite" OFF)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_library(tini2p-priv INTERFACE)

# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7420 
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Release>:NDEBUG>)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Require C++14 support (minimum version compilers guarantee this)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find NoiseC library
find_package(NoiseC REQUIRED)
if (NOT TARGET NoiseC::NoiseC)
  include(BuildNoiseC)

  if (NOT TARGET NoiseC::NoiseC)
    message(FATAL_ERROR "Could not find NoiseC.")
  endif()
endif()
target_link_libraries(tini2p-priv INTERFACE NoiseC::NoiseC)
# end-noise-c

# Find libSodium crypto library
find_package(sodium REQUIRED)
if(NOT ${sodium_FOUND})
  message(FATAL_ERROR "libSodium not found or requirement not satisfied.")
endif()
target_include_directories(tini2p-priv INTERFACE ${sodium_INCLUDE_DIR})
if(${CMAKE_BUILD_TYPE} EQUAL Debug)
  target_link_libraries(tini2p-priv INTERFACE ${sodium_LIBRARY_DEBUG})
else()
  target_link_libraries(tini2p-priv INTERFACE ${sodium_LIBRARY_RELEASE})
endif()
# end-sodium

# Include tiny-AES-c
target_include_directories(tini2p-priv INTERFACE ${CMAKE_SOURCE_DIR}/deps/tiny-AES-c) 
# end-tiny-AES-c

find_package(Threads)
target_link_libraries(tini2p-priv INTERFACE ${CMAKE_THREAD_LIBS_INIT})

find_package(Boost 1.66 REQUIRED COMPONENTS system thread)
if (NOT Boost_FOUND)
  message(FATAL_ERROR "Boost not found or requirement not satisfied.")
endif()

target_link_libraries(tini2p-priv INTERFACE Boost::system Boost::thread)

add_subdirectory(src)

if (WITH_TESTS)
  if(WITH_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 --coverage")
  endif()

  add_subdirectory(tests/unit_tests)

  if (WITH_NET_TESTS)
    add_subdirectory(tests/net_tests)
  endif()
endif()
