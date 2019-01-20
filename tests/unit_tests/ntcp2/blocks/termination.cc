/* Copyright (c) 2019, tini2p
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <catch2/catch.hpp>

#include "src/ntcp2/blocks/termination.h"

namespace meta = ntcp2::meta::block;

struct TerminationBlockFixture
{
  ntcp2::TerminationBlock block;
};

TEST_CASE_METHOD(
    TerminationBlockFixture,
    "TerminationBlock has a block ID",
    "[block]")
{
  REQUIRE(block.type() == meta::TerminationID);
}

TEST_CASE_METHOD(TerminationBlockFixture, "TerminationBlock has a size", "[block]")
{
  REQUIRE(block.data_size() >= meta::MinTermSize);
  REQUIRE(block.data_size() <= meta::MaxTermSize);
  REQUIRE(block.size() == meta::HeaderSize + block.data_size());
  REQUIRE(block.size() == block.buffer().size());
}

TEST_CASE_METHOD(
    TerminationBlockFixture,
    "TerminationBlock serializes and deserializes from the buffer",
    "[block]")
{
  // serialize to buffer
  REQUIRE_NOTHROW(block.serialize());

  // create from a valid buffer range
  REQUIRE_NOTHROW(
      ntcp2::TerminationBlock(block.buffer().begin(), block.buffer().end()));

  // deserialize from buffer
  REQUIRE_NOTHROW(block.deserialize());

  REQUIRE(block.type() == meta::TerminationID);
  REQUIRE(block.size() == meta::HeaderSize + block.data_size());
  REQUIRE(block.reason() == meta::NormalClose);
  REQUIRE(block.buffer().size() == block.size());
}

TEST_CASE_METHOD(
    TerminationBlockFixture,
    "TerminationBlock fails to deserialize invalid ID",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the block ID
  ++block.buffer()[meta::TypeOffset];
  REQUIRE_THROWS(block.deserialize());

  block.buffer()[meta::TypeOffset] -= 2;
  REQUIRE_THROWS(block.deserialize());
}

TEST_CASE_METHOD(
    TerminationBlockFixture,
    "TerminationBlock fails to deserialize invalid size",
    "[block]")
{
  using boost::endian::big_uint16_t;

  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the size
  ntcp2::write_bytes(
      &block.buffer()[meta::SizeOffset], big_uint16_t(meta::MinTermSize - 1));
  REQUIRE_THROWS(block.deserialize());

  ntcp2::write_bytes(
      &block.buffer()[meta::SizeOffset], big_uint16_t(meta::MaxTermSize + 1));
  REQUIRE_THROWS(block.deserialize());
}
