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

#include "src/data/blocks/termination.h"

using tini2p::data::TerminationBlock;

struct TerminationBlockFixture
{
  TerminationBlock block;
};

TEST_CASE_METHOD(
    TerminationBlockFixture,
    "TerminationBlock has a block ID",
    "[block]")
{
  REQUIRE(block.type() == TerminationBlock::type_t::Termination);
}

TEST_CASE_METHOD(TerminationBlockFixture, "TerminationBlock has a size", "[block]")
{
  REQUIRE(block.data_size() >= TerminationBlock::MinTermLen);
  REQUIRE(block.data_size() <= TerminationBlock::MaxTermLen);
  REQUIRE(block.size() == TerminationBlock::HeaderLen + block.data_size());
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
  const auto& buf = block.buffer();
  REQUIRE_NOTHROW(TerminationBlock(buf.begin(), buf.end()));

  // deserialize from buffer
  REQUIRE_NOTHROW(block.deserialize());

  REQUIRE(block.type() == TerminationBlock::type_t::Termination);
  REQUIRE(block.size() == TerminationBlock::HeaderLen + block.data_size());
  REQUIRE(block.reason() == TerminationBlock::reason_t::NormalClose);
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
  ++block.buffer()[TerminationBlock::TypeOffset];
  REQUIRE_THROWS(block.deserialize());

  block.buffer()[TerminationBlock::TypeOffset] -= 2;
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
  tini2p::write_bytes(
      &block.buffer()[TerminationBlock::SizeOffset], big_uint16_t(TerminationBlock::MinTermLen - 1));
  REQUIRE_THROWS(block.deserialize());

  tini2p::write_bytes(
      &block.buffer()[TerminationBlock::SizeOffset], big_uint16_t(TerminationBlock::MaxTermLen + 1));
  REQUIRE_THROWS(block.deserialize());
}
