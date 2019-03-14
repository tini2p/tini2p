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

#include "src/data/blocks/padding.h"

using tini2p::data::PaddingBlock;

struct PaddingBlockFixture
{
  PaddingBlock block;
};

TEST_CASE_METHOD(PaddingBlockFixture, "PaddingBlock has a valid block ID", "[block]")
{
  REQUIRE(block.type() == PaddingBlock::type_t::Padding);
}

TEST_CASE_METHOD(PaddingBlockFixture, "PaddingBlock has a valid size", "[block]")
{
  REQUIRE(block.size() == block.buffer().size());
  REQUIRE(block.data_size() <= PaddingBlock::MaxPaddingLen);
  REQUIRE(block.data_size() == block.padding().size());
}

TEST_CASE_METHOD(
    PaddingBlockFixture,
    "PaddingBlock serializes and deserializes",
    "[block]")
{
  // serialize to buffer
  REQUIRE_NOTHROW(block.serialize());

  // deserialize from buffer
  REQUIRE_NOTHROW(block.deserialize());

  REQUIRE(block.type() == PaddingBlock::type_t::Padding);
  REQUIRE(block.size() == block.buffer().size());
  REQUIRE(block.data_size() <= PaddingBlock::MaxPaddingLen);
  REQUIRE(block.data_size() == block.padding().size());
}

TEST_CASE_METHOD(
    PaddingBlockFixture,
    "PaddingBlock fails to deserialize invalid ID",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the block ID
  ++block.buffer()[PaddingBlock::TypeOffset];
  REQUIRE_THROWS(block.deserialize());

  block.buffer()[PaddingBlock::TypeOffset] -= 2;
  REQUIRE_THROWS(block.deserialize());
}

TEST_CASE_METHOD(
    PaddingBlockFixture,
    "PaddingBlock fails to deserialize invalid size",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the size
  REQUIRE_NOTHROW(tini2p::write_bytes(
      &block.buffer()[PaddingBlock::SizeOffset], PaddingBlock::MaxPaddingLen + 1));

  REQUIRE_THROWS(block.deserialize());
}
