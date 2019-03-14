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

#include "src/data/blocks/options.h"

using tini2p::data::OptionsBlock;

struct OptionsBlockFixture
{
  OptionsBlock block;
};

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock has a block ID",
    "[block]")
{
  REQUIRE(block.type() == OptionsBlock::type_t::Options);
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock has a block size",
    "[block]")
{
  REQUIRE(block.data_size() == OptionsBlock::OptionsLen);
  REQUIRE(block.size() == OptionsBlock::HeaderLen + OptionsBlock::OptionsLen);
  REQUIRE(block.size() == block.buffer().size());
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock serializes a valid block",
    "[block]")
{
  REQUIRE_NOTHROW(block.serialize());

  // check min padding ratios
  block.tmin = block.min_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  block.tmax = block.min_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  block.rmin = block.min_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  block.rmax = block.min_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  // check max padding ratios
  block.tmax = block.max_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  block.tmin = block.max_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  block.rmax = block.max_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());

  block.rmin = block.max_padding_ratio();
  REQUIRE_NOTHROW(block.serialize());
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock serializes and deserializes a valid block",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  REQUIRE_NOTHROW(block.deserialize());
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock fails to deserialize invalid ID",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the block ID
  ++block.buffer()[OptionsBlock::TypeOffset];

  REQUIRE_THROWS(block.deserialize());

  block.buffer()[OptionsBlock::TypeOffset] += 2;

  REQUIRE_THROWS(block.deserialize());
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock fails to deserialize invalid size",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the size 
  ++block.buffer()[OptionsBlock::SizeOffset];

  REQUIRE_THROWS(block.deserialize());

  // invalidate the size 
  block.buffer()[OptionsBlock::SizeOffset] -= 2;

  REQUIRE_THROWS(block.deserialize());
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock fails to serialize invalid parameters",
    "[block]")
{
  // check invalid parameters (lowerbound)
  block.tmin = block.min_padding_ratio() - 1;
  REQUIRE_THROWS(block.serialize());

  block.tmin = block.min_padding_ratio();
  block.tmax = block.min_padding_ratio() - 1;
  REQUIRE_THROWS(block.serialize());

  block.tmax = block.min_padding_ratio();
  block.rmin = block.min_padding_ratio() - 1;
  REQUIRE_THROWS(block.serialize());

  block.rmin = block.min_padding_ratio();
  block.rmax = block.min_padding_ratio() - 1;
  REQUIRE_THROWS(block.serialize());

  // check invalid parameters (upperbound)
  block.rmax = block.min_padding_ratio();
  block.tmin = block.max_padding_ratio() + 1;
  REQUIRE_THROWS(block.serialize());

  block.tmin = block.max_padding_ratio();
  block.tmax = block.max_padding_ratio() + 1;
  REQUIRE_THROWS(block.serialize());

  block.tmax = block.max_padding_ratio();
  block.rmin = block.max_padding_ratio() + 1;
  REQUIRE_THROWS(block.serialize());

  block.rmin = block.max_padding_ratio();
  block.rmax = block.max_padding_ratio() + 1;
  REQUIRE_THROWS(block.serialize());
}

TEST_CASE_METHOD(
    OptionsBlockFixture,
    "OptionsBlock fails to deserialize invalid parameters",
    "[block]")
{
  // Testing invalid header values done above.
  //
  // Parameters cannot be deserialized out of range.
  //   The only ranged parameters are cast as `(std::uint8_t)val / 16.0` (all in-range float values).
  //   All invalid values just wrap-around, i.e. uint8_MAX + 1 = uint8_MIN = 0
}
