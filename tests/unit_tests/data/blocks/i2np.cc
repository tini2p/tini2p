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

#include "src/data/blocks/i2np.h"

namespace meta = tini2p::meta::block;

using tini2p::data::I2NPBlock;

struct I2NPBlockFixture
{
  I2NPBlock block;
};

TEST_CASE_METHOD(
    I2NPBlockFixture,
    "I2NPBlock has a block ID",
    "[block]")
{
  REQUIRE(block.type() == meta::I2NPMessageID);
}

TEST_CASE_METHOD(I2NPBlockFixture, "I2NPBlock has a size", "[block]")
{
  REQUIRE(block.data_size() >= meta::MinI2NPSize);
  REQUIRE(block.data_size() <= meta::MaxI2NPSize);
  REQUIRE(block.size() == meta::HeaderSize + block.data_size());
  REQUIRE(block.size() == block.buffer().size());
}

TEST_CASE_METHOD(I2NPBlockFixture, "I2NPBlock has an expiration", "[block]")
{
  REQUIRE(block.expiration() > tini2p::time::now_s());
}

TEST_CASE_METHOD(
    I2NPBlockFixture,
    "I2NPBlock serializes and deserializes from the buffer",
    "[block]")
{
  // serialize to buffer
  REQUIRE_NOTHROW(block.serialize());

  // create from a valid buffer range
  const auto& buf = block.buffer();
  REQUIRE_NOTHROW(I2NPBlock(buf.begin(), buf.end()));

  // deserialize from buffer
  REQUIRE_NOTHROW(block.deserialize());

  REQUIRE(block.type() == meta::I2NPMessageID);
  REQUIRE(block.msg_id() != 0);
  REQUIRE(block.size() == meta::HeaderSize + block.data_size());
  REQUIRE(block.buffer().size() == block.size());
}

TEST_CASE_METHOD(
    I2NPBlockFixture,
    "I2NPBlock fails to deserialize invalid ID",
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
    I2NPBlockFixture,
    "I2NPBlock fails to deserialize invalid size",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the size 
  tini2p::write_bytes(&block.buffer()[meta::SizeOffset], meta::MinI2NPSize - 1);
  REQUIRE_THROWS(block.deserialize());

  tini2p::write_bytes(&block.buffer()[meta::SizeOffset], meta::MaxI2NPSize + 1);
  REQUIRE_THROWS(block.deserialize());
}

TEST_CASE_METHOD(
    I2NPBlockFixture,
    "I2NPBlock fails to deserialize invalid expiration",
    "[block]")
{
  using tini2p::time::now_s;
  using boost::endian::big_uint32_t;

  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the expiration (at expiration)
  tini2p::write_bytes(
      &block.buffer()[meta::ExpirationOffset], big_uint32_t(now_s()));
  REQUIRE_THROWS(block.deserialize());

  // invalidate the expiration (past expiration)
  tini2p::write_bytes(
      &block.buffer()[meta::ExpirationOffset], big_uint32_t(now_s() - 1));
  REQUIRE_THROWS(block.deserialize());
}
