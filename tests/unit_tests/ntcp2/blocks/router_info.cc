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

#include "src/ntcp2/blocks/router_info.h"

namespace meta = ntcp2::meta::block;

struct RouterInfoBlockFixture
{
  RouterInfoBlockFixture() : info(new ntcp2::router::Info()), block(info.get())
  {
  }

  std::unique_ptr<ntcp2::router::Info> info;
  ntcp2::RouterInfoBlock block;
};

TEST_CASE_METHOD(
    RouterInfoBlockFixture,
    "RouterInfoBlock has a block ID",
    "[block]")
{
  REQUIRE(block.type() == meta::RouterInfoID);
}

TEST_CASE_METHOD(
    RouterInfoBlockFixture,
    "RouterInfoBlock has a block size",
    "[block]")
{
  REQUIRE(block.data_size() >= meta::MinRouterInfoSize);
  REQUIRE(block.data_size() <= meta::MaxRouterInfoSize);
}

TEST_CASE_METHOD(
    RouterInfoBlockFixture,
    "RouterInfoBlock serializes and deserializes a valid block",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  REQUIRE_NOTHROW(block.deserialize());
}

TEST_CASE_METHOD(
    RouterInfoBlockFixture,
    "RouterInfoBlock fails to deserialize invalid ID",
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
    RouterInfoBlockFixture,
    "RouterInfoBlock fails to deserialize invalid size",
    "[block]")
{
  // serialize a valid block
  REQUIRE_NOTHROW(block.serialize());

  // invalidate the size
  ntcp2::write_bytes(&block.buffer()[meta::SizeOffset], meta::MaxRouterInfoSize + 1);
  REQUIRE_THROWS(block.deserialize());

  ntcp2::write_bytes(&block.buffer()[meta::SizeOffset], meta::MinRouterInfoSize - 1);
  REQUIRE_THROWS(block.deserialize());
}
