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

#include "src/crypto/rand.h"

#include "src/ntcp2/router/mapping.h"

namespace meta = ntcp2::meta::router::mapping;

struct MappingFixture
{
  MappingFixture()
  {
    min_kv.fill(0xbe);
    max_kv.fill(0xbe);
  }

  std::array<std::uint8_t, meta::MinKVSize> min_kv;
  std::array<std::uint8_t, meta::MaxKVSize> max_kv;
  ntcp2::router::Mapping map;
};

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping validates entry sizes",
    "[map]")
{
  const std::string kv_str(meta::MaxKVSize, 0xF);

  REQUIRE_NOTHROW(map.size());
  REQUIRE_NOTHROW(map.add(kv_str, kv_str));
  REQUIRE_NOTHROW(map.add(min_kv, min_kv));
  REQUIRE_NOTHROW(map.add(min_kv, max_kv));
  REQUIRE_NOTHROW(map.add(max_kv, min_kv));
  REQUIRE_NOTHROW(map.add(max_kv, max_kv));
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping rejects invalid entry sizes",
    "[map]")
{
  const std::string kv_str(meta::MaxKVSize + 1, 0xF);

  REQUIRE_THROWS(map.add(min_kv, kv_str));
  REQUIRE_THROWS(map.add(kv_str, min_kv));
  REQUIRE_THROWS(map.add(min_kv, std::vector<std::uint8_t>{}));
  REQUIRE_THROWS(map.add(std::vector<std::uint8_t>{}, min_kv));
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping rejects too many entries",
    "[map]")
{
  const ntcp2::router::MappingEntry entry(max_kv, max_kv);
  while(entry.size() + map.size() < meta::MaxSize)
    {  // generate random key for unique entries
      REQUIRE_NOTHROW(map.add(max_kv, max_kv));
      ntcp2::crypto::RandBytes(max_kv.data(), max_kv.size());
    }
  REQUIRE_THROWS(map.add(max_kv, max_kv));
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping serializes an empty mapping",
    "[map]")
{
  REQUIRE_NOTHROW(map.serialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping serializes a non-empty mapping",
    "[map]")
{
  for (std::uint8_t cnt = 0; cnt < 3; ++cnt)
    map.add(max_kv, max_kv);

  REQUIRE_NOTHROW(map.serialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping deserializes an empty mapping",
    "[map]")
{
  REQUIRE_NOTHROW(map.serialize());
  REQUIRE_NOTHROW(map.deserialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping deserializes a non-empty mapping",
    "[map]")
{
  namespace meta = ntcp2::meta::router::mapping;

  constexpr std::uint8_t num_entry = 3;
  for (std::uint8_t cnt = 0; cnt < num_entry; ++cnt)
    {
      ntcp2::crypto::RandBytes(min_kv.data(), min_kv.size());
      map.add(min_kv, min_kv);
    }

  REQUIRE_NOTHROW(map.serialize());
  REQUIRE_NOTHROW(map.deserialize());

  ntcp2::router::MappingEntry entry(min_kv, min_kv);
  REQUIRE(map.size() == meta::SizeSize + (num_entry * entry.size()));
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping fails to deserialize an invalid key length",
    "[map]")
{
  REQUIRE_NOTHROW(map.add(min_kv, min_kv));
  REQUIRE_NOTHROW(map.serialize());

  // will overrun the buffer if unchecked
  map.buffer().at(meta::KeySizeOffset) = 0xFF;
  REQUIRE_THROWS(map.deserialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping fails to deserialize an invalid value length",
    "[map]")
{
  ntcp2::router::MappingEntry entry(min_kv, min_kv);
  REQUIRE_NOTHROW(map.add(entry.key(), entry.value()));
  REQUIRE_NOTHROW(map.serialize());

  // will overrun the buffer if unchecked
  const auto& value_offset =
      meta::KeySizeOffset + entry.key().size() + meta::DelimSize;
  map.buffer().at(value_offset) = 0xFF;
  REQUIRE_THROWS(map.deserialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping fails to deserialize an invalid buffer length",
    "[map]")
{
  REQUIRE_NOTHROW(map.serialize());

  // invalidate the buffer size
  const auto tmp = map.buffer().back();
  REQUIRE_NOTHROW(map.buffer().pop_back());
  REQUIRE_THROWS(map.deserialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping fails to deserialize an invalid mapping length",
    "[map]")
{
  // invalidate the mapping size
  map.buffer().resize(1);
  map.buffer().at(meta::SizeOffset) = 0xFF;

  REQUIRE_THROWS(map.deserialize());
}

TEST_CASE_METHOD(
    MappingFixture,
    "Mapping fails to deserialize missing key-value delimiter",
    "[map]")
{
  ntcp2::router::MappingEntry entry(min_kv, min_kv);

  REQUIRE_NOTHROW(map.add(entry.key(), entry.value()));
  REQUIRE_NOTHROW(map.serialize());

  const std::uint8_t kv_delim = 0x3D;
  auto& buf = map.buffer();

  // find and remove the key-value delimiter ("=")
  const auto& kv_it = std::find(buf.begin(), buf.end(), kv_delim);

  REQUIRE_NOTHROW(buf.erase(kv_it));

  REQUIRE_THROWS(map.deserialize());
}
