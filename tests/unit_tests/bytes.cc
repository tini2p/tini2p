/* copyright (c) 2018, tini2p
 * all rights reserved.
 *
 * redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * this software is provided by the copyright holders and contributors "as is"
 * and any express or implied warranties, including, but not limited to, the
 * implied warranties of merchantability and fitness for a particular purpose are
 * disclaimed. in no event shall the copyright holder or contributors be liable
 * for any direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute goods or
 * services; loss of use, data, or profits; or business interruption) however
 * caused and on any theory of liability, whether in contract, strict liability,
 * or tort (including negligence or otherwise) arising in any way out of the use
 * of this software, even if advised of the possibility of such damage.
*/

#include <catch2/catch.hpp>

#include "src/bytes.h"

struct BytesFixture
{
  BytesFixture()
  {
    buf.resize(short_bytes.size());
  }

  std::vector<std::uint8_t> buf;
  const std::array<std::uint8_t, 3> short_bytes{{0x69, 0x32, 0x70}};
};

TEST_CASE_METHOD(BytesFixture, "Bytes writes integral byte", "[byte]")
{
  using Catch::Matchers::Equals;

  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), short_bytes.front()));
  REQUIRE(buf.front() == short_bytes.front());

  constexpr std::uint8_t u8 = 0xF0;
  constexpr std::int8_t i8 = 0x0D;

  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), u8));
  REQUIRE(buf.front() == u8);

  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), i8));
  REQUIRE(buf.front() == i8);
}

TEST_CASE_METHOD(BytesFixture, "Bytes writes integral bytes", "[byte]")
{
  std::uint16_t u16 = 0xDEAD;
  std::uint32_t u32 = 0xBEEF;
  std::uint64_t u64 = 0xFADED;

  std::int16_t i16 = 0xDEAD;
  std::int32_t i32 = 0xBEEF;
  std::int64_t i64 = 0xFADED;

  std::size_t tmp = u16;
  buf.resize(sizeof(u16));
  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), u16));
  REQUIRE_NOTHROW(tini2p::read_bytes(buf.data(), u16));
  REQUIRE(u16 == tmp);

  tmp = u32;
  buf.resize(sizeof(u32));
  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), u32));
  REQUIRE_NOTHROW(tini2p::read_bytes(buf.data(), u32));
  REQUIRE(u32 == tmp);

  tmp = u64;
  buf.resize(sizeof(u64));
  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), u64));
  REQUIRE_NOTHROW(tini2p::read_bytes(buf.data(), u64));
  REQUIRE(u64 == tmp);

  tmp = i16;
  buf.resize(sizeof(i16));
  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), i16));
  REQUIRE_NOTHROW(tini2p::read_bytes(buf.data(), i16));
  REQUIRE(i16 == tmp);

  tmp = i32;
  buf.resize(sizeof(i32));
  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), i32));
  REQUIRE_NOTHROW(tini2p::read_bytes(buf.data(), i32));
  REQUIRE(i32 == tmp);

  tmp = i64;
  buf.resize(sizeof(i64));
  REQUIRE_NOTHROW(tini2p::write_bytes(buf.data(), i64));
  REQUIRE_NOTHROW(tini2p::read_bytes(buf.data(), i64));
  REQUIRE(i64 == tmp);

  buf.resize(sizeof(u64) + sizeof(i64));
  tini2p::BytesWriter<decltype(buf)> writer(buf);
  tini2p::BytesReader<decltype(buf)> reader(buf);

  tmp = u64;
  REQUIRE_NOTHROW(writer.write_bytes(u64));
  REQUIRE_NOTHROW(reader.read_bytes(u64));
  REQUIRE(u64 == tmp);

  tmp = i64;
  REQUIRE_NOTHROW(writer.write_bytes(i64));
  REQUIRE_NOTHROW(reader.read_bytes(i64));
  REQUIRE(i64 == tmp);
}

TEST_CASE_METHOD(BytesFixture, "Bytes writes buffer bytes", "[byte]")
{
  using Catch::Matchers::Equals;

  buf.resize(short_bytes.size());
  REQUIRE_NOTHROW(tini2p::BytesWriter<decltype(buf)>(buf).write_data(short_bytes));

  const std::string buf_str{buf.begin(), buf.end()},
      sb_str{short_bytes.begin(), short_bytes.end()};

  REQUIRE_THAT(buf_str, Equals(sb_str));
}

TEST_CASE_METHOD(BytesFixture, "Bytes reads buffer bytes", "[byte]")
{
  using Catch::Matchers::Equals;

  buf.resize(short_bytes.size());

  REQUIRE_NOTHROW(
      tini2p::BytesReader<decltype(short_bytes)>(short_bytes).read_data(buf));

  const std::string buf_str{buf.begin(), buf.end()},
      sb_str{short_bytes.begin(), short_bytes.end()};

  REQUIRE_THAT(buf_str, Equals(sb_str));
}

TEST_CASE_METHOD(BytesFixture, "Bytes resets to beginning of buffer", "[byte]")
{
  using Catch::Matchers::Equals;

  buf.resize(short_bytes.size());
  auto tmp_buf = buf;

  tini2p::BytesReader<decltype(short_bytes)> reader(short_bytes);

  REQUIRE_NOTHROW(reader.read_data(buf));
  REQUIRE_NOTHROW(reader.reset());
  REQUIRE_NOTHROW(reader.read_data(tmp_buf));

  const std::string buf_str{buf.begin(), buf.end()},
      tmp_str{tmp_buf.begin(), tmp_buf.end()};

  REQUIRE_THAT(buf_str, Equals(tmp_str));
}

TEST_CASE_METHOD(BytesFixture, "Bytes fails to read buffer overflow", "[byte]")
{
  buf.resize(short_bytes.size() * 2);

  REQUIRE_THROWS(
      tini2p::BytesReader<decltype(short_bytes)>(short_bytes).read_data(buf));

  buf.resize(1);
  std::uint16_t over;

  REQUIRE_THROWS(tini2p::BytesReader<decltype(buf)>(buf).read_bytes(over));
}

TEST_CASE_METHOD(BytesFixture, "Bytes fails to write buffer overflow", "[byte]")
{
  buf.resize(short_bytes.size() - 1);

  REQUIRE_THROWS(tini2p::BytesWriter<decltype(buf)>(buf).write_data(short_bytes));

  buf.resize(1);
  std::uint16_t over;

  REQUIRE_THROWS(tini2p::BytesWriter<decltype(buf)>(buf).write_bytes(over));
}

TEST_CASE_METHOD(BytesFixture, "Bytes fails buffer overflow by skipping bytes", "[byte]")
{
  REQUIRE_THROWS(tini2p::BytesWriter<decltype(buf)>(buf).skip_bytes(buf.size() + 1));
  REQUIRE_THROWS(tini2p::BytesReader<decltype(buf)>(buf).skip_bytes(buf.size() + 1));
}
