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

#include "src/crypto/aes.h"

namespace crypto = tini2p::crypto;

using tini2p::crypto::AES;
using dec_m = AES::decrypt_m;
using enc_m = AES::encrypt_m;

struct AESFixture
{
  AESFixture() : k(AES::create_key_iv()), aes(k.key, k.iv)
  {
    in.fill(0xBE);
  }

  AES::key_iv_t k;
  std::array<std::uint8_t, AES::BlockLen * 3> in, out;
  AES aes;
};

TEST_CASE("AES creates key and IV")
{
  AES::key_iv_t k;
  REQUIRE(k.key.size() == AES::KeyLen);
  REQUIRE(k.iv.size() == AES::IVLen);
}

TEST_CASE_METHOD(AESFixture, "AES CBC sets key", "[aes]")
{
  REQUIRE_NOTHROW(AES(k.key, k.iv));
  REQUIRE_NOTHROW(AES(k.key, k.iv).rekey(k.key, k.iv));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts block(s) of data", "[aes]")
{
  AES::block_t in, out;
  std::array<std::uint8_t, AES::BlockLen * 3> blocks;
  crypto::RandBytes(in);

  REQUIRE_NOTHROW(aes.Process<enc_m>(in.data(), in.size()));
  REQUIRE_NOTHROW(aes.Process<enc_m>(blocks.data(), blocks.size()));
  REQUIRE_NOTHROW(
      aes.Process<enc_m>(out.data(), out.size(), in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC decrypts a block(s) of data", "[aes]")
{
  AES::block_t in, out;
  std::array<std::uint8_t, AES::BlockLen * 3> blocks;
  crypto::RandBytes(in);

  REQUIRE_NOTHROW(aes.Process<dec_m>(in.data(), in.size()));
  REQUIRE_NOTHROW(aes.Process<dec_m>(blocks.data(), blocks.size()));
  REQUIRE_NOTHROW(
      aes.Process<dec_m>(out.data(), out.size(), in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts and decrypts back to plaintext", "[aes]")
{
  using Catch::Matchers::Equals;

  REQUIRE_NOTHROW(aes.Process<enc_m>(out.data(), out.size(), in.data(), in.size()));

  // decrypt in place
  REQUIRE_NOTHROW(aes.Process<dec_m>(out.data(), out.size()));

  REQUIRE_THAT(
      std::string(out.begin(), out.end()),
      Equals(std::string(in.begin(), in.end())));
}

TEST_CASE_METHOD(AESFixture, "AES CBC rejects null buffer", "[aes]")
{
  REQUIRE_THROWS(aes.Process<enc_m>(nullptr, out.size(), in.data(), in.size()));
  REQUIRE_THROWS(aes.Process<enc_m>(out.data(), out.size(), nullptr, in.size()));

  REQUIRE_THROWS(aes.Process<dec_m>(nullptr, out.size(), in.data(), in.size()));
  REQUIRE_THROWS(aes.Process<dec_m>(out.data(), out.size(), nullptr, in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC rejects null size", "[aes]")
{
  REQUIRE_THROWS(aes.Process<enc_m>(out.data(), 0, in.data(), in.size()));
  REQUIRE_THROWS(aes.Process<enc_m>(out.data(), out.size(), in.data(), 0));

  REQUIRE_THROWS(aes.Process<dec_m>(out.data(), 0, in.data(), in.size()));
  REQUIRE_THROWS(aes.Process<dec_m>(out.data(), out.size(), in.data(), 0));
}
