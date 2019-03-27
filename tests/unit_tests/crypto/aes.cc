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

struct AESFixture
{
  AESFixture() : k(crypto::AES::create_key_iv()), aes(k.key, k.iv)
  {
    crypto::RandBytes(in);
  }

  crypto::AES::key_iv_t k;
  crypto::FixedSecBytes<crypto::AES::BlockLen * 3> in, out;
  crypto::AES aes;
};

TEST_CASE("AES creates key and IV")
{
  crypto::AES::key_iv_t k;
  REQUIRE(k.key.size() == crypto::AES::KeyLen);
  REQUIRE(k.iv.size() == crypto::AES::IVLen);
}

TEST_CASE_METHOD(AESFixture, "AES CBC sets key", "[aes]")
{
  REQUIRE_NOTHROW(crypto::AES(k.key, k.iv));
  REQUIRE_NOTHROW(crypto::AES(k.key, k.iv).rekey(k.key, k.iv));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts block(s) of data", "[aes]")
{
  crypto::AES::block_t in, out;
  std::array<std::uint8_t, crypto::AES::BlockLen * 3> blocks;
  crypto::RandBytes(in);

  REQUIRE_NOTHROW(aes.Encrypt(in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC decrypts a block(s) of data", "[aes]")
{
  crypto::AES::block_t in, out;
  crypto::FixedSecBytes<crypto::AES::BlockLen * 3> blocks;
  crypto::RandBytes(in);

  REQUIRE_NOTHROW(aes.Decrypt(in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts and decrypts back to plaintext", "[aes]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  decltype(in) t_in(in);

  // encrypt/decrypt buffer in-place
  REQUIRE_NOTHROW(aes.Encrypt(in.data(), in.size()));
  REQUIRE_NOTHROW(aes.Decrypt(in.data(), in.size()));

  REQUIRE_THAT(
      vec(in.begin(), in.end()), Equals(vec(t_in.begin(), t_in.end())));
}

TEST_CASE_METHOD(AESFixture, "AES CBC rejects null buffer", "[aes]")
{
  REQUIRE_THROWS(aes.Encrypt(nullptr, in.size()));
  REQUIRE_THROWS(aes.Decrypt(nullptr, in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC rejects null size", "[aes]")
{
  REQUIRE_THROWS(aes.Encrypt(in.data(), 0));
  REQUIRE_THROWS(aes.Decrypt(in.data(), 0));
}
