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
  AESFixture() : dec(key, iv), enc(key, iv)
  {
    in.fill(0xBE);
    crypto::RandBytes(key.data(), key.size());
    crypto::RandBytes(iv.data(), iv.size());
  }

  crypto::aes::Key key;
  crypto::aes::IV iv;
  std::array<std::uint8_t, crypto::aes::BlockLen * 3> in, out;
  crypto::aes::CBCDecryption dec;
  crypto::aes::CBCEncryption enc;
};

TEST_CASE("AES creates key and IV")
{
  crypto::aes::KeyIV key_iv;

  REQUIRE_NOTHROW(key_iv = crypto::aes::create_key_iv());
  REQUIRE(key_iv.key.size() == crypto::aes::KeyLen);
  REQUIRE(key_iv.iv.size() == crypto::aes::IVLen);
}

TEST_CASE_METHOD(AESFixture, "AES CBC encryption sets key", "[aes]")
{
  REQUIRE_NOTHROW(crypto::aes::CBCEncryption(key, iv));
  REQUIRE_NOTHROW(crypto::aes::CBCEncryption(key, iv).rekey(key, iv));
}

TEST_CASE_METHOD(AESFixture, "AES CBC decryption sets key", "[aes]")
{
  REQUIRE_NOTHROW(crypto::aes::CBCDecryption(key, iv));
  REQUIRE_NOTHROW(crypto::aes::CBCDecryption(key, iv).rekey(key, iv));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts a block of data", "[aes]")
{
  crypto::aes::Block in, out;
  crypto::RandBytes(in.data(), in.size());

  REQUIRE_NOTHROW(enc.Process(out, in));

  REQUIRE_NOTHROW(enc.Process(out.data(), out.size(), in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts multiple blocks of data", "[aes]")
{
  REQUIRE_NOTHROW(enc.Process(out.data(), out.size(), in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC decrypts a block of data", "[aes]")
{
  crypto::aes::Block in, out;
  crypto::RandBytes(in.data(), in.size());

  REQUIRE_NOTHROW(dec.Process(out, in));

  REQUIRE_NOTHROW(dec.Process(out.data(), out.size(), in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC decrypts multiple blocks of data", "[aes]")
{
  REQUIRE_NOTHROW(dec.Process(out.data(), out.size(), in.data(), in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC encrypts and decrypts back to plaintext", "[aes]")
{
  using Catch::Matchers::Equals;

  REQUIRE_NOTHROW(enc.Process(out.data(), out.size(), in.data(), in.size()));

  // decrypt in place
  REQUIRE_NOTHROW(dec.Process(out.data(), out.size(), out.data(), out.size()));

  REQUIRE_THAT(
      std::string(out.begin(), out.end()),
      Equals(std::string(in.begin(), in.end())));
}

TEST_CASE_METHOD(AESFixture, "AES CBC rejects null buffer", "[aes]")
{
  REQUIRE_THROWS(enc.Process(nullptr, out.size(), in.data(), in.size()));
  REQUIRE_THROWS(enc.Process(out.data(), out.size(), nullptr, in.size()));

  REQUIRE_THROWS(dec.Process(nullptr, out.size(), in.data(), in.size()));
  REQUIRE_THROWS(dec.Process(out.data(), out.size(), nullptr, in.size()));
}

TEST_CASE_METHOD(AESFixture, "AES CBC rejects null size", "[aes]")
{
  REQUIRE_THROWS(enc.Process(out.data(), 0, in.data(), in.size()));
  REQUIRE_THROWS(enc.Process(out.data(), out.size(), in.data(), 0));

  REQUIRE_THROWS(dec.Process(out.data(), 0, in.data(), in.size()));
  REQUIRE_THROWS(dec.Process(out.data(), out.size(), in.data(), 0));
}
