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

#include "src/data/router/info.h"

namespace meta = tini2p::meta::router::info;

using tini2p::data::Info;

struct RouterInfoFixture
{
  RouterInfoFixture() : info() {}

  Info info;
};

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid router identity", "[ri]")
{
  REQUIRE(info.identity().size() == Info::identity_t::DefaultSize);
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid date", "[ri]")
{
  REQUIRE(info.date());
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid addresses", "[ri]")
{
  REQUIRE(info.addresses().empty());
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid options", "[ri]")
{
  using Catch::Matchers::Equals;

  const auto noise_i = info.options().entry(std::string("i"));
  const auto iv = info.iv();

  REQUIRE_THAT(
      std::string(noise_i.begin(), noise_i.end()),
      Equals(tini2p::crypto::Base64::Encode(iv.data(), iv.size())));
}

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid signature", "[ri]")
{
  const auto& sig = info.signature();

  REQUIRE(sig.size() == info.identity().signing().sig_len());
  REQUIRE(info.identity().signing().Verify(
      info.buffer().data(), info.size() - sig.size(), sig));
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo has serializes and deserializes empty addresses + options",
    "[ri]")
{
  REQUIRE_NOTHROW(info.serialize());
  REQUIRE_NOTHROW(info.deserialize());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo has serializes and deserializes non-empty addresses + options",
    "[ri]")
{
  info.addresses().emplace_back(tini2p::data::Address());
  info.options().add(std::string("host"), std::string("127.0.0.1"));

  REQUIRE_NOTHROW(info.serialize());
  REQUIRE_NOTHROW(info.deserialize());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo can sign a message with its router identity",
    "[ri]")
{
  Info::signature_t sig;
  Info::identity_t::signing_t::message_t msg(19);
  tini2p::crypto::RandBytes(msg);

  REQUIRE_NOTHROW(info.identity().signing().Sign(msg.data(), msg.size(), sig));
}
