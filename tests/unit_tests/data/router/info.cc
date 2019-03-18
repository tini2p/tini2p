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

using tini2p::data::Info;
using crypto_t = Info::identity_t::ecies_x25519_hmac_t;
using signing_t = Info::identity_t::eddsa_t;

struct RouterInfoFixture
{
  RouterInfoFixture() : info() {}

  Info info;
};

TEST_CASE_METHOD(RouterInfoFixture, "RouterInfo has valid router identity", "[ri]")
{
  REQUIRE(info.identity().size() == Info::identity_t::DefaultSize);
  REQUIRE(!info.identity().cert().locally_unreachable());
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
  const auto& ident = info.identity();
  const auto& sig_len =
      boost::apply_visitor([](const auto& v) { return v.size(); }, sig);

  REQUIRE(sig_len == ident.sig_len());
  REQUIRE(ident.Verify(info.buffer().data(), info.size() - sig_len, sig));
  REQUIRE(info.Verify());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo has serializes and deserializes empty addresses + options",
    "[ri]")
{
  REQUIRE_NOTHROW(info.serialize());
  REQUIRE_NOTHROW(info.deserialize());

  REQUIRE_NOTHROW(Info(info.buffer()));

  Info info_copy(info.buffer());
  REQUIRE(info_copy.Verify());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo has serializes and deserializes non-empty addresses + options",
    "[ri]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  info.addresses().emplace_back(tini2p::data::Address());
  info.options().add(std::string("host"), std::string("127.0.0.1"));

  REQUIRE_NOTHROW(info.serialize());
  REQUIRE_NOTHROW(info.deserialize());

  REQUIRE_NOTHROW(Info(info.buffer()));
  Info info_copy(info.buffer());

  REQUIRE_THAT(
      static_cast<vec>(info_copy.buffer()),
      Equals(static_cast<vec>(info.buffer())));

  const auto& sigkey0 =
      boost::get<signing_t>(info.identity().signing()).pubkey();

  const auto& sigkey1 =
      boost::get<signing_t>(info_copy.identity().signing()).pubkey();

  REQUIRE_THAT(
      vec(sigkey0.begin(), sigkey0.end()),
      Equals(vec(sigkey1.begin(), sigkey1.end())));

  const auto& sig0 = boost::get<signing_t::signature_t>(info.signature());
  const auto& sig1 = boost::get<signing_t::signature_t>(info_copy.signature());

  REQUIRE_THAT(
      vec(sig0.begin(), sig0.end()), Equals(vec(sig1.begin(), sig1.end())));

  REQUIRE(info_copy.identity().Verify(
      info_copy.buffer().data(), info_copy.size() - sig1.size(), sig1));

  REQUIRE(info_copy.Verify());
}

TEST_CASE_METHOD(
    RouterInfoFixture,
    "RouterInfo can sign a message with its router identity",
    "[ri]")
{
  Info::signature_v sig;
  signing_t::message_t msg(19);
  tini2p::crypto::RandBytes(msg);

  const auto& ident = info.identity();

  REQUIRE_NOTHROW(sig = ident.Sign(msg.data(), msg.size()));
  REQUIRE(ident.Verify(msg.data(), msg.size(), sig));
}
