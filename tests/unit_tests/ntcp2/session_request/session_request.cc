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

#include "src/ntcp2/session_request/session_request.h"

namespace meta = ntcp2::meta::session_request;

struct SessionRequestFixture
{
  SessionRequestFixture()
  {
    const ntcp2::exception::Exception ex{"SessionRequestFixture", __func__};

    ntcp2::noise::init_handshake<ntcp2::Initiator>(&initiator_state, ex);
    ntcp2::noise::init_handshake<ntcp2::Responder>(&responder_state, ex);

    // set dummy router hash (unrealistic)
    ntcp2::router::IdentHash router_hash;
    ntcp2::crypto::RandBytes(router_hash.data(), router_hash.size());

    // set dummy static IV (unrealistic)
    ntcp2::crypto::aes::IV iv;
    ntcp2::crypto::RandBytes(iv.data(), iv.size());

    initiator = std::make_unique<ntcp2::SessionRequest<ntcp2::Initiator>>(
        initiator_state, router_hash, iv);

    responder = std::make_unique<ntcp2::SessionRequest<ntcp2::Responder>>(
        responder_state, router_hash, iv);
  }

  ntcp2::crypto::pk::X25519 remote_key;
  ntcp2::SessionRequestMessage message;

  NoiseHandshakeState *initiator_state, *responder_state;
  std::unique_ptr<ntcp2::SessionRequest<ntcp2::Initiator>> initiator;
  std::unique_ptr<ntcp2::SessionRequest<ntcp2::Responder>> responder;
};

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequest initiator writes message after KDF",
    "[srq]")
{
  REQUIRE_NOTHROW(initiator->kdf().generate_keys());
  REQUIRE_NOTHROW(initiator->kdf().derive_keys(remote_key));
  REQUIRE_NOTHROW(initiator->ProcessMessage(message));
}

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequest responder reads message after KDF",
    "[srq]")
{
  using Catch::Matchers::Equals;

  REQUIRE_NOTHROW(responder->kdf().generate_keys());
  REQUIRE_NOTHROW(responder->kdf().get_local_public_key(remote_key));

  REQUIRE_NOTHROW(initiator->kdf().generate_keys());
  REQUIRE_NOTHROW(initiator->kdf().derive_keys(remote_key));
  REQUIRE_NOTHROW(initiator->ProcessMessage(message));

  const auto& ciphertext = message.ciphertext;
  const auto& padding = message.padding;

  REQUIRE_NOTHROW(responder->kdf().derive_keys());
  REQUIRE_NOTHROW(responder->ProcessMessage(message));

  REQUIRE_THAT(
      std::string(initiator->x().begin(), initiator->x().end()),
      Equals(std::string(responder->x().begin(), responder->x().end())));

  REQUIRE_THAT(
      std::string(ciphertext.begin(), ciphertext.end()),
      Equals(
          std::string(message.ciphertext.begin(), message.ciphertext.end())));

  REQUIRE(padding.size() == message.options.pad_len);

  REQUIRE_THAT(
      std::string(padding.begin(), padding.end()),
      Equals(std::string(message.padding.begin(), message.padding.end())));
}

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequest initiator fails to write without KDF",
    "[srq]")
{
  REQUIRE_THROWS(initiator->ProcessMessage(message));
}

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequest responder fails to read without KDF",
    "[srq]")
{
  message.data.resize(ntcp2::meta::session_request::MinSize);
  REQUIRE_THROWS(responder->ProcessMessage(message));
}

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequest responder fails to read invalid message size",
    "[srq]")
{
  message.data.resize(meta::MinSize - 1);
  REQUIRE_THROWS(responder->ProcessMessage(message));

  message.data.resize(meta::MaxSize + 1);
  REQUIRE_THROWS(responder->ProcessMessage(message));
}

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequestOptions rejects too large message 3 pt. 2 length",
    "[srq]")
{
  REQUIRE_THROWS(message.options.update(meta::MinMsg3Pt2Size - 1, {}));
  REQUIRE_THROWS(message.options.update(meta::MaxMsg3Pt2Size + 1, {}));
}

TEST_CASE_METHOD(
    SessionRequestFixture,
    "SessionRequestOptions rejects too large padding length",
    "[srq]")
{
  REQUIRE_THROWS(message.options.update({}, meta::MaxPaddingSize + 1));
}
