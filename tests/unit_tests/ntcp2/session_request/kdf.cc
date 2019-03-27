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

#include "src/ntcp2/session_request/kdf.h"

using tini2p::ntcp2::Initiator;
using tini2p::ntcp2::Responder;
using tini2p::ntcp2::SessionRequestKDF;

struct SessionRequestKDFFixture
{
  SessionRequestKDFFixture()
  {
    const tini2p::exception::Exception ex{"SessionRequestKDFFixture", __func__};

    tini2p::ntcp2::noise::init_handshake<Initiator>(&initiator_state, ex);
    tini2p::ntcp2::noise::init_handshake<Responder>(&responder_state, ex);

    initiator_kdf = std::make_unique<SessionRequestKDF>(initiator_state);
    responder_kdf = std::make_unique<SessionRequestKDF>(responder_state);
  }

  NoiseHandshakeState *initiator_state, *responder_state;
  std::unique_ptr<SessionRequestKDF> initiator_kdf, responder_kdf;
  tini2p::crypto::X25519::pubkey_t key;
};

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF sets remote public key",
    "[srq_kdf]")
{
  REQUIRE_NOTHROW(initiator_kdf->set_remote_key(key));
}

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF generates local keypair",
    "[srq_kdf]")
{
  REQUIRE_NOTHROW(initiator_kdf->generate_keys());
}

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF derives initiator session request keys",
    "[srq_kdf]")
{
  REQUIRE_NOTHROW(initiator_kdf->generate_keys());
  REQUIRE_NOTHROW(initiator_kdf->Derive(key));
}

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF derives responder session request keys",
    "[srq_kdf]")
{
  REQUIRE_NOTHROW(responder_kdf->generate_keys());
  REQUIRE_NOTHROW(responder_kdf->Derive());
}

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF fails to derive initiator keys without remote static key",
    "[srq_kdf]")
{
  REQUIRE_NOTHROW(initiator_kdf->generate_keys());
  REQUIRE_THROWS(initiator_kdf->Derive());
}

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF fails to derive initiator keys without local keypair",
    "[srq_kdf]")
{
  REQUIRE_NOTHROW(initiator_kdf->set_remote_key(key));
  REQUIRE_THROWS(initiator_kdf->Derive());
}

TEST_CASE_METHOD(
    SessionRequestKDFFixture,
    "SessionRequestKDF fails to derive responder keys without local keypair",
    "[srq_kdf]")
{
  REQUIRE_THROWS(responder_kdf->Derive());
}

TEST_CASE("SessionRequestKDF rejects null handshake state", "[srq_kdf]")
{
  REQUIRE_THROWS(SessionRequestKDF(nullptr));
}
