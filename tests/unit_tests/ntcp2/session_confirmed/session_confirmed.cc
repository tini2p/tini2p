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

#include "tests/unit_tests/mock/handshake.h"

struct SessionConfirmedFixture : public MockHandshake
{
  SessionConfirmedFixture()
  {
    ValidSessionRequest();
    ValidSessionCreated();
    InitializeSessionConfirmed();
  }
};

TEST_CASE_METHOD(
    SessionConfirmedFixture,
    "SessionConfirmed initiator writes message",
    "[sco]")
{
  REQUIRE_NOTHROW(sco_initiator->ProcessMessage(sco_message, srq_message.options));
}

TEST_CASE_METHOD(
    SessionConfirmedFixture,
    "SessionConfirmed responder reads a written message",
    "[sco]")
{
  REQUIRE_NOTHROW(sco_initiator->ProcessMessage(sco_message, srq_message.options));
  REQUIRE_NOTHROW(sco_responder->ProcessMessage(sco_message, srq_message.options));
}

TEST_CASE_METHOD(
    SessionConfirmedFixture,
    "SessionConfirmed initiator rejects invalid message size",
    "[sco]")
{
  // Part two message size must equal value sent in initial SessionRequest
  ++srq_message.options.m3p2_len;
  REQUIRE_THROWS(sco_initiator->ProcessMessage(sco_message, srq_message.options));

  srq_message.options.m3p2_len -= 2;
  REQUIRE_THROWS(sco_initiator->ProcessMessage(sco_message, srq_message.options));
}

TEST_CASE_METHOD(
    SessionConfirmedFixture,
    "SessionConfirmed responder rejects invalid message size",
    "[sco]")
{
  // Part two message size must equal value sent in initial SessionRequest
  ++srq_message.options.m3p2_len;
  REQUIRE_THROWS(sco_responder->ProcessMessage(sco_message, srq_message.options));

  srq_message.options.m3p2_len -= 2;
  REQUIRE_THROWS(sco_responder->ProcessMessage(sco_message, srq_message.options));
}

TEST_CASE_METHOD(
    SessionConfirmedFixture,
    "SessionConfirmed responder rejects invalid MAC",
    "[sco]")
{
  // Write a valid message
  REQUIRE_NOTHROW(sco_initiator->ProcessMessage(sco_message, srq_message.options));

  // Invalidate the ciphertext to fail MAC verification
  ++sco_message.data[0];
  REQUIRE_THROWS(sco_responder->ProcessMessage(sco_message, srq_message.options));

  --sco_message.data[0];  // reset

  // Invalidate part two
  ++sco_message.data[meta::session_confirmed::PartOneSize];
  REQUIRE_THROWS(sco_responder->ProcessMessage(sco_message, srq_message.options));
}

TEST_CASE("SessionConfirmed rejects null handshake state", "[sco]")
{
  REQUIRE_THROWS(SessionConfirmed<Initiator>(nullptr, {}));
  REQUIRE_THROWS(SessionConfirmed<Responder>(nullptr, {}));
}
