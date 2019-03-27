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

struct SessionCreatedFixture : public MockHandshake
{
  SessionCreatedFixture()
  {
    ValidSessionRequest();
    InitializeSessionCreated();
  }
};

TEST_CASE_METHOD(
    SessionCreatedFixture,
    "SessionCreated initiator writes message",
    "[scr]")
{
  REQUIRE_NOTHROW(scr_initiator->ProcessMessage(scr_message));
}

TEST_CASE_METHOD(
    SessionCreatedFixture,
    "SessionCreated responder reads a written message",
    "[scr]")
{
  REQUIRE_NOTHROW(scr_initiator->ProcessMessage(scr_message));
  REQUIRE_NOTHROW(scr_responder->ProcessMessage(scr_message));
}

TEST_CASE_METHOD(
    SessionCreatedFixture,
    "SessionCreated rejects null handshake state",
    "[scr]")
{
  using hash_t = tini2p::data::Identity::hash_t;

  REQUIRE_THROWS(sess_init_t::created_impl_t(
      nullptr, request_msg_t{}, hash_t{}, obfse_t::iv_t{}));

  REQUIRE_THROWS(sess_resp_t::created_impl_t(
      nullptr, request_msg_t{}, hash_t{}, obfse_t::iv_t{}));
}
