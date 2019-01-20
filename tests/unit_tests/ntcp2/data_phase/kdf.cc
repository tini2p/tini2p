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

#include "src/ntcp2/data_phase/kdf.h"

#include "tests/unit_tests/mock/handshake.h"

struct DataPhaseKDFFixture : public MockHandshake
{
  DataPhaseKDFFixture()
  {
    ValidSessionRequest();
    ValidSessionCreated();
    ValidSessionConfirmed();

    // Switch roles according to spec
    initiator = std::make_unique<ntcp2::DataPhaseKDF>(
        responder_state, ntcp2::Initiator());
    responder = std::make_unique<ntcp2::DataPhaseKDF>(
        initiator_state, ntcp2::Responder());
  }

  std::unique_ptr<ntcp2::DataPhaseKDF> initiator;
  std::unique_ptr<ntcp2::DataPhaseKDF> responder;
};

TEST_CASE_METHOD(DataPhaseKDFFixture, "DataPhaseKDF generates keys", "[dpkdf]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;
  using ntcp2::meta::data_phase::Direction;

  boost::endian::big_uint16_t tmp = 17, msg_len = 17;
  constexpr const bool alice_to_bob = true;

  const auto& init_hash = initiator->hash();
  const auto& resp_hash = responder->hash();
  REQUIRE_THAT(
      vec(init_hash.begin(), init_hash.end()),
      Equals(vec(resp_hash.begin(), resp_hash.end())));


  // check initial length is obfuscated then deobfuscated correctly
  REQUIRE_NOTHROW(initiator->ProcessLength(msg_len, Direction::BobToAlice));
  REQUIRE(msg_len != tmp);

  REQUIRE_NOTHROW(responder->ProcessLength(msg_len, Direction::BobToAlice));
  REQUIRE(msg_len == tmp);

  // check response length is obfuscated then deobfuscated correctly
  REQUIRE_NOTHROW(responder->ProcessLength(msg_len, Direction::AliceToBob));
  REQUIRE(msg_len != tmp);

  REQUIRE_NOTHROW(initiator->ProcessLength(msg_len, Direction::AliceToBob));
  REQUIRE(msg_len == tmp);

  // check follow-on length is obfuscated then deobfuscated correctly
  REQUIRE_NOTHROW(initiator->ProcessLength(msg_len, Direction::BobToAlice));
  REQUIRE(msg_len != tmp);

  REQUIRE_NOTHROW(responder->ProcessLength(msg_len, Direction::BobToAlice));
  REQUIRE(msg_len == tmp);
}
