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

#include "src/crypto/crypto.h"
#include "src/crypto/ecies/x25519.h"

using tini2p::crypto::Crypto;
using tini2p::crypto::HmacSha256;
using tini2p::crypto::X25519;
using tini2p::crypto::EciesX25519;

using Ecies = Crypto<EciesX25519<HmacSha256>>;

struct EciesX25519Fixture
{
  EciesX25519Fixture() : ecies() {}

  Ecies ecies;
};

TEST_CASE_METHOD(
    EciesX25519Fixture,
    "EciesX25519 has valid key lengths",
    "[ecies_x25519]")
{
  REQUIRE(ecies.pubkey_len() == X25519::PublicKeyLen);
  REQUIRE(ecies.pvtkey_len() == X25519::PrivateKeyLen);
  REQUIRE(ecies.shrkey_len() == X25519::SharedKeyLen);
}

TEST_CASE_METHOD(
    EciesX25519Fixture,
    "EciesX25519 encrypts when remote public keys are set",
    "[ecies_x25519]")
{
  Ecies::message_t msg(17);
  Ecies::ciphertext_t cph;

  Ecies::keypair_t r_id_keys(Ecies::curve_t::create_keys()), r_ep_keys; // remote public keys

  REQUIRE_NOTHROW(Ecies::curve_t::DeriveEphemeralKeys<Ecies::impl_t::hmac_t>(
      r_id_keys, r_ep_keys));

  Ecies e_with_pub(r_id_keys.pubkey, r_ep_keys.pubkey);

  REQUIRE_NOTHROW(e_with_pub.Encrypt(msg, cph));
  REQUIRE_NOTHROW(e_with_pub.Decrypt(msg, cph));
}
