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

#include "src/data/router/identity.h"

namespace crypto = tini2p::crypto;

using tini2p::data::Identity;

struct RouterIdentityFixture
{
  RouterIdentityFixture()
      : crypto_keys(Identity::crypto_t::impl_t::create_keys()),
        identity(crypto_keys, Identity::signing_t::impl_t::create_keys())
  {
  }

  Identity::crypto_t::keypair_t crypto_keys;
  Identity identity;
};

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity has a crypto public key",
    "[ident]")
{
  REQUIRE_NOTHROW(identity.crypto().pubkey());
  REQUIRE_NOTHROW(
      identity.crypto().pubkey_len() == Identity::crypto_t::impl_t::PublicKeyLen);
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity has a signing public key",
    "[ident]")
{
  REQUIRE_NOTHROW(identity.signing().pubkey());
  REQUIRE_NOTHROW(
      identity.signing().pubkey_len()
      == Identity::signing_t::impl_t::PublicKeyLen);
}

TEST_CASE_METHOD(RouterIdentityFixture, "RouterIdentity has a cert", "[ident]")
{
  REQUIRE_NOTHROW(identity.cert());

  const auto& cert = identity.cert();
  REQUIRE(cert.cert_type == Identity::cert_t::Cert_t::KeyCert);
  REQUIRE(cert.length == Identity::cert_t::KeyCertSize);
  REQUIRE(cert.sign_type == Identity::cert_t::Signing_t::EdDSA);
  REQUIRE(cert.crypto_type == Identity::cert_t::Crypto_t::EciesX25519);
}

TEST_CASE_METHOD(RouterIdentityFixture, "RouterIdentity has a valid size", "[ident]")
{
  REQUIRE_NOTHROW(identity.size());

  const auto expected_len =
      identity.crypto().pubkey_len() + identity.padding_len()
      + identity.signing().pubkey_len() + identity.cert().length;

  REQUIRE(identity.size() == expected_len);
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity serializes and deserializes a valid router identity",
    "[ident]")
{
  REQUIRE_NOTHROW(identity.serialize());
  REQUIRE_NOTHROW(identity.deserialize());
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity signs and verifies a message",
    "[ident]")
{
  std::array<std::uint8_t, 13> msg{};
  Identity::signing_t::signature_t signature;

  const auto& signing = identity.signing();
  REQUIRE_NOTHROW(signing.Sign(msg.data(), msg.size(), signature));
  REQUIRE(signing.Verify(msg.data(), msg.size(), signature));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity encrypts and decrypts a message",
    "[ident]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;
  using crypto_t = Identity::crypto_t;
  using signing_t = Identity::signing_t;

  crypto_t::message_t message, result;
  crypto_t::ciphertext_t ciphertext;

  crypto::RandBytes(message);

  crypto_t::keypair_t l_id_keys(crypto_t::curve_t::create_keys()),
      r_id_keys(crypto_t::curve_t::create_keys()), r_ep_keys;

  // derive realistic mock remote id + ephemeral keypairs
  REQUIRE_NOTHROW(crypto_t::curve_t::DeriveEphemeralKeys(
      r_id_keys, r_ep_keys, crypto_t::impl_t::context_t("testctx")));

  Identity full_ident(
      l_id_keys,
      r_id_keys.pubkey,
      r_ep_keys.pubkey,
      signing_t::create_keys());

  REQUIRE_NOTHROW(full_ident.crypto().Encrypt(message, ciphertext));
  REQUIRE_NOTHROW(full_ident.crypto().Decrypt(result, ciphertext));

  REQUIRE_THAT(
      vec(message.begin(), message.end()),
      Equals(vec(result.begin(), result.end())));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity rejects deserializing an invalid cert",
    "[ident]")
{
  auto cert_data = identity.buffer().data() + Identity::CertOffset;

  // invalidate the cert
  crypto::RandBytes(cert_data, identity.cert().length);

  REQUIRE_THROWS(identity.deserialize());
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity rejects decryption without a private key",
    "[ident]")
{
  // unrealistic, mock identity and ephemeral remote public keys
  Identity ident(crypto_keys.pubkey, crypto_keys.pubkey, Identity::signing_t::pubkey_t{});

  Identity::crypto_t::message_t message;
  Identity::crypto_t::ciphertext_t ciphertext;

  REQUIRE_THROWS(ident.crypto().Decrypt(message, ciphertext));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity rejects signing without a private key",
    "[ident]")
{
  using sign_pubkey_t = Identity::signing_t::pubkey_t;

  // unrealistic, mock identity and ephemeral remote public keys
  Identity ident(crypto_keys.pubkey, crypto_keys.pubkey, sign_pubkey_t{});

  std::array<std::uint8_t, 7> msg{};
  Identity::signing_t::signature_t signature;

  REQUIRE_THROWS(ident.signing().Sign(msg.data(), msg.size(), signature));
}
