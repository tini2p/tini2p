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

using Identity = tini2p::data::Identity;
using crypto_t = Identity::ecies_x25519_hmac_t;
using signing_t = Identity::eddsa_t;

struct RouterIdentityFixture
{

  RouterIdentityFixture() : identity() {}

  Identity identity;
};

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity has a crypto public key",
    "[ident]")
{
  REQUIRE_NOTHROW(boost::get<crypto_t>(identity.crypto()).pubkey());
  REQUIRE(identity.crypto_pubkey_len() == crypto_t::PublicKeyLen);
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity has a signing public key",
    "[ident]")
{
  REQUIRE_NOTHROW(boost::get<signing_t>(identity.signing()).pubkey());
  REQUIRE_NOTHROW(identity.signing_pubkey_len() == signing_t::PublicKeyLen);
}

TEST_CASE_METHOD(RouterIdentityFixture, "RouterIdentity has a cert", "[ident]")
{
  REQUIRE_NOTHROW(identity.cert());

  const auto& cert = identity.cert();
  REQUIRE(cert.cert_type == Identity::cert_t::cert_type_t::KeyCert);
  REQUIRE(cert.length == Identity::cert_t::KeyCertSize);
  REQUIRE(cert.sign_type == Identity::cert_t::sign_type_t::EdDSA);
  REQUIRE(cert.crypto_type == Identity::cert_t::crypto_type_t::EciesX25519);
}

TEST_CASE_METHOD(RouterIdentityFixture, "RouterIdentity has a valid size", "[ident]")
{
  REQUIRE_NOTHROW(identity.size());

  const auto keys_len = crypto_t::PublicKeyLen + signing_t::PublicKeyLen;
  const auto expected_len = keys_len + (Identity::KeysPaddingLen - keys_len)
                            + Identity::cert_t::KeyCertSize;

  REQUIRE(identity.size() == expected_len);
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity serializes and deserializes a valid router identity",
    "[ident]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  REQUIRE_NOTHROW(identity.serialize());
  REQUIRE_NOTHROW(identity.deserialize());

  REQUIRE_NOTHROW(Identity(identity.buffer()));
  Identity ident_copy(identity.buffer());

  REQUIRE_THAT(
      static_cast<vec>(ident_copy.buffer()),
      Equals(static_cast<vec>(identity.buffer())));

  REQUIRE_THAT(
      static_cast<vec>(ident_copy.padding()),
      Equals(static_cast<vec>(identity.padding())));

  const auto& signing = boost::get<signing_t>(identity.signing());
  const auto& sigkey0 = signing.pubkey();
  const auto& sigkey1 = signing.pubkey();

  REQUIRE_THAT(vec(sigkey0.begin(), sigkey0.end()), Equals(vec(sigkey1.begin(), sigkey1.end())));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity signs and verifies a message",
    "[ident]")
{
  std::array<std::uint8_t, 13> msg{};
  Identity::eddsa_t::signature_t signature;

  Identity::signature_v sig;

  REQUIRE_NOTHROW(sig = identity.Sign(msg.data(), msg.size()));
  REQUIRE(identity.Verify(msg.data(), msg.size(), sig));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity encrypts and decrypts a message",
    "[ident]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;
  using crypto_t = Identity::ecies_x25519_hmac_t;

  crypto_t::message_t message, result;
  crypto_t::ciphertext_t ciphertext;

  crypto::RandBytes(message);

  crypto_t::keypair_t r_id_keys(crypto_t::create_keys()), r_ep_keys;

  // derive realistic mock remote id + ephemeral keypairs
  REQUIRE_NOTHROW(crypto_t::curve_t::DeriveEphemeralKeys(
      r_id_keys, r_ep_keys, crypto_t::context_t("testctx")));

  Identity full_ident;
  full_ident.rekey<crypto_t>(r_id_keys.pubkey, r_ep_keys.pubkey);

  REQUIRE_NOTHROW(full_ident.Encrypt<crypto_t>(message, ciphertext));
  REQUIRE_NOTHROW(full_ident.Decrypt<crypto_t>(result, ciphertext));

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

  // invalidate the cert length
  tini2p::BytesWriter<Identity::buffer_t> writer(identity.buffer());
  writer.skip_bytes(Identity::CertOffset + Identity::cert_t::LengthOffset);
  writer.write_bytes<Identity::cert_t::length_t>(0x42);

  REQUIRE_THROWS(identity.deserialize());

  // reset length, overwrite signing + crypto types with random data
  writer.skip_back(Identity::cert_t::LengthLen);
  writer.write_bytes(Identity::cert_t::length_t(0x07));
  writer.write_bytes(tini2p::crypto::RandInRange());

  REQUIRE_NOTHROW(identity.deserialize());
  REQUIRE(identity.cert().locally_unreachable());
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity rejects decryption without remote keys",
    "[ident]")
{
  // unrealistic, mock identity and ephemeral remote public keys
  crypto_t::keypair_t crypto_keys;
  Identity ident;

  crypto_t::message_t message;
  crypto_t::ciphertext_t ciphertext;

  REQUIRE_THROWS(ident.Decrypt<crypto_t>(message, ciphertext));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity rejects signing without a private key",
    "[ident]")
{
  Identity ident;
  ident.rekey<signing_t>(signing_t::pubkey_t{});

  std::array<std::uint8_t, 7> msg{};
  Identity::signature_v sig;

  REQUIRE_THROWS(sig = ident.Sign(msg.data(), msg.size()));
}
