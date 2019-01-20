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

#include "src/ntcp2/router/identity.h"

namespace meta = ntcp2::meta::crypto;
namespace crypto = ntcp2::crypto;

struct RouterIdentityFixture
{
  RouterIdentityFixture()
      : identity(crypto::elgamal::create_keys(), crypto::ed25519::create_keys())
  {
  }

  ntcp2::router::Identity identity;
};

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity has a crypto public key",
    "[ident]")
{
  REQUIRE_NOTHROW(identity.crypto()->pub_key());
  REQUIRE_NOTHROW(identity.crypto()->pub_key().size() == crypto::pk::ElGamalLen);
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity has a signing public key",
    "[ident]")
{

  REQUIRE_NOTHROW(identity.signing()->pub_key());
  REQUIRE_NOTHROW(identity.signing()->pub_key().size() == crypto::pk::Ed25519Len);
}

TEST_CASE_METHOD(RouterIdentityFixture, "RouterIdentity has a cert", "[ident]")
{
  namespace cert_meta = ntcp2::meta::router::cert;

  REQUIRE_NOTHROW(identity.cert());

  const auto& cert = identity.cert();
  REQUIRE(cert.cert_type == cert_meta::KeyCert);
  REQUIRE(cert.length == cert_meta::KeyCertSize);
  REQUIRE(cert.sign_type == cert_meta::Ed25519Sign);
  REQUIRE(cert.crypto_type == cert_meta::ElGamalCrypto);
}

TEST_CASE_METHOD(RouterIdentityFixture, "RouterIdentity has a size", "[ident]")
{
  REQUIRE_NOTHROW(identity.size());

  const auto expected_len =
      identity.crypto()->pub_key().size() + identity.padding_len()
      + identity.signing()->pub_key().size() + identity.cert().length;

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
  ntcp2::crypto::ed25519::Signature signature;

  const auto* signing = identity.signing();
  REQUIRE_NOTHROW(signing->Sign(msg.data(), msg.size(), signature));
  REQUIRE(signing->Verify(msg.data(), msg.size(), signature));
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity encrypts and decrypts a message",
    "[ident]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  ntcp2::crypto::elgamal::Plaintext plaintext, result;
  ntcp2::crypto::elgamal::Ciphertext ciphertext;
  constexpr bool zero_pad[2] = {false, true};

  ntcp2::crypto::RandBytes(plaintext.data(), plaintext.size());

  auto* crypto = identity.crypto();
  for (const auto& pad : zero_pad)
    {
      REQUIRE_NOTHROW(crypto->Encrypt(ciphertext, plaintext, pad));
      REQUIRE_NOTHROW(crypto->Decrypt(result, ciphertext, pad));

      REQUIRE_THAT(
          vec(plaintext.begin(), plaintext.end()),
          Equals(vec(result.begin(), result.end())));
    }
}

TEST_CASE_METHOD(
    RouterIdentityFixture,
    "RouterIdentity rejects deserializing an invalid cert",
    "[ident]")
{
  auto cert_data =
      identity.buffer().data() + (identity.size() - identity.cert().length);

  // invalidate the cert
  ntcp2::crypto::RandBytes(cert_data, identity.cert().length);

  REQUIRE_THROWS(identity.deserialize());
}

TEST_CASE("RouterIdentity rejects decryption without a private key", "[ident]")
{
  ntcp2::crypto::pk::ElGamal crypto_pk;
  ntcp2::crypto::pk::Ed25519 sign_pk;
  ntcp2::router::Identity ident(crypto_pk, sign_pk);

  ntcp2::crypto::elgamal::Plaintext plaintext;
  ntcp2::crypto::elgamal::Ciphertext ciphertext;

  REQUIRE_THROWS(ident.crypto()->Decrypt(plaintext, ciphertext, {}));
}

TEST_CASE("RouterIdentity rejects signing without a private key", "[ident]")
{
  ntcp2::crypto::pk::ElGamal crypto_pk;
  ntcp2::crypto::pk::Ed25519 sign_pk;
  ntcp2::router::Identity ident(crypto_pk, sign_pk);

  std::array<std::uint8_t, 7> msg{};
  ntcp2::crypto::ed25519::Signature signature;

  REQUIRE_THROWS(ident.signing()->Sign(msg.data(), msg.size(), signature));
}
