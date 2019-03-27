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

#ifndef SRC_DATA_ROUTER_CERTIFICATE_H_
#define SRC_DATA_ROUTER_CERTIFICATE_H_

#include <iostream>
#include <type_traits>

#include "src/exception/exception.h"

#include "src/bytes.h"

#include "src/data/router/meta.h"

namespace tini2p
{
namespace data
{
/// @brief Container and processor of router certificates
class Certificate
{
 public:
  enum Sizes : std::uint8_t
  {
    CertTypeSize = 1,
    NullCertSize = 3,
    KeyCertSize = 7,
    LengthLen = 2,
  };

  enum Offsets : std::uint8_t
  {
    CertTypeOffset = 0,
    LengthOffset,
    SignTypeOffset = 3,
    CryptoTypeOffset = 5,
  };

  enum Cert_t : std::uint8_t
  {
    NullCert = 0,
    HashCashCert,
    HiddenCert,
    SignedCert,
    MultipleCert,
    KeyCert
  };

  enum Signing_t : std::uint16_t
  {
    DSASha1 = 0,
    ECDSASha256P256,
    ECDSASha384P384,
    ECDSASha512P521,
    RSASha256_2048,
    RSASha384_3072,
    RSASha512_4096,
    EdDSASha512Ed25519,
    EdDSASha512Ed25519ph,
    Gost256,
    Gost512,
    RedDSA,
    XEdDSA,
    SigningUnsupported = 65534,
    SigningReserved = 65535,
    // convenience definition
    EdDSA = EdDSASha512Ed25519,
  };

  enum Crypto_t : std::uint16_t
  {
    ElGamal = 0,
    EciesP256,
    EciesP384,
    EciesP521,
    EciesX25519,
    EciesX25519Blake,
    CryptoUnsupported = 65534,
    CryptoReserved = 65535
  };

  using cert_type_t = Cert_t;
  using length_t = std::uint16_t;
  using sign_type_t = Signing_t;
  using crypto_type_t = Crypto_t;
  using buffer_t = crypto::SecBytes;

  cert_type_t cert_type;
  length_t length;
  sign_type_t sign_type;
  crypto_type_t crypto_type;
  buffer_t buffer;

  Certificate()
      : cert_type(cert_type_t::KeyCert),
        length(KeyCertSize),
        sign_type(sign_type_t::EdDSA),
        crypto_type(crypto_type_t::EciesX25519),
        locally_unreachable_(false),
        buffer(KeyCertSize)
  {
    serialize();
  }

  /// @brief Create a certificate with given sign + crypto types
  Certificate(
      const sign_type_t sign_type_in,
      const crypto_type_t crypto_type_in)
      : cert_type(cert_type_t::KeyCert),
        length(KeyCertSize),
        sign_type(sign_type_in),
        crypto_type(crypto_type_in),
        locally_unreachable_(false),
        buffer(KeyCertSize)
  {
    serialize();
  }

  /// @brief Create a certificate with given sign + crypto type info
  Certificate(
      const std::type_info& sign_type_info,
      const std::type_info& crypto_type_info)
      : cert_type(cert_type_t::KeyCert),
        length(KeyCertSize),
        locally_unreachable_(false),
        buffer(KeyCertSize)
  {
    type_info_to_type(sign_type_info, crypto_type_info);

    serialize();
  }

  /// @brief Convert signing + crypto type_info to sign + crypto types
  void type_info_to_type(
      const std::type_info& sign_type_info,
      const std::type_info& crypto_type_info)
  {
    using eddsa_t = tini2p::crypto::EdDSASha512;
    using reddsa_t = tini2p::crypto::RedDSASha512;
    using xeddsa_t = tini2p::crypto::XEdDSASha512;

    using ecies_x25519_hmac_t = tini2p::crypto::EciesX25519<tini2p::crypto::HmacSha256>;
    using ecies_x25519_blake_t = tini2p::crypto::EciesX25519<tini2p::crypto::Blake2b>;

    sign_type = sign_type_info == typeid(eddsa_t)
                    ? sign_type_t::EdDSA
                    : sign_type_info == typeid(reddsa_t)
                          ? sign_type_t::RedDSA
                          : sign_type_info == typeid(xeddsa_t)
                                ? sign_type_t::XEdDSA
                                : sign_type_t::SigningUnsupported;

    crypto_type = crypto_type_info == typeid(ecies_x25519_hmac_t)
                      ? crypto_type_t::EciesX25519
                      : crypto_type_info == typeid(ecies_x25519_blake_t)
                            ? crypto_type_t::EciesX25519Blake
                            : crypto_type_t::CryptoUnsupported;
  }

  /// @brief Serialize the certificate to buffer
  void serialize()
  {
    const exception::Exception ex{"Router: Certificate", __func__};

    check_params(ex);

    if (buffer.size() != KeyCertSize)
      buffer.resize(KeyCertSize);

    tini2p::BytesWriter<buffer_t> writer(buffer);

    writer.write_bytes(cert_type);
    writer.write_bytes(length);
    writer.write_bytes(sign_type);
    writer.write_bytes(crypto_type);
  }

  /// @brief Deserialize the certificate from buffer
  void deserialize()
  {
    const exception::Exception ex{"Router: Certificate", __func__};

    tini2p::BytesReader<buffer_t> reader(buffer);

    std::uint8_t t_cert;
    std::uint16_t t_sign, t_crypto;

    reader.read_bytes(cert_type);
    reader.read_bytes(length);

    if (length && reader.gcount())
      reader.read_bytes(sign_type);

    if (length && reader.gcount())
      reader.read_bytes(crypto_type);

    check_params(ex);

    buffer.resize(reader.count());
  }

  /// @brief Get unreachable status
  /// @detail Identity/Destination is unreachable if cert has unsupported crypto
  constexpr bool locally_unreachable() const noexcept
  {
    return locally_unreachable_;
  }

 private:
  void check_params(const tini2p::exception::Exception& ex)
  {
    if (cert_type != cert_type_t::NullCert && cert_type != cert_type_t::KeyCert)
      ex.throw_ex<std::runtime_error>("invalid certificate type.");

    if (cert_type == cert_type_t::KeyCert && length != KeyCertSize)
      ex.throw_ex<std::runtime_error>("invalid certificate length.");

    if (!length)
      {
        std::cerr << "Router: Certificate: old unsupported cert type."
                  << std::endl;
        locally_unreachable_ = true;
      }

    switch (crypto_type)
    {
      case crypto_type_t::EciesX25519:
      case crypto_type_t::EciesX25519Blake:
        break;
      default:
        locally_unreachable_ = true;
        break;
    };

    switch (sign_type)
    {
      case sign_type_t::EdDSA:
      case sign_type_t::RedDSA:
      case sign_type_t::XEdDSA:
        break;
      default:
        locally_unreachable_ = true;
        break;
    };
  }

  bool locally_unreachable_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_CERTIFICATE_H_
