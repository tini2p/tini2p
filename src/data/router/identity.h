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

#ifndef SRC_DATA_ROUTER_IDENTITY_H_
#define SRC_DATA_ROUTER_IDENTITY_H_

#include "src/crypto/aes.h"
#include "src/crypto/crypto.h"
#include "src/crypto/keys.h"
#include "src/crypto/signing.h"

#include "src/data/router/meta.h"
#include "src/data/router/certificate.h"

namespace tini2p
{
namespace data
{
/// @brief Class for I2P RouterIdentity
class Identity
{
 public:
  using cert_t = Certificate;  //< Certificate trait alias
  using crypto_t = crypto::Crypto<crypto::EciesX25519<crypto::HmacSha256>>;  //< Crypto implementation trait alias
  using signing_t = crypto::Signing<crypto::EdDSASha512>;  //< Signing implementation trait alias
  using hash_t = crypto::Sha256::digest_t;  //< Hash trait alias
  using padding_t = crypto::SecBytes;  //< Padding trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias

  enum Sizes : std::uint16_t
  {
    KeysPaddingLen = 384,  //< Size of keys + padding, see spec
    MinSize = KeysPaddingLen + cert_t::NullCertSize,
    DefaultSize = KeysPaddingLen + cert_t::KeyCertSize,  // Ed25519 key cert
    MaxSize = DefaultSize,
  };

  enum Offsets : std::uint16_t
  {
    CertOffset = KeysPaddingLen,
    CertSizeOffset = CertOffset + cert_t::CertTypeSize,
  };

  Identity() : buf_(DefaultSize), crypto_(), signing_()
  {
    serialize();
  }

  /// @brief Converting ctor for deserializing from a buffer
  /// @param buffer Buffer containing raw router identity
  explicit Identity(buffer_t buf) : buf_(std::forward<buffer_t>(buf))
  {
    if (buf_.size() < MinSize)
      exception::Exception{"RouterIdentity", __func__}
          .throw_ex<std::length_error>("invalid identity size.");

    deserialize();
  }

  /// @brief Converting ctor for deserializing from a buffer
  /// @param buffer Buffer containing raw router identity
  explicit Identity(
      buffer_t::const_iterator begin,
      buffer_t::const_iterator end)
      : buf_(begin, end)
  {
    if (end - begin < MinSize)
      exception::Exception{"RouterIdentity", __func__}
          .throw_ex<std::length_error>("invalid identity size.");

    deserialize();
  }

  /// @brief Converting ctor for deserializing from a buffer
  /// @param buffer Buffer containing raw router identity
  explicit Identity(
      buffer_t::const_pointer data,
      const buffer_t::size_type size)
      : buf_(data, size), crypto_(), signing_()
  {
    if (size < MinSize)
      exception::Exception{"RouterIdentity", __func__}
          .throw_ex<std::length_error>("invalid identity size.");

    deserialize();
  }

  /// @brief Converting-ctor (copy) for serializing from a crypto + signing key
  /// @detail Useful for initializing a verifying Identity
  /// @param r_id_key Remote crypto identity public key
  /// @param r_ep_key Remote crypto ephemeral public key
  /// @param sk Remote signing public key
  Identity(
      crypto_t::pubkey_t r_id_key,
      crypto_t::pubkey_t r_ep_key,
      signing_t::pubkey_t sk)
      : buf_(DefaultSize),
        crypto_(
            std::forward<crypto_t::pubkey_t>(r_id_key),
            std::forward<crypto_t::pubkey_t>(r_ep_key)),
        signing_(std::forward<signing_t::pubkey_t>(sk))
  {
    serialize();
  }

  /// @brief Converting-ctor (copy) for serializing from a crypto + signing keypairs
  /// @param crypto_keys Local crypto identity keypair
  /// @param sign_keys Local signing keypair
  Identity(crypto_t::keypair_t crypto_keys, signing_t::keypair_t sign_keys)
      : buf_(DefaultSize),
        crypto_(std::forward<crypto_t::keypair_t>(crypto_keys)),
        signing_(std::forward<signing_t::keypair_t>(sign_keys))
  {
    serialize();
  }

  /// @brief Create a fully initialized Identity
  /// @param crypto_keys Local crypto identity keypair
  /// @param r_id_key Remote crypto identity public key
  /// @param r_ep_key Remote crypto ephemeral public key
  /// @param sign_keys Local signing keypair
  Identity(
      crypto_t::keypair_t l_id_keys,
      crypto_t::pubkey_t r_id_key,
      crypto_t::pubkey_t r_ep_key,
      signing_t::keypair_t sign_keys)
      : buf_(DefaultSize),
        crypto_(
            std::forward<crypto_t::keypair_t>(l_id_keys),
            std::forward<crypto_t::pubkey_t>(r_id_key),
            std::forward<crypto_t::pubkey_t>(r_ep_key)),
        signing_(std::forward<signing_t::keypair_t>(sign_keys))
  {
    serialize();
  }

  /// @brief Get a const reference to the buffer
  const buffer_t& buffer() const noexcept
  {
    return buf_;
  }

  /// @brief Get a non-const reference to the buffer
  buffer_t& buffer() noexcept
  {
    return buf_;
  }

  /// @brief Get a const reference to the crypto class
  const crypto_t& crypto() const noexcept
  {
    return crypto_;
  }

  /// @brief Get a non-const reference to the crypto class
  crypto_t& crypto() noexcept
  {
    return crypto_;
  }

  /// @brief Get a const reference to the signing class
  const signing_t& signing() const noexcept
  {
    return signing_;
  }

  /// @brief Get a non-const reference to the signing class
  signing_t& signing() noexcept
  {
    return signing_;
  }

  /// @brief Get a const reference to the certificate
  const cert_t& cert() const noexcept
  {
    return cert_;
  }

  /// @brief Get the total size of the router identity
  constexpr std::size_t size() const noexcept
  {
    return crypto_.pubkey_len() + padding_.size() + signing_.pubkey_len()
           + cert_.length;
  }

  /// @brief Get the padding size
  std::uint16_t padding_len() const noexcept
  {
    return padding_.size();
  }

  /// @brief Get a const reference to the Identity hash
  const hash_t& hash() const noexcept
  {
    return hash_;
  }

  /// @brief Calculate a new Identity hash from the current buffer
  void update_hash()
  {
    crypto::Sha256::Hash(hash_, buf_);
  }

  /// @brief Serialize the router identity to buffer
  void serialize()
  {
    update_padding();

    buf_.resize(size());
    tini2p::BytesWriter<buffer_t> writer(buf_);

    writer.write_data(crypto_.pubkey());
    writer.write_data(padding_);
    writer.write_data(signing_.pubkey());

    cert_.serialize();
    writer.write_data(cert_.buffer);

    update_hash();
  }

  /// @brief Deserialize the router identity from buffer
  void deserialize()
  {
    crypto_t::pubkey_t crypto_key;
    signing_t::pubkey_t sign_key;

    const auto key_size = crypto_key.size() + sign_key.size();
    padding_.resize(KeysPaddingLen - key_size);
    buf_.resize(key_size + padding_.size() + cert_t::KeyCertSize);

    tini2p::BytesReader<buffer_t> reader(buf_);
    reader.read_data(crypto_key);
    reader.read_data(padding_);
    reader.read_data(sign_key);
    reader.read_data(cert_.buffer);
    cert_.deserialize();

    if (cert_.local_unreachable())
    {
      std::cerr << "Router: Identity: unreachable because of unsupported crypto.";
      return;
    }

    crypto_.rekey(std::move(crypto_key));
    signing_.rekey(std::move(sign_key));

    buf_.resize(reader.count());
    update_hash();
  }

 private:
  void update_padding()
  {
    padding_.resize(
        KeysPaddingLen
        - (crypto_t::impl_t::PublicKeyLen + signing_t::impl_t::PublicKeyLen));
    crypto::RandBytes(padding_);
  }

  padding_t padding_;
  cert_t cert_;
  crypto_t crypto_;
  signing_t signing_;
  hash_t hash_;
  buffer_t buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_IDENTITY_H_
