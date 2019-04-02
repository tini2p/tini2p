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

#include <typeinfo>

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
  using hash_t = crypto::Sha256::digest_t;  //< Hash trait alias
  using padding_t = crypto::SecBytes;  //< Padding trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias

  using ecies_x25519_hmac_t = crypto::EciesX25519<crypto::HmacSha256>;  //< ECIES-X25519-Ratchet-HMAC-SHA256 trait alias
  using ecies_x25519_blake_t = crypto::EciesX25519<crypto::Blake2b>;  //< ECIES-X25519-Ratchet-Blake2b trait alias
  using crypto_v = boost::variant<ecies_x25519_hmac_t, ecies_x25519_blake_t>;  //< Crypto implementation trait alias
  using crypto_pubkey_v = boost::variant<crypto::X25519::PublicKey>;  //< Crypto public key variant trait alias

  using eddsa_t = crypto::EdDSASha512;  //< EdDSA-SHA512 trait alias
  using reddsa_t = crypto::RedDSASha512;  //< RedDSA-SHA512 trait alias
  using xeddsa_t = crypto::XEdDSASha512;  //< XEdDSA-SHA512 trait alias
  using signing_v = boost::variant<eddsa_t, reddsa_t, xeddsa_t>;  //< Signing variant trait alias
  using blind_signing_v = boost::variant<reddsa_t, xeddsa_t>;  //< Blind signing variant trait alias

  /// @alias signature_v
  /// @brief Signature variant trait alias
  using signature_v = boost::variant<eddsa_t::signature_t, reddsa_t::signature_t, xeddsa_t::signature_t>;

  /// @alias sign_pubkey_v
  /// @brief Signing pubkey variant trait alias
  using sign_pubkey_v = boost::variant<eddsa_t::pubkey_t, reddsa_t::pubkey_t, xeddsa_t::pubkey_t>;

  /// @alias blind_signature_v
  /// @brief Blind signature variant trait alias
  using blind_signature_v = boost::variant<reddsa_t::signature_t, xeddsa_t::signature_t>;

  /// @alias blind_pubkey_v
  /// @brief Blinded signing pubkey trait alias
  using blind_pubkey_v = boost::variant<reddsa_t::pubkey_t, xeddsa_t::pubkey_t>;

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

  Identity() : buf_(DefaultSize), cert_(), blind_signing_()
  {
    rekey<ecies_x25519_blake_t, eddsa_t>(ecies_x25519_blake_t::create_keys(), eddsa_t::create_keys());

    serialize();
  }

  /// @brief Create an Identity with given crypto + signing implementations
  /// @tparam TCrypto Crypto implementation type
  /// @tparam TSigning Signing implementation type
  /// @param t_crypto Crytpo implementation
  /// @param signing Signing implementation
  template <
      class TCrypto,
      class TSigning,
      typename = std::enable_if_t<
          (std::is_same<TCrypto, ecies_x25519_hmac_t>::value || std::is_same<TCrypto, ecies_x25519_blake_t>::value)
          && (std::is_same<TSigning, eddsa_t>::value || std::is_same<TSigning, reddsa_t>::value
              || std::is_same<TSigning, xeddsa_t>::value)>>
  Identity(TCrypto t_crypto, TSigning signing)
      : buf_(DefaultSize),
        cert_(typeid(TSigning), typeid(TCrypto)),
        crypto_(std::forward<TCrypto>(t_crypto)),
        signing_(std::forward<TSigning>(signing)),
        blind_signing_()
  {
    serialize();
  }

  /// @brief Converting ctor for deserializing from a buffer
  /// @param buffer Buffer containing raw router identity
  explicit Identity(buffer_t buf)
      : buf_(std::forward<buffer_t>(buf)),
        cert_(),
        padding_(),
        crypto_(),
        signing_(),
        blind_signing_()
  {
    const exception::Exception ex{"RouterIdentity", __func__};

    if (buf_.size() < MinSize || buf_.size() > MaxSize)
      ex.throw_ex<std::length_error>("invalid identity size.");

    deserialize();
  }

  /// @brief Converting ctor for deserializing from a buffer
  /// @param buffer Buffer containing raw router identity
  Identity(buffer_t::const_iterator begin, buffer_t::const_iterator end)
      : buf_(begin, end), cert_(), padding_(), crypto_(), signing_(), blind_signing_()
  {
    const exception::Exception ex{"RouterIdentity", __func__};

    const auto size = end - begin;
    if (size < MinSize || size > MaxSize)
      ex.throw_ex<std::length_error>("invalid identity size.");

    deserialize();
  }

  /// @brief Create an Identity from a buffer
  /// @param data Pointer to the buffer
  /// @param len Size of the buffer
  Identity(const std::uint8_t* data, const std::size_t len)
      : cert_(), padding_(), crypto_(), signing_(), blind_signing_()
  {
    tini2p::check_cbuf(data, len, MinSize, MaxSize, {"RouterIdentity", __func__});

    buf_.resize(len);
    std::copy_n(data, len, buf_.data());

    deserialize();
  }

  /// @brief Sign a message
  /// @param msg_ptr Const pointer to the beginning of the message
  /// @param msg_len Length of the message
  /// @return Signature variant containing the message signature
  decltype(auto) Sign(const std::uint8_t* msg_ptr, const std::size_t msg_len) const
  {
    return boost::apply_visitor(
        [msg_ptr, msg_len](const auto& val) {
          typename std::decay_t<decltype(val)>::signature_t sig;
          val.Sign(msg_ptr, msg_len, sig);
          return signature_v(std::move(sig));
        },
        signing_);
  }

  /// @brief Verify a signed a message
  /// @detail Signature variant must match the Identity's signing variant type
  /// @param msg_ptr Const pointer to the beginning of the message
  /// @param msg_len Length of the message
  /// @param sig Signature variant containing the message signature
  /// @return True if the signature is valid
  /// @throw Logic error on signature type mismatch
  bool Verify(const std::uint8_t* msg_ptr, const std::size_t msg_len, const signature_v& sig) const
  {
    const exception::Exception ex{"Identity", __func__};

    return boost::apply_visitor(
        [msg_ptr, msg_len, sig, ex](const auto& s) {
          using sig_t = typename std::decay_t<decltype(s)>::signature_t;

          if (sig.type() != typeid(sig_t))
            ex.throw_ex<std::logic_error>("invalid signature type.");

          return s.Verify(msg_ptr, msg_len, boost::get<sig_t>(sig));
        },
        signing_);
  }

  /// @brief Blind-sign a message
  /// @param msg_ptr Const pointer to the beginning of the message
  /// @param msg_len Length of the message
  /// @return Signature variant containing the message signature
  decltype(auto) BlindSign(const std::uint8_t* msg_ptr, const std::size_t msg_len) const
  {
    return boost::apply_visitor(
        [msg_ptr, msg_len](const auto& val) {
          typename std::decay_t<decltype(val)>::signature_t sig;
          val.Sign(msg_ptr, msg_len, sig);
          return blind_signature_v(std::move(sig));
        },
        blind_signing_);
  }

  /// @brief Verify a blind-signed a message
  /// @detail Signature variant must match the Identity's signing variant type
  /// @param msg_ptr Const pointer to the beginning of the message
  /// @param msg_len Length of the message
  /// @param sig Signature variant containing the message signature
  /// @return True if the signature is valid
  /// @throw Logic error on signature type mismatch
  bool BlindVerify(const std::uint8_t* msg_ptr, const std::size_t msg_len, const blind_signature_v& sig) const
  {
    const exception::Exception ex{"Identity", __func__};

    return boost::apply_visitor(
        [msg_ptr, msg_len, sig, ex](const auto& s) {
          using sig_t = typename std::decay_t<decltype(s)>::signature_t;

          if (sig.type() != typeid(sig_t))
            ex.throw_ex<std::logic_error>("invalid signature type.");

          return s.Verify(msg_ptr, msg_len, boost::get<sig_t>(sig));
        },
        blind_signing_);
  }

  /// @brief Encrypt a message
  /// @tparam TCrypto Crypto implementation type
  /// @param message Message buffer
  /// @param ciphertext Ciphertext buffer
  template <
      class TCrypto,
      typename = std::enable_if_t<
          std::is_same<TCrypto, ecies_x25519_hmac_t>::value
          || std::is_same<TCrypto, ecies_x25519_blake_t>::value>>
  void Encrypt(
      const typename TCrypto::message_t& message,
      typename TCrypto::ciphertext_t& ciphertext)
  {
    const exception::Exception ex{"Identity", __func__};

    if (crypto_.type() != typeid(TCrypto))
      ex.throw_ex<std::invalid_argument>("invalid crypto type.");

    boost::apply_visitor(
        [&ciphertext, message](auto& c) { c.Encrypt(message, ciphertext); },
        crypto_);
  }

  /// @brief Decrypt a message
  /// @tparam TCrypto Crypto implementation type
  /// @param message Message buffer
  /// @param ciphertext Ciphertext buffer
  template <
      class TCrypto,
      typename = std::enable_if_t<
          std::is_same<TCrypto, ecies_x25519_hmac_t>::value
          || std::is_same<TCrypto, ecies_x25519_blake_t>::value>>
  void Decrypt(
      typename TCrypto::message_t& message,
      const typename TCrypto::ciphertext_t& ciphertext)
  {
    const exception::Exception ex{"Identity", __func__};

    if (crypto_.type() != typeid(TCrypto))
      ex.throw_ex<std::invalid_argument>("invalid crypto type.");

    boost::apply_visitor([&message, ciphertext](auto& c) { c.Decrypt(message, ciphertext); }, crypto_);
  }

  /// @brief Serialize the router identity to buffer
  void serialize()
  {
    resize_padding();
    crypto::RandBytes(padding_);

    buf_.resize(size());
    BytesWriter<buffer_t> writer(buf_);

    const auto write_pubkey = [&writer](const auto& t) { writer.write_data(t.pubkey()); };

    boost::apply_visitor(write_pubkey, crypto_);
    writer.write_data(padding_);
    boost::apply_visitor(write_pubkey, signing_);

    cert_.serialize();
    writer.write_data(cert_.buffer);

    update_hash();
  }

  /// @brief Deserialize the router identity from buffer
  void deserialize()
  {
    tini2p::BytesReader<buffer_t> reader(buf_);
    reader.skip_bytes(CertOffset);
    reader.read_data(cert_.buffer);
    cert_.deserialize();

    if (cert_.locally_unreachable())
      {
        std::cerr << "Router: Identity: unreachable because of unsupported crypto.";
        return;
      }
    reader.skip_back(CertOffset + cert_.buffer.size());

    type_to_variant();
    resize_padding();

    boost::apply_visitor([&reader](auto& c) { reader.read_data(c.pubkey()); }, crypto_);

    reader.read_data(padding_);

    boost::apply_visitor(
        [&reader](auto& s) {
          typename std::decay_t<decltype(s)>::pubkey_t key;
          reader.read_data(key);
          s.rekey(std::move(key));
        },
        signing_);

    buf_.resize(cert_.buffer.size() + reader.count());
    update_hash();
  }

  /// @brief Create a fully initialized Identity
  /// @param crypto_keys Local crypto identity keypair
  /// @param r_id_key Remote crypto identity public key
  /// @param r_ep_key Remote crypto ephemeral public key
  /// @param sign_keys Local signing keypair
  template <
      class TCrypto,
      class TSigning,
      typename = std::enable_if_t<
          (std::is_same<TCrypto, ecies_x25519_hmac_t>::value || std::is_same<TCrypto, ecies_x25519_blake_t>::value)
          && (std::is_same<TSigning, eddsa_t>::value
              || std::is_same<TSigning, reddsa_t>::value
              || std::is_same<TSigning, xeddsa_t>::value)>>
  void rekey(
      typename TCrypto::keypair_t l_id_keys,
      typename TCrypto::pubkey_t r_id_key,
      typename TCrypto::pubkey_t r_ep_key,
      typename TSigning::keypair_t sign_keys)
  {
    using crypto_keys_t = typename TCrypto::keypair_t;
    using crypto_pubkey_t = typename TCrypto::pubkey_t;
    using sign_keys_t = typename TSigning::keypair_t;

    if (crypto_.type() != typeid(TCrypto))
      crypto_ = std::move(TCrypto(
          std::forward<crypto_keys_t>(l_id_keys),
          std::forward<crypto_keys_t>(r_id_key),
          std::forward<crypto_pubkey_t>(r_ep_key)));
    else
      boost::get<TCrypto>(crypto_).rekey(
          std::forward<crypto_keys_t>(l_id_keys),
          std::forward<crypto_keys_t>(r_id_key),
          std::forward<crypto_pubkey_t>(r_ep_key));

    if (signing_.type() != typeid(TSigning))
      signing_ = std::move(TSigning(std::forward<sign_keys_t>(sign_keys)));
    else
      boost::get<TSigning>(signing_).rekey(std::forward<sign_keys_t>(sign_keys));

    serialize();
  }

  /// @brief Rekey local crypto and signing keypairs
  /// @param crypto_keys Local crypto identity keypair
  /// @param sign_keys Local signing keypair
  template <
      class TCrypto,
      class TSigning,
      typename = std::enable_if_t<
          (std::is_same<TCrypto, ecies_x25519_hmac_t>::value
           || std::is_same<TCrypto, ecies_x25519_blake_t>::value)
          && (std::is_same<TSigning, eddsa_t>::value
              || std::is_same<TSigning, reddsa_t>::value
              || std::is_same<TSigning, xeddsa_t>::value)>>
  void rekey(
      typename TCrypto::keypair_t crypto_keys,
      typename TSigning::keypair_t sign_keys)
  {
    using crypto_keys_t = typename TCrypto::keypair_t;
    using sign_keys_t = typename TSigning::keypair_t;

    if (crypto_.type() != typeid(TCrypto))
      crypto_ = std::move(TCrypto(std::forward<crypto_keys_t>(crypto_keys)));
    else
      boost::get<TCrypto>(crypto_).rekey(
          std::forward<crypto_keys_t>(crypto_keys));

    if (signing_.type() != typeid(TSigning))
      signing_ = std::move(TSigning(std::forward<sign_keys_t>(sign_keys)));
    else
      boost::get<TSigning>(signing_).rekey(
          std::forward<sign_keys_t>(sign_keys));

    serialize();
  }

  /// @brief Rekey the crypto + signing public keys
  /// @detail Useful for initializing a verifying Identity
  /// @param r_id_key Remote crypto identity public key
  /// @param r_ep_key Remote crypto ephemeral public key
  /// @param sk Remote signing public key
  template <
      class TCrypto,
      class TSigning,
      typename = std::enable_if_t<
          (std::is_same<TCrypto, ecies_x25519_hmac_t>::value
           || std::is_same<TCrypto, ecies_x25519_blake_t>::value)
          && (std::is_same<TSigning, eddsa_t>::value
              || std::is_same<TSigning, reddsa_t>::value
              || std::is_same<TSigning, xeddsa_t>::value)>>
  void rekey(
      typename TCrypto::pubkey_t r_id_key,
      typename TCrypto::pubkey_t r_ep_key,
      typename TSigning::pubkey_t sk)
  {
    using crypto_key_t = typename TCrypto::pubkey_t;
    using sign_key_t = typename TSigning::pubkey_t;

    rekey<TCrypto>(std::forward<crypto_key_t>(r_id_key), std::forward<crypto_key_t>(r_ep_key));

    rekey<TSigning>(std::forward<sign_key_t>(sk));
  }

  template <
      class TCrypto,
      typename = std::enable_if_t<
          std::is_same<TCrypto, ecies_x25519_hmac_t>::value
          || std::is_same<TCrypto, ecies_x25519_blake_t>::value>>
  void rekey(
      typename TCrypto::pubkey_t r_id_key,
      typename TCrypto::pubkey_t r_ep_key)
  {
    using pubkey_t = typename TCrypto::pubkey_t;

    if (crypto_.type() != typeid(TCrypto))
      crypto_ = TCrypto(std::forward<pubkey_t>(r_id_key), std::forward<pubkey_t>(r_ep_key));
    else
      boost::get<TCrypto>(crypto_).rekey(std::forward<pubkey_t>(r_id_key), std::forward<pubkey_t>(r_ep_key));
  }

  template <
      class TSigning,
      typename = std::enable_if_t<
          std::is_same<TSigning, eddsa_t>::value
          || std::is_same<TSigning, reddsa_t>::value
          || std::is_same<TSigning, xeddsa_t>::value>>
  void rekey(typename TSigning::pubkey_t sk)
  {
    using pubkey_t = typename TSigning::pubkey_t;

    if (signing_.type() != typeid(TSigning))
      signing_ = TSigning(std::forward<pubkey_t>(sk));
    else
      boost::get<TSigning>(signing_).rekey(std::forward<pubkey_t>(sk));
  }

  void init_signature(signature_v& sig)
  {
    const exception::Exception ex{"Identity", __func__};

    const auto& sign_type = signing_.type();

    if (sign_type == typeid(eddsa_t))
      sig = eddsa_t::signature_t();
    else if (sign_type == typeid(reddsa_t))
      sig = reddsa_t::signature_t();
    else if (sign_type == typeid(xeddsa_t))
      sig = xeddsa_t::signature_t();
    else
      ex.throw_ex<std::logic_error>("unsupported signing type");
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
  const crypto_v& crypto() const noexcept
  {
    return crypto_;
  }

  /// @brief Get a non-const reference to the crypto class
  crypto_v& crypto() noexcept
  {
    return crypto_;
  }

  /// @brief Get the crypto public key length
  decltype(auto) crypto_pubkey_len() const
  {
    return boost::apply_visitor(
        [](const auto& c) -> std::uint16_t { return std::decay_t<decltype(c)>::PublicKeyLen; }, crypto_);
  }

  /// @brief Get a const reference to the signing class
  const signing_v& signing() const noexcept
  {
    return signing_;
  }

  /// @brief Get a non-const reference to the signing class
  signing_v& signing() noexcept
  {
    return signing_;
  }

  /// @brief Get the signing public key length
  decltype(auto) signing_pubkey_len() const
  {
    return boost::apply_visitor(
        [](const auto& s) -> std::uint16_t { return std::decay_t<decltype(s)>::PublicKeyLen; }, signing_);
  }

  /// @brief Get the signature length
  decltype(auto) sig_len() const
  {
    return boost::apply_visitor(
        [](const auto& s) -> std::uint16_t { return std::decay_t<decltype(s)>::SignatureLen; }, signing_);
  }

  /// @brief Get the blind signing public key length
  decltype(auto) blind_signing_pubkey_len() const
  {
    return boost::apply_visitor(
        [](const auto& s) -> std::uint16_t { return std::decay_t<decltype(s)>::PublicKeyLen; }, blind_signing_);
  }

  /// @brief Get the blind signature length
  decltype(auto) blind_sig_len() const
  {
    return boost::apply_visitor(
        [](const auto& s) -> std::uint16_t { return std::decay_t<decltype(s)>::SignatureLen; }, blind_signing_);
  }

  const padding_t& padding() const noexcept
  {
    return padding_;
  }

  /// @brief Get a const reference to the certificate
  const cert_t& cert() const noexcept
  {
    return cert_;
  }

  /// @brief Get the total size of the router identity
  std::size_t size() const noexcept
  {
    return crypto_pubkey_len() + padding_.size() + signing_pubkey_len() + cert_.length;
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

 private:
  void resize_padding()
  {
    padding_.resize(KeysPaddingLen - (crypto_pubkey_len() + signing_pubkey_len()));
  }

  void type_to_variant()
  {
    if (cert_.crypto_type == cert_t::crypto_type_t::EciesX25519
        && crypto_.type() != typeid(ecies_x25519_hmac_t))
      crypto_ = std::move(ecies_x25519_hmac_t());
    else if (
        cert_.crypto_type == cert_t::crypto_type_t::EciesX25519Blake
        && crypto_.type() != typeid(ecies_x25519_blake_t))
      crypto_ = std::move(ecies_x25519_blake_t());

    if (cert_.sign_type == cert_t::sign_type_t::EdDSA
        && signing_.type() != typeid(eddsa_t))
      signing_ = std::move(eddsa_t());
    else if (
        cert_.sign_type == cert_t::sign_type_t::RedDSA
        && signing_.type() != typeid(reddsa_t))
      signing_ = std::move(reddsa_t());
    else if (
        cert_.sign_type == cert_t::sign_type_t::XEdDSA
        && signing_.type() != typeid(xeddsa_t))
      signing_ = std::move(xeddsa_t());
  }

  padding_t padding_;
  cert_t cert_;
  crypto_v crypto_;
  signing_v signing_;
  blind_signing_v blind_signing_;
  hash_t hash_;
  buffer_t buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_IDENTITY_H_
