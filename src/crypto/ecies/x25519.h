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

#ifndef SRC_CRYPTO_ECIES_X25519_H_
#define SRC_CRYPTO_ECIES_X25519_H_

#include <map>

#include "src/exception/exception.h"

#include "src/crypto/blake.h"
#include "src/crypto/chacha_poly1305.h"
#include "src/crypto/dh/x3dh.h"
#include "src/crypto/hkdf.h"
#include "src/crypto/keys.h"
#include "src/crypto/sha.h"
#include "src/crypto/signature.h"
#include "src/crypto/x25519.h"

namespace tini2p
{
namespace crypto
{
template <class Hasher>
struct EciesX25519State
{
  enum
  {
    MsgKeyCacheSize = 32,
  };

  using curve_t = X25519;  //< Implementation trait alias
  using aead_t = ChaChaPoly1305;  //< AEAD symmetric crypto trait alias
  using hmac_t = Hasher;  //< HMAC-base hashing function trait alias
  using context_t = KDFContext<hmac_t>;  //< KDF context trait alias
  using msg_keys_t = std::array<curve_t::shrkey_t, MsgKeyCacheSize>;  //< Message keys collection trait alias

  curve_t::keypair_t id_keys, ep_keys;
  curve_t::pubkey_t remote_id_key, remote_ep_key;
  curve_t::shrkey_t root_key, chain_key;
  aead_t::nonce_t n;
  std::uint16_t pn;
  typename hmac_t::salt_t salt;
  const context_t dh_ctx{std::string("eciesxdh")},
      ck_ctx{std::string("eciesxchain")}, kdf_ctx{std::string("eciesxkdf")};
  msg_keys_t msg_keys;  //< message keys, indexed by chain nonce

  // TODO(tini2p) : restrict access to these state variables
  bool requires_remote_key, requires_dh_ratchet, requires_chain_ratchet;

  EciesX25519State()
      : id_keys(curve_t::create_keys()),
        requires_remote_key(true),
        requires_dh_ratchet(true),
        requires_chain_ratchet(true),
        pn(0),
        msg_keys{}
  {
    curve_t::DeriveEphemeralKeys<hmac_t>(id_keys, ep_keys, kdf_ctx);
  }

  EciesX25519State(const EciesX25519State& oth)
      : id_keys(oth.id_keys),
        ep_keys(oth.ep_keys),
        remote_id_key(oth.remote_id_key),
        remote_ep_key(oth.remote_ep_key),
        root_key(oth.root_key),
        chain_key(oth.chain_key),
        n(oth.n),
        pn(oth.pn),
        salt(oth.salt),
        requires_remote_key(oth.requires_remote_key),
        requires_dh_ratchet(oth.requires_dh_ratchet),
        requires_chain_ratchet(oth.requires_chain_ratchet),
        msg_keys(oth.msg_keys)
  {
  }

  /// @brief Create an EciesX25519State with local identity private key
  /// @param id_key Local long-term static identity private key
  explicit EciesX25519State(curve_t::pvtkey_t id_key)
      : requires_remote_key(true),
        requires_dh_ratchet(true),
        requires_chain_ratchet(true),
        pn(0),
        msg_keys{}
  {
    id_keys.pvtkey = std::forward<curve_t::pvtkey_t>(id_key);
    curve_t::PrivateToPublic(id_keys);
    curve_t::DeriveEphemeralKeys<hmac_t>(id_keys, ep_keys, kdf_ctx);
  }

  /// @brief Create an EciesX25519State with local identity keypair
  /// @param id_keys Local long-term static identity keypair
  explicit EciesX25519State(curve_t::keypair_t id_keys)
      : id_keys(std::forward<curve_t::keypair_t>(id_keys)),
        requires_remote_key(true),
        requires_dh_ratchet(true),
        requires_chain_ratchet(true),
        pn(0),
        msg_keys{}
  {
    curve_t::DeriveEphemeralKeys<hmac_t>(id_keys, ep_keys, kdf_ctx);
  }

  /// @brief Create an EciesX25519State from remote static + ephemeral public keys
  /// @note Creates fresh local static + ephemeral keys
  /// @param remote_id_pk Remote static public key
  /// @param remote_ep_pk Remote ephemeral public key
  EciesX25519State(
      curve_t::pubkey_t remote_id_key,
      curve_t::pubkey_t remote_ep_key)
      : id_keys(curve_t::create_keys()),
        remote_id_key(std::forward<curve_t::pubkey_t>(remote_id_key)),
        remote_ep_key(std::forward<curve_t::pubkey_t>(remote_ep_key)),
        requires_remote_key(false),
        requires_dh_ratchet(true),
        requires_chain_ratchet(true),
        pn(0),
        msg_keys{}
  {
    curve_t::DeriveEphemeralKeys<hmac_t>(id_keys, ep_keys, kdf_ctx);
  }

  /// @brief Create a fully initialized EciesX25519State
  /// @param id_keys Local static keypair
  /// @param ep_keys Local ephemeral keypair
  /// @param remote_id_pk Remote static public key
  /// @param remote_ep_pk Remote ephemeral public key
  EciesX25519State(
      curve_t::keypair_t id_keys,
      curve_t::pubkey_t remote_id_key,
      curve_t::pubkey_t remote_ep_key)
      : id_keys(std::forward<curve_t::keypair_t>(id_keys)),
        remote_id_key(std::forward<curve_t::pubkey_t>(remote_id_key)),
        remote_ep_key(std::forward<curve_t::pubkey_t>(remote_ep_key)),
        requires_remote_key(false),
        requires_dh_ratchet(true),
        requires_chain_ratchet(true),
        pn(0),
        msg_keys{}
  {
    curve_t::DeriveEphemeralKeys<hmac_t>(id_keys, ep_keys, kdf_ctx);
  }

  void operator=(const EciesX25519State& oth)
  {
    id_keys = oth.id_keys;
    ep_keys = oth.ep_keys;
    remote_id_key = oth.remote_id_key;
    remote_ep_key = oth.remote_ep_key;
    root_key = oth.root_key;
    chain_key = oth.chain_key;
    n = oth.n;
    pn = oth.pn;
    salt = oth.salt;
    requires_remote_key = oth.requires_remote_key;
    requires_dh_ratchet = oth.requires_dh_ratchet;
    requires_chain_ratchet = oth.requires_chain_ratchet;
    msg_keys = oth.msg_keys;
  }
};

/// @class EciesX25519
/// @brief Implementation of the ECIES-X25519-AEAD-ChaCha20-Poly1305-Ratchet protocol
/// @detail This scheme is based on [X3DH](https://signal.org/docs/specifications/x3dh/) and [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/).
///
///   Long-term static X25519 keys are used for input key material for X3DH.
///
///   A root and chain key are derived from the X3DH results using the Diffie-Hellman ratchet (DHRatchet).
///
///   The DHRatchet uses X3DH + HKDF<Blake2b> to derive new root + chain keys:
///
///     - root_key = X3DH(static_dh_keys, remote_dh_pubkey)
///
///     - sub_key: Uint8Buffer<64>
///       - root_key = sub_key[:31]
///       - chain_key = sub_key[32:]
///     - root_key: Uint8Buffer<32>
///     - nonce: Nonce{ CounterUint8Buffer<12>, CounterUint16 }
///     - dh_context: CString("xrtdhkdf")
///
///   On each message, a new chain key and one-time message key are derived using the chain key ratchet (ChainRatchet).
///
///   For new sessions between the same parties, each generates a new root key using DHRatchet.
///   The first message after rekey will include the new X3DH public key to derive the new session's root + chain keys.
//.
///   The ChainRatchet uses HKDF<Blake2b> to derive new chain + message keys:
///
///     - sub_key: Uint8Buffer<64>
///       - chain_key = sub_key[:31]
///       - message_key = sub_key[32:]
///     - master_key: Uint8Buffer<32>
///     - nonce: Nonce{ CounterUint8Buffer<12>, CounterUint16 }
///     - chain_context: CString("xrtchain")
///
///   The nonce is strictly increasing, and new sessions must be initiated after MaxNonce<65535> messages.
///
///   IMPORTANT: the same nonce *MUST NOT* be used with the same key to encrypt different messages. Doing so is doom for the cryptosystem.
/// @tparam Signing RouterInfo/LeaseSet signature impl type
/// @tparam Hasher HMAC-based hashing algorithm for HKDF
template <class Hasher>
class EciesX25519
{
  using ratchet_t = enum { DH, Chain };

 public:
  using curve_t = X25519;  //< Curve trait alias
  using pubkey_t = curve_t::pubkey_t;  //< Public key trait alias
  using pvtkey_t = curve_t::pvtkey_t;  //< Private key trait alias
  using shrkey_t = curve_t::shrkey_t;  //< Shared key trait alias
  using keypair_t = curve_t::keypair_t;  //< Keypair trait alias

  using hmac_t = Hasher;  //< HMAC-based hash function trait alias
  using hkdf_t = HKDF<hmac_t>;  //< AEAD symmetric crypto impl trait alias
  using dh_t = X3DH<hmac_t>;  //< Diffie-Hellman trait alias
  using context_t = KDFContext<hmac_t>;  //< KDF context trait alias
  using state_t = EciesX25519State<hmac_t>;  //< ECIES state trait alias

  using aead_t = ChaChaPoly1305;  //< AEAD symmetric crypto impl trait alias
  using nonce_t = aead_t::nonce_t;  //< AEAD symmetric nonce trait alias

  using dh_keys_t = DHKeys<curve_t, aead_t>;  //< DHKeys trait alias

  using message_t = SecBytes;  //< Message trait alias
  using ciphertext_t = SecBytes;  //< Ciphertext trait alias

  enum
  {
    ADLen = Sha256::DigestLen,
    MACLen = aead_t::MACLen,
    NonceLen = nonce_t::NonceLen,
    PublicKeyLen = curve_t::PublicKeyLen,
    PrivateKeyLen = curve_t::PrivateKeyLen,
    SharedKeyLen = curve_t::SharedKeyLen,
  };

  /// @brief Default ctor, creates new keypair
  EciesX25519() : state_() {}

  EciesX25519(const EciesX25519& oth) : state_(oth.state_) {}

  //EciesX25519(EciesX25519&& oth) : state_(std::move(oth.state_))  {}

  /// @brief Create an EciesX25519 with local identity private key
  /// @param id_key Local long-term identity private key
  explicit EciesX25519(pvtkey_t id_key) : state_(std::forward<pvtkey_t>(id_key))
  {
  }


  /// @brief Create an EciesX25519 with local identity keypair
  /// @param id_keys Local long-term identity keypair
  explicit EciesX25519(keypair_t id_keys)
      : state_(std::forward<keypair_t>(id_keys))
  {
  }

  /// @brief Create an EciesX25519 from remote static + ephemeral public keys
  /// @note Creates fresh local static + ephemeral keys
  /// @param remote_id_pk Remote static public key
  /// @param remote_ep_pk Remote ephemeral public key
  EciesX25519(pubkey_t remote_id_pk, pubkey_t remote_ep_pk)
      : state_(
            std::forward<pubkey_t>(remote_id_pk),
            std::forward<pubkey_t>(remote_ep_pk))
  {
    Ratchet(ratchet_t::DH);
  }

  /// @brief Create a fully initialized EciesX25519
  /// @param id_keys Local static keypair
  /// @param remote_id_pk Remote static public key
  /// @param remote_ep_pk Remote ephemeral public key
  EciesX25519(keypair_t id_keys, pubkey_t remote_id_key, pubkey_t remote_ep_key)
      : state_(
            std::forward<keypair_t>(id_keys),
            std::forward<pubkey_t>(remote_id_key),
            std::forward<pubkey_t>(remote_ep_key))
  {
    Ratchet(ratchet_t::DH);
  }

  void operator=(const EciesX25519& oth)
  {
    state_ = oth.state_;
  }

  void operator=(EciesX25519&& oth)
  {
    state_ = std::move(oth.state_);
  }

  /// @brief Encrypt a given message
  /// @detail Stores ciphertext + AEAD + MAC in output buffer
  /// @param message Message buffer
  /// @param ciphertext Ciphertext output buffer
  void Encrypt(const message_t& message, ciphertext_t& ciphertext)
  {
    check_remote_key({"EciesX25519", __func__});

    if (state_.requires_chain_ratchet)
      Ratchet(ratchet_t::Chain);

    const auto& ad = GenerateAD();
    const auto& key = state_.msg_keys[static_cast<nonce_t::uint_t>(state_.n)];

    aead_t::AEADEncrypt(key.buffer(), state_.n, message, ad, ciphertext);
  }

  /// @brief Authenticate and decrypt a given ciphertext
  /// @param message Message output buffer
  /// @param ciphertext Ciphertext buffer
  void Decrypt(message_t& message, const ciphertext_t& ciphertext)
  {
    check_remote_key({"EciesX25519", __func__});

    if (state_.requires_chain_ratchet)
      Ratchet(ratchet_t::Chain);

    const auto& ad = GenerateAD();
    const auto& key = state_.msg_keys[static_cast<nonce_t::uint_t>(state_.n)];

    aead_t::AEADDecrypt(key.buffer(), state_.n, message, ad, ciphertext);
  }

  /// @brief Get a const reference to the root key
  const shrkey_t& root_key() const noexcept
  {
    return state_.root_key;
  }

  /// @brief Get a const reference to the chain key
  const shrkey_t& chain_key() const noexcept
  {
    return state_.chain_key;
  }

  /// @brief Get a const reference to the identity public key
  const pubkey_t& pubkey() const noexcept
  {
    return state_.id_keys.pubkey;
  }

  /// @brief Get a non-const reference to the identity public key
  pubkey_t& pubkey() noexcept
  {
    return state_.id_keys.pubkey;
  }

  /// @brief Get local static keys
  const keypair_t& id_keys() const noexcept
  {
    return state_.id_keys;
  }

  /// @brief Get local ephemeral keys
  const keypair_t& ep_keys() const noexcept
  {
    return state_.ep_keys;
  }

  /// @brief Get a const reference to the identity public key
  const pubkey_t& remote_id_key() const noexcept
  {
    return state_.remote_id_key;
  }

  /// @brief Get a non-const reference to the identity public key
  pubkey_t& remote_id_key() noexcept
  {
    return state_.remote_id_key;
  }

  /// @brief Set remote identity public key
  void rekey(pubkey_t remote_id_key)
  {
    state_.remote_id_key = std::forward<pubkey_t>(remote_id_key);
  }

  /// @brief Set remote identity + ephemeral public keys
  void rekey(pubkey_t remote_id_key, pubkey_t remote_ep_key)
  {
    state_.requires_remote_key = false;
    state_.remote_id_key = std::forward<pubkey_t>(remote_id_key);
    state_.remote_ep_key = std::forward<pubkey_t>(remote_ep_key);
  }

  void rekey(keypair_t keys)
  {
    state_.id_keys = std::forward<keypair_t>(keys);
    curve_t::DeriveEphemeralKeys(state_.ep_keys, state_.id_keys, state_.kdf_ctx);
  }

  /// @brief Create EciesX25519 keypair
  static keypair_t create_keys()
  {
    return curve_t::create_keys();
  }

 private:
  void Ratchet(const ratchet_t ratchet)
  {
    const bool is_dh = ratchet == ratchet_t::DH;

    auto& requires_ratchet =
        is_dh ? state_.requires_dh_ratchet : state_.requires_chain_ratchet;

    if (!requires_ratchet)
      {
        requires_ratchet = true;
        return;
      }

    if (is_dh)
    {
      dh_t::DH(
          state_.root_key,
          state_.remote_id_key,
          state_.remote_ep_key,
          state_.id_keys,
          state_.ep_keys,
          state_.dh_ctx);
    }

    auto& master_key = is_dh ? state_.root_key : state_.chain_key;

    SecBytes kdf_out(aead_t::KeyLen * 2);
    tini2p::write_bytes(state_.salt.data(), static_cast<nonce_t::uint_t>(state_.n));

    hkdf_t::Derive(
        kdf_out.data(),
        kdf_out.size(),
        master_key.data(),
        master_key.size(),
        state_.salt,
        state_.ck_ctx);

    // pre-increment nonce to update current message key in caller
    const auto& n = ++state_.n;
    // update next chain or message key
    auto& sub_key = is_dh ? state_.chain_key : state_.msg_keys[n];

    tini2p::BytesReader<decltype(kdf_out)> reader(kdf_out);
    reader.read_data(master_key);  // ratchet the master key
    reader.read_data(sub_key);  // update the sub key

    requires_ratchet = false;
  }

  Sha256::digest_t GenerateAD()
  {
    FixedSecBytes<PublicKeyLen + NonceLen> ad_in;

    // write the message key + nonce into the ad input buffer
    tini2p::BytesWriter<decltype(ad_in)> ad_write(ad_in);
    ad_write.write_data(state_.msg_keys[static_cast<nonce_t::uint_t>(state_.n)]);
    ad_write.write_data(static_cast<nonce_t::buffer_t>(state_.n));

    // compute the AD
    Sha256::digest_t ad;
    Sha256::Hash(ad, ad_in);

    return std::move(ad);
  }

  void check_remote_key(const exception::Exception& ex)
  {
    if (state_.requires_remote_key)
      ex.throw_ex<std::logic_error>("remote DH public key(s) required.");
  }

  state_t state_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_ECIES_X25519_H_
