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

#ifndef SRC_CRYPTO_CRYPTO_H_
#define SRC_CRYPTO_CRYPTO_H_

#include "src/crypto/ecies.h"
#include "src/crypto/keys.h"
#include "src/crypto/signature.h"

namespace tini2p
{
namespace crypto
{
/// @brief Generic wrapper for end-to-end crypto implementations
/// @tparam SignImpl Crypto implementation fulfilling the required traits
/// @detail Required traits:
///
///  - curve_t : Elliptic curve
///  - dh_t : Diffie-Hellman key exchange impl
///  - aead_t : AEAD symmetric cryptographic impl
///  - pubkey_t : Public key - SecureBuffer[PublicKeyLen]
///  - pvtkey_t : Private key - SecureBuffer[PrivateKeyLen]
///  - shrkey_t : Shared key - SecureBuffer[ShrKeyLen]
///  - keypair_t : Keypair { pubkey_t, pvtkey_t }
///  - dh_keys_t : DHKeys { Keypair<id>, Keypair<ephemeral>, shrkey_t, nonce_t }
///  - message_t : Message - SecureBuffer
///  - ciphertext_t : Ciphertext - SecureBuffer
template <
    class CryptoImpl,
    typename = std::enable_if_t<
        std::is_same<CryptoImpl, EciesX25519<HmacSha256>>::value
        || std::is_same<CryptoImpl, EciesX25519<Blake2b>>::value>>
class Crypto
{
 public:
  using impl_t = CryptoImpl;  //< Implementation trait alias
  using curve_t = typename impl_t::curve_t;  //< Elliptic curve trait alias
  using hkdf_t = typename impl_t::hkdf_t;  //< HKDF trait alias
  using dh_t = typename impl_t::dh_t;  //< Diffie-Hellman trait alias
  using aead_t = typename impl_t::aead_t;  //< AEAD symmetric crypto trait alias
  using pubkey_t = typename impl_t::pubkey_t;  //< Public key trait alias
  using pvtkey_t = typename impl_t::pvtkey_t;  //< Private key trait alias
  using keypair_t = typename impl_t::keypair_t;  //< Keypair trait alias
  using dh_keys_t = typename impl_t::dh_keys_t;  //< DH Keypair + AEAD key + AEAD nonce trait alias
  using ciphertext_t = typename impl_t::ciphertext_t;  //< Ciphertext trait alias
  using message_t = typename impl_t::message_t;  //< Message trait alias

  Crypto() : impl_() {}

  /// @brief Create an crytpo impl with local identity public key
  /// @param r_id_key Remote long-term static identity public key
  explicit Crypto(pubkey_t r_id_key) : impl_(std::forward<pubkey_t>(r_id_key)) {}

  /// @brief Create an crytpo impl with local identity private key
  /// @param sk Local long-term static identity private key
  explicit Crypto(pvtkey_t sk) : impl_(std::forward<pvtkey_t>(sk)) {}

  /// @brief Create an crypto impl with local identity keypair
  /// @param id_keys Local long-term static identity keypair
  explicit Crypto(keypair_t id_keys) : impl_(std::forward<keypair_t>(id_keys))
  {
  }

  /// @brief Create a crypto impl with local identity and ephemeral keypairs
  /// @detail Remote static id key and ephemeral key need to be set before DH, encryption, and/or decryption
  /// @param id_keys Local static keypair
  /// @param ep_keys Local ephemeral keypair
  Crypto(keypair_t id_keys, keypair_t ep_keys)
      : impl_(
            std::forward<keypair_t>(id_keys),
            std::forward<keypair_t>(ep_keys))
  {
  }

  /// @brief Create an crypto impl from remote static + ephemeral public keys
  /// @detail Creates fresh local static + ephemeral keys
  /// @param remote_id_pk Remote static public key
  /// @param remote_ep_pk Remote ephemeral public key
  Crypto(pubkey_t remote_id_pk, pubkey_t remote_ep_pk)
      : impl_(
            std::forward<pubkey_t>(remote_id_pk),
            std::forward<pubkey_t>(remote_ep_pk))
  {
  }

  /// @brief Create a fully initialized EciesX25519
  /// @param id_keys Local static keypair
  /// @param ep_keys Local ephemeral keypair
  /// @param remote_id_pk Remote static public key
  /// @param remote_ep_pk Remote ephemeral public key
  Crypto(
      keypair_t id_keys,
      pubkey_t remote_id_key,
      pubkey_t remote_ep_key)
      : impl_(
            std::forward<keypair_t>(id_keys),
            std::forward<pubkey_t>(remote_id_key),
            std::forward<pubkey_t>(remote_ep_key))
  {
  }

  /// @brief Encrypt a message
  /// @param message Input buffer for plaintext
  /// @param ciphertext Output buffer for ciphertext
  void Encrypt(const message_t& message, ciphertext_t& ciphertext)
  {
    impl_.Encrypt(message, ciphertext);
  }

  /// @brief Decrypt a message
  /// @param message Output buffer for the message
  /// @param ciphertext Input buffer for the ciphertext
  void Decrypt(message_t& message, const ciphertext_t& ciphertext)
  {
    impl_.Decrypt(message, ciphertext);
  }

  /// @brief Get the public key length
  decltype(auto) pubkey_len() const noexcept
  {
    return impl_t::PublicKeyLen;
  }

  /// @brief Get the public key length
  decltype(auto) pvtkey_len() const noexcept
  {
    return impl_t::PrivateKeyLen;
  }

  /// @brief Get the public key length
  decltype(auto) shrkey_len() const noexcept
  {
    return impl_t::SharedKeyLen;
  }

  /// @brief Get a const reference to the public key
  decltype(auto) pubkey() const noexcept
  {
    return impl_.pubkey();
  }

  /// @brief Get a non-const reference to the public key
  decltype(auto) pubkey() noexcept
  {
    return impl_.pubkey();
  }

  void rekey(pubkey_t key)
  {
    impl_.rekey(key);
  }

 private:
  impl_t impl_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_CRYPTO_H_
