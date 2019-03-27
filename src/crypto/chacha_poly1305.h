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

#ifndef SRC_CRYPTO_CHACHA_POLY1305_H_
#define SRC_CRYPTO_CHACHA_POLY1305_H_

#include <sodium.h>

#include "src/crypto/nonce.h"
#include "src/crypto/poly1305.h"

namespace tini2p
{
namespace crypto
{
struct ChaChaPoly1305
{
  enum
  {
    KeyLen = 32,
    MACLen = Poly1305::DigestLen,
  };

  using key_t = FixedSecBytes<KeyLen>;  //< Key trait alias
  using nonce_t = Nonce;  //< Nonce trait alias
  using mac_t = Poly1305::digest_t;  //< MAC alias trait

  /// @brief AEAD encrypt a message using IETF-AEAD-Chacha20-Poly1305
  /// @tparam Plaintext a plaintext buffer type
  /// @tparam Ciphertext a ciphertext buffer type
  /// @param key Encryption key
  /// @param n Public nonce
  /// @param message Message to encrypt
  /// @param ad Additional data for AEAD
  /// @param ciphertext Buffer for the encryption result: ciphertext || AD || Poly1305MAC
  /// @param ex Exception handler
  template <class Message, class Ciphertext, class AD>
  inline static void AEADEncrypt(
      const key_t& key,
      const nonce_t& n,
      const Message& message,
      const AD& ad,
      Ciphertext& ciphertext)
  {
    const exception::Exception ex{"ChaChaPoly1305", __func__};

    const auto& ad_size = ad.size();
    if (message.size() + ad_size + Poly1305::DigestLen > ciphertext.size())
      ciphertext.resize(message.size() + Poly1305::DigestLen);

    unsigned long long ciphertext_size = ciphertext.size();
    if (const int err = crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(),
            &ciphertext_size,
            message.data(),
            message.size(),
            ad.data(),
            ad_size,
            nullptr,  // secret nonce (unused)
            static_cast<Nonce::buffer_t>(n).data(),
            key.data()))
      {
        ex.throw_ex<std::runtime_error>(
            ("error encrypting message: " + std::to_string(err)).c_str());
      };
  }

  /// @brief AEAD encrypt a message using IETF-AEAD-Chacha20-Poly1305
  /// @tparam Plaintext a plaintext buffer type
  /// @tparam Ciphertext a ciphertext buffer type
  /// @param key Encryption key
  /// @param n Public nonce
  /// @param message Message to encrypt
  /// @param ad Additional data for AEAD
  /// @param ciphertext Buffer for the encryption result: ciphertext || AD || Poly1305MAC
  /// @param ex Exception handler
  template <class Message, class Ciphertext, class AD>
  inline static void AEADDecrypt(
      const key_t& key,
      const nonce_t& n,
      Message& message,
      const AD& ad,
      const Ciphertext& ciphertext)
  {
    const exception::Exception ex{"ChaChaPoly1305", __func__};

    const auto& ad_size = ad.size();

    unsigned long long message_size = ciphertext.size() - Poly1305::DigestLen;
    if (message.size() < message_size)
      message.resize(message_size);

    if (const int err = crypto_aead_chacha20poly1305_ietf_decrypt(
            message.data(),
            &message_size,
            nullptr,
            ciphertext.data(),
            ciphertext.size(),
            ad.data(),
            ad_size,
            static_cast<Nonce::buffer_t>(n).data(),
            key.data()))
      {
        ex.throw_ex<std::runtime_error>(
            ("error decrypting message: " + std::to_string(err)).c_str());
      }
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_CHACHA_POLY1305_H_
