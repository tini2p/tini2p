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

#ifndef SRC_CRYPTO_ED25519_SHA512_H_
#define SRC_CRYPTO_ED25519_SHA512_H_

#include <sodium.h>

#include "src/exception/exception.h"

#include "src/crypto/keys.h"
#include "src/crypto/rand.h"
#include "src/crypto/sec_bytes.h"
#include "src/crypto/signature.h"

#include "src/crypto/eddsa/ed25519.h"

namespace tini2p
{
namespace crypto
{
class EdDSASha512 : public Ed25519
{
 public:
  using signature_t = Ed25519::signature_t;  //< Signature trait alias

  EdDSASha512()
  {
    create_own_keys({"EdDSASha512"});
  }

  /// @brief Create an EdDSASha512 signer with a private key
  /// @param sk EdDSASha512 private key
  EdDSASha512(pvtkey_t sk) { rekey(std::forward<pvtkey_t>(sk)); }

  /// @brief create a new EdDSASha512 verifier with a public key
  EdDSASha512(pubkey_t pk) : pk_(std::forward<pubkey_t>(pk)) {}

  EdDSASha512(keypair_t keys)
      : pk_(std::forward<pubkey_t>(keys.pubkey)),
        sk_(std::make_unique<pvtkey_t>(std::forward<pvtkey_t>(keys.pvtkey)))
  {
    std::copy_n(pk_.data(), pk_.size(), sk_->data() + PublicKeyLen);  // thanks I2P
  }

  /// @brief Sign a message
  /// @param m Message to sign
  /// @param mlen Length of message to sign
  /// @param signature Buffer for the resulting signature
  void Sign(
      message_t::const_pointer msg,
      const message_t::size_type msg_len,
      signature_t& sig) const
  {
    const exception::Exception ex{"EdDSASha512", __func__};

    if (!sk_)
      ex.throw_ex<std::runtime_error>("null signing key.");

    if (!msg || !msg_len)
      ex.throw_ex<std::invalid_argument>("null message.");

    // Sign message
    if (crypto_sign_detached(sig.data(), nullptr, msg, msg_len, sk_->data()))
      ex.throw_ex<std::runtime_error>("could not sign message.");
  }

  /// @brief Verify an Ed25519 signed message
  /// @param m Signed message to verify
  /// @param mlen Length of the signed message
  /// @param sig Buffer containing the signature
  /// @return True on successful verification
  bool Verify(
      message_t::const_pointer msg,
      const message_t::size_type msg_len,
      const signature_t& sig) const
  {
    if (!msg || !msg_len)
      exception::Exception{"EdDSASha512", __func__}
          .throw_ex<std::invalid_argument>("null message.");

    return !static_cast<bool>(crypto_sign_verify_detached(sig.data(), msg, msg_len, pk_.data()));
  }

  /// @brief Get a const reference to the public key
  const pubkey_t& pubkey() const noexcept
  {
    return pk_;
  }

  /// @brief Rekey the verifier with a new public key
  void rekey(pubkey_t key)
  {
    pk_ = std::forward<pubkey_t>(key);
    sk_.reset(nullptr);
  }

  /// @brief Rekey with a new private key
  /// @param sk Ed25519 private key
  void rekey(pvtkey_t sk)
  {
    create_own_keys({"EdDSASha512", __func__}, std::forward<pvtkey_t>(sk), false);
  }

  /// @brief Rekey with a new private key
  /// @param sk Ed25519 private key
  void rekey(keypair_t k)
  {
    pk_ = std::forward<pubkey_t>(k.pubkey);
    sk_ = std::make_unique<pvtkey_t>(std::forward<pvtkey_t>(k.pvtkey));
  }

 private:
  void create_own_keys(const exception::Exception& ex, pvtkey_t sk = {}, bool empty = true)
  {
    if (empty)
      {
        sk_.reset(new pvtkey_t());
        crypto_sign_keypair(pk_.data(), sk_->data());
      }
    else
      {
        sk_ = std::make_unique<pvtkey_t>(std::forward<pvtkey_t>(sk));

        if (crypto_sign_ed25519_sk_to_pk(pk_.data(), sk_->data()))
          ex.throw_ex<std::runtime_error>("could not create keypair.");
      }

    std::copy_n(pk_.data(), PublicKeyLen, sk_->data() + PublicKeyLen);
  }

  pubkey_t pk_;
  std::unique_ptr<pvtkey_t> sk_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_ED25519_SHA512_H_
