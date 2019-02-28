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

#ifndef SRC_CRYPTO_EDDSA_XEDDSA_SHA512_H_
#define SRC_CRYPTO_EDDSA_XEDDSA_SHA512_H_

#include <sodium.h>

#include "src/exception/exception.h"

#include "src/crypto/keys.h"
#include "src/crypto/rand.h"
#include "src/crypto/sec_bytes.h"
#include "src/crypto/signature.h"
#include "src/crypto/x25519.h"

namespace tini2p
{
namespace crypto
{
/// @struct XEdDSASha512
/// @brief XEdDSASha512 implementation
struct XEdDSASha512 : public X25519
{
  /// @brief Create an EdDSASha512 signer with a private key
  /// @param sk EdDSASha512 private key
  explicit XEdDSASha512(pvtkey_t sk)
  {
    rekey(std::forward<pvtkey_t>(sk));
  }

  /// @brief create a new EdDSASha512 verifier with a public key
  /// @param sk EdDSASha512 public key
  explicit XEdDSASha512(pubkey_t pk) : pk_(std::forward<pubkey_t>(pk)) {}

  /// @brief create a new EdDSASha512 verifier with a keypair
  /// @param sk EdDSASha512 keypair
  explicit XEdDSASha512(keypair_t keys)
  {
    rekey(std::forward<keypair_t>(keys));
  }

  inline void Sign(
      message_t::const_pointer msg,
      message_t::size_type msg_len,
      signature_t& sig)
  {
    const exception::Exception ex{"XEdDSA", __func__};

    if (!sk_)
      ex.throw_ex<std::invalid_argument>("null private key.");

    if (!msg || !msg_len)
      ex.throw_ex<std::invalid_argument>("null message.");

    ex.throw_ex<std::runtime_error>("unimplemented.");
  }

  inline bool Verify(
      message_t::const_pointer msg,
      message_t::size_type msg_len,
      const signature_t& sig)
  {
    const exception::Exception ex{"XEdDSA", __func__};

    if (!msg || !msg_len)
      ex.throw_ex<std::invalid_argument>("null message.");

    ex.throw_ex<std::runtime_error>("unimplemented.");

    return false;
  }

  /// @brief Rekey with a private key
  /// @param sk X25519 private key
  void rekey(pvtkey_t sk)
  {
    sk_ = std::make_unique<pvtkey_t>(std::forward<pvtkey_t>(sk));
    crypto_scalarmult_curve25519_base(pk_.data(), sk_->data());
  }

  /// @brief Rekey with a public key
  /// @detail Disables signing functionality, will only verify signatures
  /// @param pk X25519 public key
  void rekey(pubkey_t pk)
  {
    pk_ = std::forward<pubkey_t>(pk);
    sk_.reset(nullptr);
  }

  /// @brief Rekey with a keypair
  /// @param k X25519 keypair
  void rekey(keypair_t k)
  {
    pk_ = std::forward<pubkey_t>(k.pubkey);
    sk_ = std::make_unique<pvtkey_t>(k.pvtkey);
  }

 private:
  pubkey_t pk_;
  std::unique_ptr<pvtkey_t> sk_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_EDDSA_XEDDSA_SHA512_H_
