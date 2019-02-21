/* Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
 * Copyright (c) 2019, tini2p
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

#ifndef SRC_CRYPTO_ED25519_H_
#define SRC_CRYPTO_ED25519_H_

#include "src/exception/exception.h"

#include "src/crypto/key.h"

namespace tini2p
{
namespace crypto
{
namespace ed25519
{
enum
{
  SignatureLen = 64,
};

/// @brief Ed25519 signature alias for clarity, usability, and correctness
using Signature = std::array<std::uint8_t, SignatureLen>;

struct Base
{
  /// @brief Get the public key length
  std::uint8_t pub_key_len() const noexcept
  {
    return ed25519::PubKeyLen;
  }

  /// @brief Get the private key length
  std::uint8_t priv_key_len() const noexcept
  {
    return ed25519::PvtKeyLen - 32 /* An I2P'ism */;
  }

  /// @brief Get the signature length
  std::uint8_t sig_len() const noexcept
  {
    return ed25519::SignatureLen;
  }
};

/// @class Verifier
/// @brief Implementation class for the EdDSA Ed25519 verifier
/// @detail From Kovri Project
class Verifier : public Base
{
  ed25519::PubKey pk_;

 public:
  /// @brief create a new Ed25519 verifier with a public key
  Verifier(const decltype(pk_)& pk) : pk_(pk) {}

  /// @brief Verify an Ed25519 signed message
  /// @param m Signed message to verify
  /// @param mlen Length of the signed message
  /// @param sig Buffer containing the signature
  /// @return True on successful verification
  /// @detail Signature buffer must be at least ed25519::SignatureLen (64) bytes long
  bool Verify(
      const std::uint8_t* m,
      const std::size_t mlen,
      const std::uint8_t* sig) const
  {
    // Combine message with given signature
    SecBytes sm(ed25519::SignatureLen + mlen);
    std::copy(sig, sig + ed25519::SignatureLen, sm.begin());
    std::copy(m, m + mlen, sm.begin() + ed25519::SignatureLen);

    // Verify
    SecBytes rm(mlen + ed25519::SignatureLen);
    CryptoPP::word64 rmlen;

    int const ret(CryptoPP::NaCl::crypto_sign_open(
        rm, &rmlen, sm.data(), sm.size(), pk_.data()));

    return !ret;
  }

  /// @brief Get a const reference to the public key
  const decltype(pk_)& pub_key() const noexcept
  {
    return pk_;
  }

  /// @brief Rekey the verifier with a new public key
  void rekey(const decltype(pk_)& key)
  {
    pk_ = key;
  }
};

/// @class Signer
/// @brief Implementation class for the EdDSA Ed25519 signer
/// @detail From Kovri Project
class Signer : public Base
{
  ed25519::PvtKey sk_;
  ed25519::PubKey pk_;

 public:
  Signer(const ed25519::Keypair& keys)
      : sk_(keys.sk), pk_(keys.pk)
  {
    // Concat pubkey with secret key (an I2P'ism)
    std::copy(pk_.begin(), pk_.end(), sk_.end() - ed25519::PubKeyLen);
  }

  /// @brief Create an Ed25519 signer with a private key
  /// @param sk Ed25519 private key
  Signer(ed25519::PvtKey sk)
  {
    rekey(sk);
  }

  /// @brief Sign a message with an Ed25519 signature
  /// @param m Message to sign
  /// @param mlen Length of message to sign
  /// @param signature Buffer for the resulting signature
  /// @detail Signature buffer must be at least ed25519::SignatureLen (64) bytes long
  void Sign(
      const std::uint8_t* m,
      const std::size_t mlen,
      std::uint8_t* signature) const
  {
    // Signed message length
    CryptoPP::word64 smlen;

    // Sign message
    std::vector<std::uint8_t> sm(ed25519::SignatureLen + mlen);
    if (CryptoPP::NaCl::crypto_sign(sm.data(), &smlen, m, mlen, sk_.data()))
      exception::Exception{"Ed25519Signer", __func__}
          .throw_ex<std::runtime_error>("could not sign message");

    // We only want the signature
    std::copy(sm.begin(), sm.end() - mlen, signature);
  }

  /// @brief Get a const reference to the public key
  const decltype(pk_)& pub_key() const noexcept
  {
    return pk_;
  }

  /// @brief Rekey with a new private key
  /// @param sk Ed25519 private key
  void rekey(const ed25519::PvtKey& sk)
  {
    sk_ = sk;

    // Create keypair
    if (CryptoPP::NaCl::crypto_sign_sk2pk(pk_.data(), sk_.data()))
      exception::Exception{"Ed25519Signer", __func__}
          .throw_ex<std::runtime_error>("could not create ed25519 keypair");

    // Concat pubkey with secret key (an I2P'ism)
    std::copy(pk_.begin(), pk_.end(), sk_.end() - ed25519::PubKeyLen);
  }
};
}  // namespace ed25519
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_ED25519_H_
