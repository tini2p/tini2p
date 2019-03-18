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

#ifndef SRC_CRYPTO_EDDSA_REDDSA_SHA512_H_
#define SRC_CRYPTO_EDDSA_REDDSA_SHA512_H_

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
/// @struct RedDSASha512
/// @brief RedDSA-SHA512 implementation
class RedDSASha512
{
 public:
  enum
  {
    PublicKeyLen = 32,
    PrivateKeyLen = 32,
    SignatureLen = 64,
  };

  struct PublicKey : public Key<PublicKeyLen>
  {
    using base_t = Key<PublicKeyLen>;

    PublicKey() : base_t() {}

    PublicKey(base_t::buffer_t buf) : base_t(std::forward<base_t::buffer_t>(buf)) {}

    PublicKey(const SecBytes& buf) : base_t(buf) {}

    PublicKey(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };
  
  struct PrivateKey : public Key<PrivateKeyLen>
  {
    using base_t = Key<PrivateKeyLen>;

    PrivateKey() : base_t() {}

    PrivateKey(base_t::buffer_t buf)
        : base_t(std::forward<base_t::buffer_t>(buf))
    {
    }

    PrivateKey(const SecBytes& buf) : base_t(buf) {}

    PrivateKey(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };

  struct Signature : public crypto::Signature<SignatureLen>
  {
    using base_t = crypto::Signature<SignatureLen>;

    Signature() : base_t() {}

    Signature(base_t::buffer_t buf)
        : base_t(std::forward<base_t::buffer_t>(buf))
    {
    }

    Signature(const SecBytes& buf) : base_t(buf) {}

    Signature(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };

  using curve_t = RedDSASha512;  //< Elliptic curve trait alias (X25519 w/ specialization)
  using message_t = SecBytes;  //< Message trait alias
  using signature_t = RedDSASha512::Signature;  //< Signature trait alias
  using pubkey_t = RedDSASha512::PublicKey;  //< Public key trait alias
  using pvtkey_t = RedDSASha512::PrivateKey;  //< Private key trait alias
  using keypair_t = Keypair<RedDSASha512>;  //< Keypair trait alias

  /// @brief Default ctor, creates new keypair
  RedDSASha512()
  {
    rekey(create_keys());
  }

  RedDSASha512(const RedDSASha512& oth)
      : sk_(std::make_unique<pvtkey_t>(*(oth.sk_))), pk_(oth.pk_)
  {
  }

  /// @brief Create an RedDSASha512 signer with a private key
  /// @param sk RedDSASha512 private key
  explicit RedDSASha512(pvtkey_t sk)
  {
    rekey(std::forward<pvtkey_t>(sk));
  }

  /// @brief create a new RedDSASha512 verifier with a public key
  /// @param sk RedDSASha512 public key
  explicit RedDSASha512(pubkey_t pk) : pk_(std::forward<pubkey_t>(pk)) {}

  /// @brief create a new RedDSASha512 verifier with a keypair
  /// @param sk RedDSASha512 keypair
  explicit RedDSASha512(keypair_t keys)
  {
    rekey(std::forward<keypair_t>(keys));
  }

  void operator=(const RedDSASha512& oth)
  {
    sk_ = std::make_unique<pvtkey_t>(*(oth.sk_));
    pk_ = oth.pk_;
  }

  void Sign(
      message_t::const_pointer msg,
      const message_t::size_type msg_len,
      signature_t& sig) const
  {
    const exception::Exception ex{"RedDSA", __func__};

    check_params(msg, msg_len, ex);

    if (!sk_)
      ex.throw_ex<std::invalid_argument>("null private key.");

    ex.throw_ex<std::runtime_error>("unimplemented.");
  }

  bool Verify(
      message_t::const_pointer msg,
      const message_t::size_type msg_len,
      const signature_t& sig) const
  {
    const exception::Exception ex{"RedDSA", __func__};

    check_params(msg, msg_len, ex);

    ex.throw_ex<std::runtime_error>("unimplemented.");

    return false;
  }

  /// @brief Create an RedDSA key pair
  /// @return RedDSA keypair
  inline static keypair_t create_keys()
  {
    const exception::Exception ex{"RedDSA", __func__};

    ex.throw_ex<std::runtime_error>("unimplemented.");

    return keypair_t{};
  }

  /// @brief Rekey with a private key
  /// @param sk RedDSA private key
  void rekey(pvtkey_t sk)
  {
    const exception::Exception ex{"RedDSA", __func__};

    ex.throw_ex<std::runtime_error>("unimplemented.");
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


  const pubkey_t& pubkey() const noexcept
  {
    return pk_;
  }

  pubkey_t& pubkey() noexcept
  {
    return pk_;
  }

 private:
  void check_params(
      message_t::const_pointer msg,
      const message_t::size_type msg_len,
      const exception::Exception& ex) const
  {
    if (!msg || !msg_len)
      ex.throw_ex<std::invalid_argument>("null message.");
  }

  pubkey_t pk_;
  std::unique_ptr<pvtkey_t> sk_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_EDDSA_REDDSA_SHA512_H_
