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

#ifndef SRC_CRYPTO_Ed25519_H_
#define SRC_CRYPTO_Ed25519_H_

#include <sodium.h>

#include "src/exception/exception.h"

#include "src/crypto/keys.h"
#include "src/crypto/rand.h"
#include "src/crypto/sec_bytes.h"
#include "src/crypto/signature.h"

namespace tini2p
{
namespace crypto
{
/// @class Ed25519
/// @brief Base class for Ed25519 based crypto
class Ed25519
{
 protected:
  Ed25519() = default;  // disable direct instantiation

 public:
  enum
  {
    PublicKeyLen = 32,
    PrivateKeyLen = 64,
    SignatureLen = 64,
  };

  struct PublicKey : public Key<PublicKeyLen>
  {
    using base_t = Key<PublicKeyLen>;

    PublicKey() : base_t() {}

    PublicKey(base_t::buffer_t buf)
        : base_t(std::forward<base_t::buffer_t>(buf))
    {
    }

    PublicKey(const SecBytes& buf) : base_t(buf) {}

    PublicKey(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };

  struct PrivateKey : public Key<PrivateKeyLen>
  {
    using base_t = Key<PrivateKeyLen>;

    PrivateKey() : base_t() {}

    PrivateKey(base_t::buffer_t buf) : base_t(std::forward<base_t::buffer_t>(buf)) {}

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

  using curve_t = Ed25519;  //< Curve trait alias
  using message_t = SecBytes;  //< Message trait alias
  using signature_t = Ed25519::Signature;  //< Signature trait alias
  using pubkey_t = Ed25519::PublicKey;  //< Public key trait alias
  using pvtkey_t = Ed25519::PrivateKey;  //< Private key trait alias
  using keypair_t = Keypair<Ed25519>;  //< Keypair trait alias

  /// @brief Create an EdDSA-Ed25519-Sha512 (I2P-variant) key pair
  /// @detail Concatenates public key to the trailing 32 bytes of the private key for I2P signatures.
  ///   See I2P Java impl for details.
  /// @note What kind of interactions does this cause between the private and public keys?
  ///       Does it affect point encoding?
  ///       Does it affect signatures?
  /// @return Ed25519 keypair
  inline static keypair_t create_keys()
  {
    const exception::Exception ex{"Ed25519", __func__};

    keypair_t k;
    if(crypto_sign_keypair(k.pubkey.data(), k.pvtkey.data()))
      ex.throw_ex<std::runtime_error>("could not create keypair.");

    std::copy_n(k.pubkey.data(), PublicKeyLen, k.pvtkey.data() + PublicKeyLen);
    return std::move(k);
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_EDDSA_Ed25519_H_
