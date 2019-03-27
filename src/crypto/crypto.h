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

#include <boost/variant.hpp>

#include "src/crypto/codecs.h"

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
struct Crypto
{
  struct Base64EncodePubkey : public boost::static_visitor<std::string>
  {
    template <
        class TCrypto,
        typename = std::enable_if_t<
            std::is_same<TCrypto, EciesX25519<HmacSha256>>::value
            || std::is_same<TCrypto, EciesX25519<Blake2b>>::value>>
    std::string operator()(const TCrypto& t_crypto) const
    {
      return Base64::Encode(t_crypto.pubkey().data(), TCrypto::PublicKeyLen);
    }
  };
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_CRYPTO_H_
