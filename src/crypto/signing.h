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

#ifndef SRC_CRYPTO_SIGNING_H_
#define SRC_CRYPTO_SIGNING_H_

#include "src/crypto/eddsa.h"
#include "src/crypto/keys.h"
#include "src/crypto/signature.h"

namespace tini2p
{
namespace crypto
{
/// @brief Generic wrapper for signature implementations
/// @tparam SigningImpl Signing implementation fulfilling the required traits
/// @detail Required traits:
///
///  - pubkey_t : Public key - SecureBuffer[PublicKeyLen]
///  - pvtkey_t : Private key - SecureBuffer[PrivateKeyLen]
///  - keypair_t : Keypair - { pubkey_t, pvtkey_t }
///  - message_t : Message - SecureBuffer
///  - signature_t : Signature - SecureBuffer[SignatureLen] 
template <
    class SigningImpl,
    typename = std::enable_if_t<
        std::is_same<SigningImpl, EdDSASha512>::value
        || std::is_same<SigningImpl, RedDSASha512>::value
        || std::is_same<SigningImpl, XEdDSASha512>::value>>
class Signing : public SigningImpl
{
 public:
  using impl_t = SigningImpl;  //< Implementation trait alias
  using pubkey_t = typename impl_t::pubkey_t;  //< Public key trait alias
  using pvtkey_t = typename impl_t::pvtkey_t;  //< Public key trait alias
  using keypair_t = typename impl_t::keypair_t;  //< Keypair trait alias
  using message_t = typename impl_t::message_t;  //< Message trait alias
  using signature_t = typename impl_t::signature_t;  //< Signature trait alias

  Signing() : impl_() {}

  /// @brief Create a signing implementation with given key(s)
  /// @tparam KeyT Signing key type
  /// @param k Signing key(s) instance
  template <
      class KeyT,
      typename = std::enable_if_t<
          std::is_same<KeyT, pubkey_t>::value
          || std::is_same<KeyT, pvtkey_t>::value
          || std::is_same<KeyT, keypair_t>::value>>
  explicit Signing(KeyT k) : impl_(std::forward<KeyT>(k))
  {
  }

  /// @brief Sign a message
  /// @param data Pointer to the message buffer
  /// @param size Size of the message
  /// @param sig Signature buffer for resulting signature
  void Sign(
      typename message_t::const_pointer data,
      typename message_t::size_type size,
      signature_t& sig) const
  {
    impl_.Sign(data, size, sig);
  }

  /// @brief Verify a signed message
  /// @param data Pointer to the message buffer
  /// @param size Size of the message
  /// @param sig Signature buffer
  /// @return True if verification passes
  bool Verify(
      typename message_t::const_pointer data,
      typename message_t::size_type size,
      const signature_t& sig) const
  {
    return impl_.Verify(data, size, sig);
  }

  /// @brief Get the public key length
  decltype(auto) pubkey_len() const noexcept
  {
    return impl_t::PublicKeyLen;
  }

  /// @brief Get the private key length
  decltype(auto) pvtkey_len() const noexcept
  {
    return impl_t::PrivateKeyLen;
  }

  /// @brief Get the signature length
  decltype(auto) sig_len() const noexcept
  {
    return impl_t::SignatureLen;
  }

 private:
  impl_t impl_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_SIGNING_H_
