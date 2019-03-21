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

#ifndef SRC_CRYPTO_X25519_H_
#define SRC_CRYPTO_X25519_H_

#include <sodium.h>

#include "src/crypto/blake.h"
#include "src/crypto/keys.h"
#include "src/crypto/hkdf.h"
#include "src/crypto/rand.h"
#include "src/crypto/sha.h"
#include "src/crypto/signature.h"

namespace tini2p
{
namespace crypto
{
class X25519
{
 protected:
   X25519() = default;  // only allow derived instantiation

 public:
  enum
  {
    KeyLen = 32,
    PublicKeyLen = 32,
    PrivateKeyLen = 32,
    SharedKeyLen = 32,
    SignatureLen = 64,
  };

  struct PublicKey : public Key<PublicKeyLen>
  {
    using base_t = Key<PublicKeyLen>;
    using hasher_t = KeyHasher<PublicKeyLen>;  //< Hasher trait alias

    using pointer = PublicKey*;  //< Non-owning pointer trait alias
    using const_pointer = const PublicKey*;  //< Const non-owning pointer trait alias
    using unique_ptr = std::unique_ptr<PublicKey>;  //< Unique pointer trait alias
    using const_unique_ptr = std::unique_ptr<const PublicKey>;  //< Const unique pointer trait alias
    using shared_ptr = std::shared_ptr<PublicKey>;  //< Shared pointer trait alias
    using const_shared_ptr = std::shared_ptr<const PublicKey>;  //< Const shared pointer trait alias

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

  struct SharedKey : public Key<SharedKeyLen>
  {
    using base_t = Key<SharedKeyLen>;

    SharedKey() : base_t() {}

    SharedKey(base_t::buffer_t buf)
        : base_t(std::forward<base_t::buffer_t>(buf))
    {
    }

    SharedKey(const SecBytes& buf) : base_t(buf) {}

    SharedKey(std::initializer_list<std::uint8_t> list) : base_t(list) {}
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

  using curve_t = X25519;  //< Elliptic curve trait alias
  using message_t = SecBytes;  //< Message trait alias
  using ciphertext_t = SecBytes; //< Ciphertext trait alias
  using signature_t = X25519::Signature;  //< Signature trait alias
  using pubkey_t = X25519::PublicKey;  //< Public key trait alias
  using pvtkey_t =  X25519::PrivateKey;  //< Private key trait alias
  using shrkey_t = X25519::SharedKey;  //< Shared key trait alias
  using keypair_t = Keypair<X25519>;  //< Keypair trait alias

  /// @brief Create an X25519 key pair
  /// @return X25519 keypair
  inline static keypair_t create_keys()
  {
    keypair_t k;
    RandBytes(k.pvtkey);
    if(crypto_scalarmult_curve25519_base(k.pubkey.data(), k.pvtkey.data()))
      exception::Exception{"X25519", __func__}.throw_ex<std::runtime_error>(
          "unable to create keys.");

    return std::move(k);
  }

  /// @brief Derive ephemeral keypair for Diffie-Hellman exchange
  /// @tparam Hasher HMAC-based hashing function for HKDF
  /// @param id_keys Identity keypair
  /// @param ep_keys Ephemeral keypair
  /// @param ctx KDF context for domain separation
  /// TODO(tini2p): to salt or not to salt?
  template <
      class Hasher,
      typename = std::enable_if_t<
          std::is_same<Hasher, HmacSha256>::value
          || std::is_same<Hasher, Blake2b>::value>>
  inline static void DeriveEphemeralKeys(
      const keypair_t& id_keys,
      keypair_t& ep_keys,
      const KDFContext<Hasher>& ctx = KDFContext<Hasher>())
  {
    using salt_t = typename Hasher::salt_t;

    const exception::Exception ex{"X25519", __func__};

    const auto id_sk_ptr = id_keys.pvtkey.data();
    const auto id_sk_size = id_keys.pvtkey.size();
    const auto ep_sk_ptr = ep_keys.pvtkey.data();
    const auto ep_sk_size = ep_keys.pvtkey.size();

    HKDF<Hasher>::Derive(
        ep_sk_ptr, ep_sk_size, id_sk_ptr, id_sk_size, salt_t{}, ctx);

    if (crypto_scalarmult_curve25519_base(ep_keys.pubkey.data(), ep_sk_ptr))
      ex.throw_ex<std::runtime_error>("unable to derive ephemeral keys.");
  }

  /// @brief Compute public key from an existing private key
  /// @param keys Keypair containing an existing private key
  inline static void PrivateToPublic(keypair_t& keys)
  {
    if(crypto_scalarmult_curve25519_base(keys.pubkey.data(), keys.pvtkey.data()))
      exception::Exception{"X25519", __func__}.throw_ex<std::runtime_error>(
          "error deriving public key.");
  }

  /// @brief Diffie-Hellman key exchange over Curve25519
  /// @detail Only calculates the shared secret as the scalar multiplication of the private + public keys.
  ///   For safe use as a key, resulting secret needs to be hashed with an HKDF function. 
  /// @param shrkey Shared key result of DH
  /// @param pvtkey Private key
  /// @param pubkey Public key
  inline static void
  DH(Key<KeyLen>& shrkey, const pvtkey_t& pvtkey, const pubkey_t& remote_key)
  {
    const exception::Exception ex{"X25519"};

    if (crypto_scalarmult_curve25519(shrkey.data(), pvtkey.data(), remote_key.data()))
      ex.throw_ex<std::runtime_error>("error computing shared key.");
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_X25519_H_
