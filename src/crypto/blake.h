/* Copyright (c) 2019, tini2p
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * Modification, are permitted provided that the following conditions are met:
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

#ifndef SRC_CRYPTO_BLAKE_H_
#define SRC_CRYPTO_BLAKE_H_

#include <sodium.h>

#include "src/bytes.h"

#include "src/exception/exception.h"

#include "src/crypto/kdf_context.h"
#include "src/crypto/sec_bytes.h"

namespace tini2p
{
namespace crypto
{
/// @struct Blake2b
class Blake2b
{
 public:
  enum
  {
    DigestLen = 32,
    SaltLen = 16,
    KeyLen = 32,
    MinKeyOutLen = 16,
    MaxKeyOutLen = 64,
    MinKeyMaterialLen = KeyLen,
    MaxKeyMaterialLen = 64,
    DefaultContextLen = 8,
    MaxContextLen = 16,  //< CString[16], based on libsodium
  };

  using salt_t = std::array<std::uint8_t, SaltLen>;  // Salt trait alias
  using key_material_t = SecBytes;  //< Key material trait alias
  using digest_t = FixedSecBytes<DigestLen>;  //< Digest trait alias
  using context_t = KDFContext<Blake2b>;  //< Context trait alias
  using key_t = FixedSecBytes<KeyLen>;  //< Key trait alias

  /// @brief Generate a new subkey from a given master key
  /// @tparam N Size of the fixed-length output buffer
  /// @param key_out Output buffer for the resulting subkey
  /// @param nonce Counter-based nonce
  /// @param ctx Blake2b context string for unique KDF applications
  /// @param data Input data to hash
  /// @param key_in Master key buffer
  /// @throw Length errors for invalid key lengths
  template <std::size_t N>
  static void Hash(
      FixedSecBytes<N>& key_out,
      key_material_t::const_pointer data_ptr,
      const key_material_t::size_type data_len,
      const key_t& key_in,
      const salt_t& salt = {},
      const context_t& ctx = context_t())
  {
    Hash(
        key_out.data(),
        key_out.size(),
        data_ptr,
        data_len,
        key_in.data(),
        key_in.size(),
        salt,
        ctx);
  }

  template <std::size_t N>
  static void Hash(
      FixedSecBytes<N>& key_out,
      key_t::const_pointer key_in,
      const key_t::size_type key_in_len,
      const salt_t& salt = {},
      const context_t& ctx = context_t())
  {
    Hash(
        key_out.data(),
        key_out.size(),
        nullptr,
        0,
        key_in,
        key_in_len,
        salt,
        ctx);
  }

  /// @brief Generate a new subkey from a given master key
  /// @param key_out Output buffer for the resulting subkey
  /// @param nonce Counter-based nonce
  /// @param ctx Blake2b context string for unique KDF applications
  /// @param data Input data to hash
  /// @param key_in Master key buffer
  /// @throw Length errors for invalid key lengths
  static void Hash(
      key_material_t& key_out,
      const key_material_t& data,
      const key_t& key_in,
      const salt_t& salt = {},
      const context_t& ctx = context_t())
  {
    Hash(
        key_out.data(),
        key_out.size(),
        data.data(),
        data.size(),
        key_in.data(),
        key_in.size(),
        salt,
        ctx);
  }

 private:
  static void Hash(
      std::uint8_t* ko_it,
      const std::size_t ko_size,
      key_material_t::const_pointer data_ptr,
      const key_material_t::size_type data_len,
      key_t::const_pointer key_in,
      const key_t::size_type key_in_len,
      const salt_t& salt = {},
      const context_t& ctx = context_t())
  {
    const exception::Exception ex{"Blake2b"};

    if (ko_size < MinKeyOutLen || ko_size > MaxKeyOutLen)
      ex.throw_ex<std::invalid_argument>("invalid output key length.");

    crypto_generichash_blake2b_state h;
    crypto_generichash_blake2b_init_salt_personal(
        &h,
        key_in,
        key_in_len,
        ko_size,
        salt.data(),
        static_cast<context_t::buffer_t>(ctx).data());

    if (!data_ptr || !data_len)
      crypto_generichash_blake2b_update(&h, digest_t{}.data(), DigestLen);
    else
      crypto_generichash_blake2b_update(&h, data_ptr, data_len);

    crypto_generichash_blake2b_final(&h, ko_it, ko_size);
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_BLAKE_H_
