/* copyright (c) 2019, tini2p
 * all rights reserved.
 *
 * redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * this software is provided by the copyright holders and contributors "as is"
 * and any express or implied warranties, including, but not limited to, the
 * implied warranties of merchantability and fitness for a particular purpose are
 * disclaimed. in no event shall the copyright holder or contributors be liable
 * for any direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute goods or
 * services; loss of use, data, or profits; or business interruption) however
 * caused and on any theory of liability, whether in contract, strict liability,
 * or tort (including negligence or otherwise) arising in any way out of the use
 * of this software, even if advised of the possibility of such damage.
*/

#ifndef SRC_CRYPTO_SHA_H_
#define SRC_CRYPTO_SHA_H_

#include <sodium.h>

#include "src/exception/exception.h"

#include "src/crypto/sec_bytes.h"

namespace tini2p
{
namespace crypto
{
struct Sha256
{
  enum : std::uint8_t
  {
    DigestLen = 32,
  };

  using digest_t = FixedSecBytes<DigestLen>;  //< digest trait alias

  /// @brief Calculate a SHA256 digest of a given input buffer
  /// @param digest Non-const reference for the SHA256 digest result
  /// @param input Const reference to the input buffer
  template <class Input>
  inline static void Hash(digest_t& digest, const Input& input)
  {
    crypto_hash_sha256(
        digest.data(),
        reinterpret_cast<const std::uint8_t*>(input.data()),
        input.size());
  }
};

struct HmacSha256
{
  enum
  {
    DigestLen = Sha256::DigestLen,
    SaltLen = Sha256::DigestLen,
    KeyLen = Sha256::DigestLen,
    MinKeyMaterialLen = Sha256::DigestLen,
    MaxKeyMaterialLen = Sha256::DigestLen * 16,  // 512 bytes, need more?
    DefaultContextLen = 8,
    MaxContextLen = 16,  //< CString[16], based on libsodium
  };

  using salt_t = FixedSecBytes<SaltLen>;
  using digest_t = FixedSecBytes<DigestLen>;
  using key_material_t = SecBytes;
  using key_t = FixedSecBytes<KeyLen>;

  /// @brief Calculate the HMAC digest of input key material
  /// @param out Output buffer
  /// @param input Input key material
  /// @param key HMAC pseudo-random key
  static void Hash(
      digest_t& out,
      key_material_t::const_pointer in_ptr,
      const key_material_t::size_type in_size,
      const key_t& key)
  {
    crypto_auth_hmacsha256(out.data(), in_ptr, in_size, key.data());
  }

  /// @brief Calculate the HMAC digest of input key material
  /// @param out Output buffer
  /// @param in Input key material
  /// @param key HMAC pseudo-random key
  template <class KeyMaterial>
  inline static void Hash(
      digest_t& out,
      const KeyMaterial& in,
      const key_t& key = {})
  {
    crypto_auth_hmacsha256(out.data(), in.data(), in.size(), key.data());
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_SHA_H_
