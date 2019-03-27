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

#ifndef SRC_CRYPTO_AES_H_
#define SRC_CRYPTO_AES_H_

#include <algorithm>
#include <memory>
#include <vector>

#include <aes.h>

#include "src/exception/exception.h"

#include "src/crypto/keys.h"
#include "src/crypto/rand.h"

namespace tini2p
{
namespace crypto
{
class AES
{
 public:
  enum
  {
    KeyLen = 32,
    IVLen = 16,
    BlockLen = 16,
    AESBits = 256,
  };

  using key_t = Key<KeyLen>;  //< Key trait alias
  using iv_t = FixedSecBytes<IVLen>;  //< IV trait alias
  using key_iv_t = KeyIV<AES>;  // KeyIV trait alias
  using block_t = FixedSecBytes<BlockLen>;  //< Block trait alias

  /// @brief Create a CBC en/decryption cipher
  /// @param key Cipher key (typically responder router hash)
  /// @param iv Cipher IV
  template <
      class Key,
      class IV,
      typename = std::enable_if_t<
          (std::is_same<Key, key_t>::value
           || std::is_same<Key, key_t::buffer_t>::value)
          && (std::is_same<IV, iv_t>::value
              || std::is_same<IV, iv_t::buffer_t>::value)>>
  AES(const Key& key, const IV& iv) : key_(key), iv_(iv)
  {
  }

  /// @brief Create a CBC en/decryption cipher
  /// @param key Cipher key (typically responder router hash)
  /// @param iv Cipher IV
  template <
      class Key,
      class IV,
      typename = std::enable_if_t<
          (std::is_same<Key, key_t>::value
           || std::is_same<Key, key_t::buffer_t>::value)
          && (std::is_same<IV, iv_t>::value
              || std::is_same<IV, iv_t::buffer_t>::value)>>
  void rekey(const Key& key, const IV& iv)
  {
    std::copy_n(key.data(), KeyLen, key_.data());
    std::copy_n(iv.data(), IVLen, iv_.data());
  }

  /// @brief Encrypt a buffer of data (in-place)
  /// @param in_out In-place buffer for processing
  /// @param in_out_len In-place buffer length 
  void Encrypt(
      std::uint8_t* in_out,
      const std::size_t in_out_len)
  {
    Process(in_out, in_out_len, Mode::Encrypt, {"AES", __func__});
  }

  /// @brief Decrypt a buffer of data (in-place)
  /// @param out In-place buffer for processing
  /// @param out_len In-place buffer length
  void Decrypt(std::uint8_t* in_out, const std::size_t in_out_len)
  {
    Process(in_out, in_out_len, Mode::Decrypt, {"AES", __func__});
  }

  /// @brief Create an AES key and IV
  /// @return AES key and IV
  static key_iv_t create_key_iv()
  {
    key_iv_t k;

    RandBytes(k.key);
    RandBytes(k.iv);

    return std::move(k);
  }

 private:
  enum struct Mode
  {
    Encrypt,
    Decrypt,
  };

  void Process(
      std::uint8_t* in_out,
      const std::size_t in_out_len,
      const Mode mode,
      const exception::Exception& ex)
  {
    if (!in_out)
      ex.throw_ex<std::invalid_argument>("null buffers.");

    if (!in_out_len)
      ex.throw_ex<std::invalid_argument>("null buffer lenghts.");

    if (in_out_len % BlockLen != 0)
      ex.throw_ex<std::length_error>(
          "buffer must be a multiple of AES block size.");

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key_.data(), iv_.data());

    if (mode == Mode::Encrypt)
      AES_CBC_encrypt_buffer(&ctx, in_out, in_out_len);
    else
      AES_CBC_decrypt_buffer(&ctx, in_out, in_out_len);
  }

  key_t key_;
  iv_t iv_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_AES_H_
