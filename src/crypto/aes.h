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

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#include "src/exception/exception.h"
#include "src/ntcp2/meta.h"

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
  };

  struct AESKey : public Key<KeyLen>
  {
    using base_t = Key<KeyLen>;

    AESKey() : base_t() {}

    AESKey(base_t::buffer_t buf) : base_t(std::forward<base_t::buffer_t>(buf))
    {
    }

    AESKey(const SecBytes& buf) : base_t(buf) {}

    AESKey(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };

  struct AESIV : public Key<IVLen>
  {
    using base_t = Key<IVLen>;

    AESIV() : base_t() {}

    AESIV(base_t::buffer_t buf) : base_t(std::forward<base_t::buffer_t>(buf)) {}

    AESIV(const SecBytes& buf) : base_t(buf) {}

    AESIV(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };

  struct AESBlock : public Key<BlockLen>
  {
    using base_t = Key<BlockLen>;

    AESBlock() : base_t() {}

    AESBlock(base_t::buffer_t buf) : base_t(std::forward<base_t::buffer_t>(buf)) {}

    AESBlock(const SecBytes& buf) : base_t(buf) {}

    AESBlock(std::initializer_list<std::uint8_t> list) : base_t(list) {}
  };

  using key_t = AESKey;  //< Key trait alias
  using iv_t = AESIV;  //< IV trait alias
  using key_iv_t = KeyIV<AES>;  // KeyIV trait alias
  using block_t = AESBlock;  //< Block trait alias
  using encrypt_m = CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption;  //< Encryption mode trait alias
  using decrypt_m = CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption;  //< Decryption mode trait alias

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
  AES(const Key& key, const IV& iv)
      : enc_(key.data(), key.size(), iv.data()),
        dec_(key.data(), key.size(), iv.data())
  {
  }

  /// @brief Reset the cipher with a new key and IV
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
    enc_.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    dec_.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
  }

  /// @brief Process a buffer of data
  /// @param out Output buffer for processing
  /// @param out_len Output buffer length 
  /// @param in Input buffer for processing
  /// @param in_len Input buffer buffer length
  template <
      class Mode,
      typename = std::enable_if_t<
          std::is_same<Mode, encrypt_m>::value
          || std::is_same<Mode, decrypt_m>::value>>
  void Process(
      std::uint8_t* out,
      const std::size_t out_len,
      const std::uint8_t* in,
      const std::size_t in_len)
  {
    const tini2p::exception::Exception ex{"AES", __func__};

    if (!out || !in)
      ex.throw_ex<std::invalid_argument>("null buffers.");

    if (!out_len || !in_len)
      ex.throw_ex<std::invalid_argument>("null buffer lenghts.");

    if (out_len != in_len)
      ex.throw_ex<std::length_error>(
          "input and output buffer must have same length.");

    if (in_len % BlockLen != 0)
      ex.throw_ex<std::length_error>(
          "buffer must be a multiple of AES block size.");

    if (std::is_same<Mode, encrypt_m>::value)
      enc_.ProcessData(out, in, in_len);
    else
      dec_.ProcessData(out, in, in_len);
  }

  /// @brief Process a buffer of data (in-place)
  /// @param in_out In-place buffer for processing
  /// @param in_out_len In-place buffer length 
  template <
      class Mode,
      typename = std::enable_if_t<
          std::is_same<Mode, encrypt_m>::value
          || std::is_same<Mode, decrypt_m>::value>>
  void Process(
      std::uint8_t* in_out,
      const std::size_t in_out_len)
  {
    Process<Mode>(in_out, in_out_len, in_out, in_out_len);
  }

  /// @brief Create an AES key and IV
  /// @return AES key and IV
  inline static key_iv_t create_key_iv()
  {
    key_iv_t k;

    RandBytes(k.key);
    RandBytes(k.iv);

    return std::move(k);
  }

 private:
  encrypt_m enc_;
  decrypt_m dec_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_AES_H_
