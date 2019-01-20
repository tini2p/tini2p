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

#include "src/crypto/meta.h"

#include "src/crypto/key/aes.h"

namespace ntcp2
{
namespace crypto
{
namespace aes
{
enum
{
  BlockLen = 16,
};

using Block = CryptoPP::FixedSizeSecBlock<std::uint8_t, BlockLen>;

/// @brief Template for AES CBC Cipher
template <class Mode, class Key_t = ntcp2::crypto::aes::Key>
class CBCCipher
{
  Mode cipher_;

 public:
  /// @brief Create a CBC en/decryption cipher
  /// @param key Cipher key (typically responder router hash)
  /// @param iv Cipher IV
  CBCCipher(const Key_t& key, const IV& iv)
      : cipher_(key.data(), key.size(), iv.data())
  {
  }

  /// @brief Reset the cipher with a new key and IV
  /// @param key Cipher key (typically responder router hash)
  /// @param iv Cipher IV
  void rekey(const Key_t& key, const IV& iv)
  {
    cipher_.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
  }

  /// @brief Process one cipher block
  /// @param out Output cipher block
  /// @param in Input cipher block
  void Process(Block& out, const Block& in)
  {
    cipher_.ProcessData(out.data(), in.data(), BlockLen);
  }

  /// @brief Process a buffer of data
  /// @param out Output buffer after cipher processing 
  /// @param out_len Output buffer length 
  /// @param in Input buffer before cipher processing 
  /// @param in_len Input buffer buffer length
  void Process(
      std::uint8_t* out,
      const std::size_t out_len,
      const std::uint8_t* in,
      const std::size_t in_len)
  {
    const ntcp2::exception::Exception ex{"CBCCipher", __func__};

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

    cipher_.ProcessData(out, in, in_len);
  }
};

/// @brief Encryption mode alias for clarity, usability
using CBCEncryption = CBCCipher<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption>;

/// @brief Decryption mode alias for clarity, usability
using CBCDecryption = CBCCipher<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption>;
}  // namespace aes
}  // namespace crypto
}  // namespace ntcp2

#endif  // SRC_CRYPTO_AES_H_
