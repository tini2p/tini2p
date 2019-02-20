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

#ifndef SRC_CRYPTO_KEY_AES_H_
#define SRC_CRYPTO_KEY_AES_H_

#include <cryptopp/secblock.h>

#include "src/crypto/rand.h"

namespace tini2p
{
namespace crypto
{
namespace aes
{
enum
{
  KeyLen = 32,
  IVLen = 16,
};

using Key = CryptoPP::FixedSizeSecBlock<std::uint8_t, KeyLen>;
using IV = CryptoPP::FixedSizeSecBlock<std::uint8_t, IVLen>;

struct KeyIV
{
  Key key;
  IV iv;
};

/// @brief Create an AES key and IV 
/// @return AES key and IV
inline KeyIV create_key_iv()
{
  Key key;
  IV iv;

  RandBytes(key.data(), key.size());
  RandBytes(iv.data(), iv.size());

  return {key, iv};
}
}  // namespace aes
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_KEY_AES_H_
