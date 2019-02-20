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

#ifndef SRC_CRYPTO_KEY_X25519_H_
#define SRC_CRYPTO_KEY_X25519_H_

#include <cryptopp/xed25519.h>
#include <cryptopp/secblock.h>

#include "src/exception/exception.h"

namespace tini2p
{
namespace crypto
{
namespace x25519
{
enum
{
  PubKeyLen = 32,
  PvtKeyLen = 32,
};

using PubKey = CryptoPP::FixedSizeSecBlock<std::uint8_t, PubKeyLen>;
using PvtKey = CryptoPP::FixedSizeSecBlock<std::uint8_t, PvtKeyLen>;

struct Keypair
{
  PubKey pk;
  PvtKey sk;
};

/// @brief Create an X25519 key pair
/// @return X25519 keypair
inline Keypair create_keys()
{
  PubKey pk;
  PvtKey sk;
  CryptoPP::AutoSeededRandomPool rng;

  CryptoPP::x25519 x25519(rng);
  x25519.GeneratePrivateKey(rng, sk.data());
  x25519.GeneratePublicKey(rng, sk.data(), pk.data());

  return {pk, sk};
}
}  // namespace x25519
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_KEY_X25519_H_
