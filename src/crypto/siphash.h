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

#ifndef SRC_CRYPTO_HASH_SIPHASH_H_
#define SRC_CRYPTO_HASH_SIPHASH_H_

#include <cryptopp/siphash.h>

#include "src/crypto/rand.h"

namespace tini2p
{
namespace crypto
{
namespace hash
{
enum
{
  SipHashLen = 16,
  SipHashKeyLen = 16,
  SipHashKeyPartLen = 8,
  SipHashIVLen = 8,
};

/// @alias SipHash digest alias for correctness, clarity, and usability
using SipHashDigest = std::array<std::uint8_t, SipHashLen>;

/// @alias SipHash key part alias for correctness, clarity, and usability
using SipHashKeyPart = std::array<std::uint8_t, SipHashKeyPartLen>;

/// @alias SipHash IV alias for correctness, clarity, and usability
using SipHashIV = std::array<std::uint8_t, SipHashIVLen>;

/// @brief Calculate a SipHash digest using key parts from DataPhase KDF
/// @param key_pt1 Part one key from DataPhase KDF
/// @param key_pt2 Part two key from DataPhase KDF
/// @param iv IV from DataPhase KDF or following message round, see spec
inline void SipHash(
    const SipHashKeyPart& key_pt1,
    const SipHashKeyPart& key_pt2,
    const SipHashIV& iv,
    SipHashDigest& digest)
{
  std::array<std::uint8_t, SipHashKeyLen> key;
  std::copy(key_pt1.begin(), key_pt2.end(), key.begin());
  std::copy(key_pt2.begin(), key_pt2.end(), key.begin() + key_pt1.size());

  CryptoPP::SipHash<2, 4, true> hash(key.data(), key.size());
  hash.Update(iv.data(), iv.size());
  hash.TruncatedFinal(digest.data(), digest.size());

  // overwrite the temporary key
  RandBytes(key.data(), key.size());
}
}  // namespace hash
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_HASH_SIPHASH_H_
