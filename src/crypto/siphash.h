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

#include <sodium.h>

#include "src/bytes.h"

#include "src/crypto/rand.h"
#include "src/crypto/sec_bytes.h"

namespace tini2p
{
namespace crypto
{
struct SipHash
{
  enum
  {
    DigestLen = 16,
    KeyLen = 16,
    KeyPartLen = 8,
    IVLen = 8,
  };

  using digest_t = FixedSecBytes<DigestLen>;  //< Digest trait alias
  using key_t = FixedSecBytes<KeyLen>;  //< Key trait alias
  using key_part_t = FixedSecBytes<KeyPartLen>;  //< Key part trait alias
  using iv_t = FixedSecBytes<IVLen>;  //< IV trait alias

  /// @brief Calculate a SipHash digest using key parts from DataPhase KDF
  /// @param key_pt1 Part one key from DataPhase KDF
  /// @param key_pt2 Part two key from DataPhase KDF
  /// @param iv IV from DataPhase KDF or following message round, see spec
  static void Hash(
      const key_part_t& key_pt1,
      const key_part_t& key_pt2,
      const iv_t& iv,
      digest_t& digest)
  {
    key_t key;
    BytesWriter<key_t> writer(key);
    writer.write_data(key_pt1);
    writer.write_data(key_pt2);

    crypto_shorthash_siphashx24(
        digest.data(), iv.data(), iv.size(), key.data());
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_HASH_SIPHASH_H_
