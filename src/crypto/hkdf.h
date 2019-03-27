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

#ifndef SRC_CRYPTO_HKDF_H_
#define SRC_CRYPTO_HKDF_H_

#include <sodium.h>

#include "src/bytes.h"

#include "src/exception/exception.h"

#include "src/crypto/sec_bytes.h"
#include "src/crypto/sha.h"

#include "src/crypto/kdf_context.h"

namespace tini2p
{
namespace crypto
{
/// @class HKDF
/// @brief Implementation of HKDF RFC 5689
template <class Hasher>
class HKDF
{
 public:
  using key_material_t = SecBytes;  //< Key material trait alias
  using context_t = KDFContext<Hasher>;  //< Context trait alias
  using salt_t = typename Hasher::salt_t;  //< Salt trait alias
  using key_t = typename Hasher::key_t;  //< HKDF key trait alias

  /// @brief Generate a new subkey from input key material
  /// @detail KDF context can optionally be empty
  /// @detail Salt defaults to Hasher::SaltLen null bytes
  /// @param key_out Output buffer for the resulting subkey
  /// @param salt Salt for generating the pseudo-random key (optional)
  /// @param ctx HKDF context string for unique KDF applications (optional)
  /// @param key_material Input key material buffer
  /// @throw Length errors for invalid key lengths
  static void Derive(
      key_material_t::pointer key_out,
      key_material_t::size_type key_out_len,
      key_material_t::const_pointer key_in,
      key_material_t::size_type key_in_len,
      const salt_t& salt = salt_t(),
      const context_t& ctx = context_t())
  {
    const exception::Exception ex{"HKDF"};

    if (key_in_len < Hasher::MinKeyMaterialLen
        || key_in_len > Hasher::MaxKeyMaterialLen)
      ex.throw_ex<std::invalid_argument>("invalid input key material length.");

    if (key_out_len < Hasher::MinKeyMaterialLen
        || key_out_len > Hasher::MaxKeyMaterialLen)
      ex.throw_ex<std::invalid_argument>("invalid output key material length.");

    // derive the pseudo-random key
    key_t prk;
    Hasher::Hash(prk, key_in, key_in_len, salt);

    // expand the key material for a number of rounds, and write to the output buffer
    ExpandKeyMaterial(
        key_out,
        key_out_len,
        prk,
        static_cast<const std::uint8_t>(
            std::ceil(key_out_len / Hasher::DigestLen)),
        ctx);
  }

 private:
  static void ExpandKeyMaterial(
      key_material_t::pointer key_out,
      key_material_t::size_type key_out_len,
      const key_t& prk,
      const std::uint8_t rounds,
      const context_t& ctx)
  {
    std::vector<typename Hasher::digest_t> digests(rounds);
    const auto ctx_size = ctx.size();
    key_material_t out_ikm(Hasher::DigestLen + ctx_size + 1);
    tini2p::BytesWriter<key_material_t> oikm_writer(out_ikm);

    key_material_t::const_pointer oikm_ptr(nullptr);
    key_material_t::size_type oikm_size(0);

    // T(0) = empty-string
    // T(N) = H(prk, T(N-1) || info || byte(N))
    // digests(0) = T(1)
    for (std::uint8_t round = 0; round < rounds; ++round)
      {
        using ctx_buf_t = typename context_t::buffer_t;

        if (!round)
          {  // T(0) is empty string, skip it here and when hashing
            oikm_writer.skip_bytes(Hasher::DigestLen);
            oikm_writer.write_data(static_cast<ctx_buf_t>(ctx));
            oikm_ptr = out_ikm.data() + Hasher::DigestLen;
            oikm_size = out_ikm.size() - Hasher::DigestLen;
          }
        else
          {
            oikm_writer.write_data(digests[round - 1]);  // previous round digest, see HKDF spec
            oikm_writer.skip_bytes(ctx_size);  // already wrote info in T(0)
            oikm_ptr = out_ikm.data();
            oikm_size = out_ikm.size();
          }
        oikm_writer.write_bytes<std::uint8_t>(round + 1);  // next round byte, see HKDF spec

        Hasher::Hash(digests[round], oikm_ptr, oikm_size, prk);
        oikm_writer.reset();  // reset writer to beginning of the buffer
      }

    // write output key len bytes from expanded key material to the output buffer
    std::size_t written(0), rem(key_out_len);
    const bool is_short = key_out_len < rounds * Hasher::DigestLen;
    for (std::size_t round = 0; round < rounds; ++round)
      {
        const auto digest_it = digests[round].data();

        if (is_short && round == rounds - 1)
          std::copy_n(digest_it, rem, key_out + written);
        else
          std::copy_n(digest_it, Hasher::DigestLen, key_out + written);

        written += Hasher::DigestLen;
        rem -= Hasher::DigestLen;
      }
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_HKDF_H_
