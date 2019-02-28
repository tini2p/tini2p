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

#ifndef SRC_CRYPTO_DH_X3DH_H_
#define SRC_CRYPTO_DH_X3DH_H_

#include "src/bytes.h"

#include "src/crypto/kdf_context.h"

#include "src/crypto/blake.h"
#include "src/crypto/eddsa.h"
#include "src/crypto/hkdf.h"
#include "src/crypto/sha.h"

#include "src/crypto/x25519.h"

namespace tini2p
{
namespace crypto
{
/// @struct X3DH
/// @brief X3DH implementation
/// @tparam Hasher HKDF HMAC-based hashing impl, e.g. HmacSha256, Blake2b, etc.
template <
    class Hasher,
    typename = std::enable_if_t<
        std::is_same<Hasher, HmacSha256>::value
        || std::is_same<Hasher, Blake2b>::value>>
class X3DH
{
 public:
  using curve_t = X25519;  //< Curve trait alias
  using hmac_t = Hasher;  //< HMAC-based hashing function trait alias
  using hkdf_t = HKDF<hmac_t>;  //< HKDF trait alias
  using context_t = KDFContext<hmac_t>; //< KDF context trait alias
  using salt_t = typename hmac_t::salt_t;  //< Salt trait alias

  /// @brief Do a Diffie-Hellman key exchange to derive a shared key
  /// @tparam Output Type for the output buffer (SecureBuffer >= SharedKeyLen)
  template <
      class Output,
      typename = std::enable_if_t<
          std::is_same<Output, SecBytes>::value
          || std::is_same<Output, curve_t::shrkey_t>::value>>
  inline static void DH(
      Output& out,
      const curve_t::pubkey_t& bob_static,
      const curve_t::pubkey_t& bob_ephemeral,
      const curve_t::keypair_t& alice_static,
      const curve_t::keypair_t& alice_ephemeral,
      const context_t& ctx = context_t())
  {
    if (out.size() != curve_t::SharedKeyLen)
      exception::Exception{"X3DH", __func__}.throw_ex<std::invalid_argument>(
          "invalid output key length.");


    // perform DH between Alice (local, private keys) and Bob (remote, public keys)
    curve_t::shrkey_t out1, out2, out3;
    curve_t::DH(out1, alice_static.pvtkey, bob_ephemeral);
    curve_t::DH(out2, alice_ephemeral.pvtkey, bob_static);
    curve_t::DH(out3, alice_ephemeral.pvtkey, bob_ephemeral);

    using kdf_in_t = FixedSecBytes<curve_t::SharedKeyLen * 4>;
    kdf_in_t kdf_in;
    tini2p::BytesWriter<kdf_in_t> kdf_writer(kdf_in);

    // HKDF key-material: (byte[DigestLen](0xFF) || DH(1) || DH(2) || DH(3)), see X3DH spec
    kdf_writer.write_data(std::array<std::uint8_t, Hasher::DigestLen>{
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}});
    kdf_writer.write_data(out1);
    kdf_writer.write_data(out2);
    kdf_writer.write_data(out3);

    // Derive KDF output w/ empty (all zeroes) salt, see X3DH spec
    hkdf_t::Derive(
        out.data(), out.size(), kdf_in.data(), kdf_in.size(), salt_t{}, ctx);
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_DH_X3DH_H_
