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
 *
 * Parts used from the Kovri Project Copyright (c) 2013-2018
*/

#ifndef SRC_CRYPTO_KEY_ELGAMAL_H_
#define SRC_CRYPTO_KEY_ELGAMAL_H_

#include <cryptopp/elgamal.h>
#include <cryptopp/queue.h>
#include <cryptopp/osrng.h>

#include "src/exception/exception.h"

#include "src/crypto/constants.h"

namespace tini2p
{
namespace crypto
{
namespace elgamal
{
enum
{
  PubKeyLen = 256,
  PvtKeyLen = 256,
};

using PubKey = CryptoPP::FixedSizeSecBlock<std::uint8_t, PubKeyLen>;
using PvtKey = CryptoPP::FixedSizeSecBlock<std::uint8_t, PvtKeyLen>;

struct Keypair
{
  PubKey pk;
  PvtKey sk;
};

inline Keypair create_keys()
{
  using tini2p::meta::crypto::constants::elgp;
  using tini2p::meta::crypto::constants::elgg;

  CryptoPP::AutoSeededRandomPool rng;

  // generate the private key
  CryptoPP::ElGamalKeys::PrivateKey key;
  key.Initialize(rng, elgp, elgg);

  // generate the public key
  PubKey pk;
  const auto& x = key.GetPrivateExponent();
  a_exp_b_mod_c(elgg, x, elgp).Encode(pk.data(), pk.size());

  PvtKey sk;
  x.Encode(sk.data(), sk.size());

  return {pk, sk};
}
}  // namespace elgamal
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_KEY_ELGAMAL_H_
