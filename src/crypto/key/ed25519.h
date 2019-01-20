/* Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
 * Copyright (c) 2019, tini2p
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

#ifndef SRC_CRYPTO_KEY_ED25519_H_
#define SRC_CRYPTO_KEY_ED25519_H_

#include <cryptopp/naclite.h>
#include <cryptopp/secblock.h>

#include "src/exception/exception.h"

namespace ntcp2
{
namespace crypto
{
namespace pk
{
enum
{
  Ed25519Len = 32,
};

using Ed25519 = CryptoPP::FixedSizeSecBlock<std::uint8_t, Ed25519Len>;
}  // namespace pk

namespace sk
{
enum
{
  Ed25519Len = 64,
};

using Ed25519 = CryptoPP::FixedSizeSecBlock<std::uint8_t, Ed25519Len>;
}  // namespace sk

namespace ed25519
{
struct Keypair
{
  ntcp2::crypto::pk::Ed25519 pk;
  ntcp2::crypto::sk::Ed25519 sk;
};

/// @brief Create an Ed25519 key pair
/// @detail From Kovri Project
inline Keypair create_keys()
{
  ntcp2::crypto::pk::Ed25519 pk;
  ntcp2::crypto::sk::Ed25519 sk;

  if (CryptoPP::NaCl::crypto_sign_keypair(pk.data(), sk.data()))
    ntcp2::exception::Exception{"Crypto", __func__}
        .throw_ex<std::runtime_error>("could not create ed25519 keypair");

  return {pk, sk};
}
}  // namespace ed25519
}  // namespace crypto
}  // namespace ntcp2

#endif  // SRC_CRYPTO_KEY_ED25519_H_
