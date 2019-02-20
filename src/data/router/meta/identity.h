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

#ifndef SRC_DATA_ROUTER_META_IDENTITY_H_
#define SRC_DATA_ROUTER_META_IDENTITY_H_

namespace tini2p
{
namespace meta
{
namespace router
{
namespace identity
{
enum Sizes : std::uint16_t
{
  MinSize = 387,  // DSA cert
  DefaultSize = 391,  // Ed25519 key cert
  MaxSize = DefaultSize,
  PaddingSize = 96,  // DsaPkLen(128) - Ed25519PkLen(32), see spec
};

enum Offsets : std::uint16_t
{
  CryptoKeyOffset = 0,
  PaddingOffset = CryptoKeyOffset + tini2p::crypto::elgamal::PubKeyLen,
  SignKeyOffset = PaddingOffset + PaddingSize,
  CertOffset = SignKeyOffset + tini2p::crypto::ed25519::PubKeyLen,
  CertSizeOffset = CertOffset + cert::CertTypeSize,
};
}  // namespace identity
}  // namespace router
}  // namespace meta
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_META_IDENTITY_H_
