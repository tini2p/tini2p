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

#ifndef SRC_NTCP2_SESSION_CREATED_META_H_
#define SRC_NTCP2_SESSION_CREATED_META_H_

namespace tini2p
{
namespace meta
{
namespace ntcp2
{
namespace session_created
{
enum Sizes : std::uint16_t
{
  OptionsSize = 16,
  Y = tini2p::crypto::x25519::PubKeyLen,
  CiphertextSize = OptionsSize + tini2p::crypto::hash::Poly1305Len,
  NoisePayloadSize = Y + CiphertextSize,
  MinSize = NoisePayloadSize,
  MaxSize = 65535,
  MinPaddingSize = 32,
  MaxPaddingSize = MaxSize - NoisePayloadSize,
};

enum OptionsOffsets : std::uint8_t
{
  PadLengthOffset = 2,
  TimestampOffset = 8,
};

enum MessageOffsets : std::uint8_t
{
  CiphertextOffset = Y,
  PaddingOffset = NoisePayloadSize,
};
}  // namespace session_created
}  // namespace ntcp2
}  // namespace meta
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_CREATED_META_H_
