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

#ifndef SRC_SESSION_REQUEST_META_H_
#define SRC_SESSION_REQUEST_META_H_

#include "src/ntcp2/router/meta.h"

namespace ntcp2
{
namespace meta
{
namespace session_request
{
enum OptionsOffsets : std::uint8_t
{
  VersionOffset = 1,
  PadLengthOffset = 2,
  Msg3Pt2LengthOffset = 4,
  TimestampOffset = 8
};

enum MessageOffsets : std::uint8_t
{
  CiphertextOffset = 32,
  PaddingOffset = 64,
};

enum Sizes : std::uint16_t
{
  OptionsSize = 16,
  X = ntcp2::crypto::pk::X25519Len,
  CiphertextSize = OptionsSize + ntcp2::crypto::hash::Poly1305Len,
  NoisePayloadSize = X + CiphertextSize,
  MinSize = NoisePayloadSize,
  MaxSize = 65535,
  MinMsg3Pt2Size = meta::router::info::MinSize
                   + ntcp2::crypto::hash::Poly1305Len,  // see spec
  MaxMsg3Pt2Size = 65471,  // see spec
  MinPaddingSize = 32,
  MaxPaddingSize = MaxSize - NoisePayloadSize,
};
}  // namespace session_request
}  // namespace meta
}  // namespace ntcp2

#endif  // SRC_SESSION_REQUEST_META_H_
