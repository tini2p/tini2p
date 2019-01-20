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

#ifndef SRC_NTCP2_BLOCKS_META_H_
#define SRC_NTCP2_BLOCKS_META_H_

#include "src/ntcp2/session_request/meta.h"

namespace ntcp2
{
namespace meta
{
namespace block
{
enum Sizes : std::uint16_t
{
  TypeSize = 1,
  SizeSize = 2,
  HeaderSize = 3,
  MaxSize = 65516,
};

enum Offsets : std::uint8_t
{
  TypeOffset = 0,
  SizeOffset = 1,
  DataOffset = 3
};

enum Types : std::uint8_t
{
  DateTimeID = 0,
  OptionsID,
  RouterInfoID,
  I2NPMessageID,
  TerminationID,
  // 5-223 unknown, see spec
  // 224-253 + 255 reserved for future use, see spec
  PaddingID = 254,
  ReservedID = 255,
};

/* Date Time
 * */
enum DateTimeSizes : std::uint8_t
{
  TimestampSize = 4,
};

enum DateTimeOffsets : std::uint8_t
{
  TimestampOffset = 3,
};

/* Options
 * */
enum OptionsSizes : std::uint8_t
{
  OptionsSize = 12,
};

enum OptionsOffsets : std::uint8_t
{
  TMinOffset = 3,
  TMaxOffset,
  RMinOffset,
  RMaxOffset,
  TDummyOffset,
  RDummyOffset = 9,
  TDelayOffset = 11,
  RDelayOffset = 13
};

constexpr static float CastRatio = 16.0, MinPaddingRatio = 0,
                       MaxPaddingRatio = 15.9375;

/* RouterInfo
 * */

enum RouterInfoSizes : std::uint16_t
{
  FloodFlagSize = 1,
  RouterHeaderSize = block::HeaderSize + FloodFlagSize,
  MinRouterInfoSize = 440,  // min RI (439) + flag (1)
  MaxRouterInfoSize = MaxSize,
  MinRIPayloadSize = FloodFlagSize + MinRouterInfoSize,
  MaxRIPayloadSize = FloodFlagSize + MaxRouterInfoSize,
};

enum RouterInfoOffsets : std::uint8_t
{
  FloodFlagOffset = 3,
  RouterInfoOffset,
};

enum RouterInfoFlags : std::uint8_t
{
  FloodFlag = 0x01,
};

enum RouterInfoMasks : std::uint8_t
{
  FloodFlagMask = 0x01,
};

enum PaddingSizes : std::uint16_t
{
  MaxPaddingSize = meta::session_request::MaxMsg3Pt2Size - MinRouterInfoSize,
};

/* I2NP
 * */

enum I2NPSizes
{
  I2NPHeaderSize = 9,
  MinI2NPSize = I2NPHeaderSize,
  MaxI2NPSize = MaxSize,
};

enum I2NPMessageType : std::uint8_t
{
  Reserved = 0,
  DatabaseStore,
  DatabaseLookup,
  DatabaseSearchReply,
  DeliveryStatus = 10,
  Garlic,
  TunnelData = 18,
  TunnelGateway,
  Data,
  TunnelBuild,
  TunnelBuildReply,
  VariableTunnelBuild,
  VariableTunnelBuildReply,
  FutureReserved = 255,
};

enum I2NPOffsets
{
  I2NPTypeOffset = 3,
  MessageIDOffset = 4,
  ExpirationOffset = 8,
  MessageOffset = 12,
};

enum I2NPLimits
{
  DefaultI2NPExp = 120,  //< in seconds
};

/* Termination
 * */

enum TerminationSizes
{
  TermHeaderSize = 9,
  MinTermSize = TermHeaderSize,
  MaxTermSize = MaxSize,
  MaxTermAddDataSize = MaxTermSize - TermHeaderSize,
};

enum TerminationReason : std::uint8_t
{
  NormalClose = 0,
  TerminationRecvd,
  IdleTimeout,
  RouterShutdown,
  DataPhaseAEADFail,
  IncompatibleOpts,
  IncompatibleSig,
  ClockSkew,
  PaddingViolation,
  AEADFramingError,
  PayloadFormatError,
  SessionRequestError,
  SessionCreatedError,
  SessionConfirmedError,
  ReadTimeout,
  SigVerificationFail,
  InvalidS,
  Banned
};
}  // namespace block
}  // namespace meta
}  // namespace ntcp2

#endif  // SRC_NTCP2_BLOCKS_META_H_
