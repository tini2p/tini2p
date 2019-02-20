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

#ifndef SRC_DATA_BLOCKS_META_ROUTER_INFO_H_
#define SRC_DATA_BLOCKS_META_ROUTER_INFO_H_

namespace tini2p
{
namespace meta
{
namespace block
{
enum RouterInfoSizes : std::uint16_t
{
  FloodFlagSize = 1,
  RouterHeaderSize = block::HeaderSize + FloodFlagSize,
  MinRouterInfoSize = 440,  //< min RI (439) + flag (1)
  MaxRouterInfoSize = MaxSize,
  MinRIPayloadSize = FloodFlagSize + MinRouterInfoSize,
  MaxRIPayloadSize = FloodFlagSize + MaxRouterInfoSize,
  MinMsg3Pt2Size = MinRouterInfoSize + 16,  //< MinRISize + Poly1305Len
  MaxMsg3Pt2Size = MaxRouterInfoSize + 16,  //< MaxRISize + Poly1305Len
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
  MinPaddingSize = 0,
  MaxPaddingSize = MaxMsg3Pt2Size - MinRouterInfoSize,
};
}  // namespace block
}  // namespace meta
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_META_ROUTER_INFO_H_
