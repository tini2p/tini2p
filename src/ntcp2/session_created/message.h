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

#ifndef SRC_NTCP2_SESSION_CREATED_MESSAGE_H_
#define SRC_NTCP2_SESSION_CREATED_MESSAGE_H_

#include "src/ntcp2/session_created/meta.h"
#include "src/ntcp2/session_created/options.h"

namespace ntcp2
{
/// @brief Container for session created message
struct SessionCreatedMessage
{
  std::vector<std::uint8_t> data, padding;
  ntcp2::session_created::Options options;
  CryptoPP::FixedSizeSecBlock<
      std::uint8_t,
      ntcp2::meta::session_created::CiphertextSize>
      ciphertext;

  /// @brief Create a session created message w/ minimum length
  SessionCreatedMessage() : data(meta::session_created::MinSize), options()
  {
    if (options.pad_len)
      {
        padding.resize(options.pad_len);
        crypto::RandBytes(padding.data(), padding.size());
      }
  }

  /// @brief Create a session created message w/ specified padding length
  /// @para pad_len Length of padding to include
  SessionCreatedMessage(const std::uint16_t pad_len) : options(pad_len) {
    padding.resize(pad_len);
    crypto::RandBytes(padding.data(), padding.size());
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_CREATED_MESSAGE_H_
