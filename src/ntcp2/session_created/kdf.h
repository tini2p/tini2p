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

#ifndef SRC_NTCP2_SESSION_CREATED_KDF_H_
#define SRC_NTCP2_SESSION_CREATED_KDF_H_

#include "src/ntcp2/session_request/session_request.h"
#include "src/ntcp2/session_created/message.h"

namespace ntcp2
{
  /// @class SessionCreatedConfirmedKDF
  /// @brief Perform key derivation for SessionCreated and SessionConfirmed messages
  /// @detail Key derivation is exactly the same for both messages
  /// @notes Calls MixHash on the previous message's ciphertext and padding, see spec
  class SessionCreatedConfirmedKDF
  {
    NoiseHandshakeState* state_;
    const std::array<std::uint8_t, 0> zero_len_{};

   public:
    SessionCreatedConfirmedKDF(NoiseHandshakeState* state) : state_(state)
    {
      if (!state)
        exception::Exception{"SessionCreatedConfirmedKDF", __func__}
            .throw_ex<std::invalid_argument>("null handshake state.");
    }

    /// @notes Don't free state, handled by owner
    ~SessionCreatedConfirmedKDF() {}

    /// @brief Derive keys for session created message
    /// @param message Successfully processed session request message
    template <
        class Msg,
        typename = std::enable_if_t<
            std::is_same<Msg, ntcp2::SessionRequestMessage>::value
            || std::is_same<Msg, ntcp2::SessionCreatedMessage>::value>>
    void derive_keys(const Msg& message)
    {
      const exception::Exception ex{"SessionCreatedConfirmedKDF", __func__};

      if (message.ciphertext.empty() || message.padding.empty())
        ex.throw_ex<std::length_error>(
            ("null MixHash parameter(s): ciphertext - "
             + std::to_string(message.ciphertext.size()) + " padding - "
             + std::to_string(message.padding.size()))
                .c_str());

      noise::mix_hash(state_, message.ciphertext, ex);
      noise::mix_hash(state_, message.padding, ex);
    }
  };
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_CREATED_KDF_H_
