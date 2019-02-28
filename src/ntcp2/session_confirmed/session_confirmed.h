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

#ifndef SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_
#define SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_

#include <noise/protocol/handshakestate.h>

#include "src/data/blocks/options.h"
#include "src/data/blocks/padding.h"
#include "src/data/blocks/router_info.h"

#include "src/ntcp2/session_request/message.h"
#include "src/ntcp2/session_created/message.h"
#include "src/ntcp2/session_confirmed/message.h"

namespace tini2p
{
namespace ntcp2
{
/// @brief Session created message handler
template <class RoleT>
class SessionConfirmed
{
 public:
  using role_t = RoleT;  //< Role trait alias
  using state_t = noise::HandshakeState;  //< Handshake state trait alias
  using request_msg_t = SessionRequestMessage;  //< SessionRequest message trait alias
  using created_msg_t = SessionCreatedMessage;  //< SessionCreated message trait alias
  using message_t = SessionConfirmedMessage;  //< SessionConfirmed message trait alias
  using kdf_t = SessionCreatedKDF;  //< KDF trait alias

  /// @brief Initialize a session created message handler
  /// @param state Handshake state from successful session requested exchange
  /// @param message SessionCreated message with ciphertext + padding for KDF
  SessionConfirmed(state_t* state, const created_msg_t& message)
      : state_(state), kdf_(state)
  {
    if (!state)
      exception::Exception{"SessionConfirmed", __func__}
          .throw_ex<std::invalid_argument>("null handshake state.");

    kdf_.Derive(message);
  }

  /// @brief Process the session created message based on role
  /// @param message Session created message to process
  /// @throw Runtime error if Noise library returns error
  void ProcessMessage(
      message_t& message,
      const request_msg_t::options_t& options)
  {
    if (std::is_same<role_t, Initiator>::value)
      Write(message, options);
    else
      Read(message, options);
  }

 private:
  void Write(message_t& message, const request_msg_t::options_t& options)
  {
    const exception::Exception ex{"SessionConfirmed", __func__};

    NoiseBuffer data /*output*/, payload /*input*/;

    // serialize message blocks to payload buffer
    message.serialize();

    if (options.m3p2_len != message.payload_size())
      ex.throw_ex<std::logic_error>(
          "part two size must equal size sent in SessionRequest.");

    auto& in = message.payload;
    auto& out = message.data;
    const auto& in_size = in.size() - message_t::mac_t::DigestLen;

    noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    noise::setup_buffers(data, payload, bufs);
    noise::write_message(state_, &data, &payload, ex);
  }

  void Read(message_t& message, const request_msg_t::options_t& options)
  {
    const exception::Exception ex{"SessionConfirmed", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    message.payload.resize(
        static_cast<std::uint16_t>(options.m3p2_len)
        - message_t::mac_t::DigestLen);

    auto& in = message.data;
    auto& out = message.payload;

    if (in.size() < message_t::MinSize || in.size() > message_t::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    noise::setup_buffers(payload, data, bufs);
    noise::read_message(state_, &data, &payload, ex);

    if (options.m3p2_len != message.payload.size() + message_t::mac_t::DigestLen)
      ex.throw_ex<std::logic_error>(
          "part two size must equal size sent in SessionRequest.");

    // deserialize message blocks from payload buffer
    message.deserialize();
  }

  role_t role_;
  state_t* state_;
  kdf_t kdf_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_
