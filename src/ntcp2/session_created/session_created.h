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

#ifndef SRC_NTCP2_SESSION_CREATED_SESSION_CREATED_H_
#define SRC_NTCP2_SESSION_CREATED_SESSION_CREATED_H_

#include "src/ntcp2/noise.h"

#include "src/ntcp2/session_created/kdf.h"
#include "src/ntcp2/session_created/message.h"

namespace tini2p
{
namespace ntcp2
{
/// @brief Session created message handler
/// @tparam RoleT Handshake role
template <class RoleT>
class SessionCreated
{
 public:
  using role_t = RoleT;  //< Role trait alias
  using obfse_t = tini2p::crypto::AES;  //< OBFSE impl trait alias
  using request_msg_t = SessionRequestMessage;  //< SessionRequest message trait alias
  using message_t = SessionCreatedMessage;  //< SessionCreated message trait alias
  using kdf_t = SessionCreatedKDF;  //< KDF trait alias

  /// @brief Initialize a session created message handler
  /// @param state Handshake state from successful session requested exchange
  /// @param encrypted Encrypted payload from session requested message
  /// @param padding Padding from session requested message
  SessionCreated(
      noise::HandshakeState* state,
      const request_msg_t& message,
      const data::Identity::hash_t& router_hash,
      const obfse_t::iv_t& iv)
      : state_(state), kdf_(state), obfse_(router_hash, iv)
  {
    if (!state)
      exception::Exception{"SessionCreated", __func__}
          .throw_ex<std::invalid_argument>("null handshake state.");

    kdf_.Derive(message);
  }

  /// @brief Process the session created message based on role
  /// @param message Session created message to process
  /// @throw Runtime error if Noise library returns error
  void ProcessMessage(message_t& message)
  {
    if (std::is_same<role_t, Initiator>::value)
      Write(message);
    else
      Read(message);
  }

 private:
  void Write(message_t& message)
  {
    using tini2p::crypto::X25519;

    const exception::Exception ex{"SessionCreated", __func__};

    NoiseBuffer data /*output*/, payload /*input*/;

    // ensure enough room for Noise payload + padding
    message.data.resize(
        message_t::NoisePayloadSize + message.options.pad_len);
    message.options.serialize();

    auto& in = message.options.buffer;
    auto& out = message.data;

    noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    noise::setup_buffers(data, payload, bufs);
    noise::write_message(state_, &data, &payload, ex);

    // encrypt Y in-place
    obfse_.Process<obfse_t::encrypt_m>(out.data(), X25519::PublicKeyLen);

    // save ciphertext for session confirmed KDF
    std::copy_n(
        &message.data[message_t::CiphertextOffset],
        message_t::CiphertextSize,
        message.ciphertext.data());

    if (message.options.pad_len)
      std::copy(
          message.padding.begin(),
          message.padding.end(),
          &message.data[message_t::PaddingOffset]);
  }

  void Read(message_t& message)
  {
    using tini2p::crypto::X25519;

    const exception::Exception ex{"SessionCreated", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    auto& in = message.data;
    auto& out = message.options.buffer;
    const auto& in_size = message_t::NoisePayloadSize;

    if (in.size() < message_t::MinSize
        || in.size() > message_t::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    // decrypt Y in-place
    obfse_.Process<obfse_t::decrypt_m>(in.data(), X25519::PublicKeyLen);

    // save ciphertext for session confirmed KDF
    std::copy_n(
        &message.data[message_t::CiphertextOffset],
        message_t::CiphertextSize,
        message.ciphertext.data());

    noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    noise::setup_buffers(payload, data, bufs);
    noise::read_message(state_, &data, &payload, ex);

    message.options.deserialize();

    if (message.options.pad_len < message_t::MinPaddingSize
        || message.options.pad_len > message_t::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid padding length.");

    if (message.data.size() - message_t::NoisePayloadSize
        == message.options.pad_len)
      {
        message.padding.resize(message.options.pad_len);
        std::copy_n(
            &message.data[message_t::PaddingOffset],
            message.padding.size(),
            message.padding.data());
      }
  }

  role_t role_;
  noise::HandshakeState* state_;
  kdf_t kdf_;
  obfse_t obfse_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_CREATED_SESSION_CREATED_H_
