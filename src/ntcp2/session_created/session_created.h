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

#include <noise/protocol/handshakestate.h>

#include "src/ntcp2/session_created/kdf.h"
#include "src/ntcp2/session_created/message.h"

namespace tini2p
{
namespace ntcp2
{
/// @brief Session created message handler
template <class Role_t>
class SessionCreated
{
  Role_t role_;
  NoiseHandshakeState* state_;
  SessionCreatedConfirmedKDF kdf_;
  tini2p::crypto::aes::CBCEncryption encryption_;
  tini2p::crypto::aes::CBCDecryption decryption_;

 public:
  /// @brief Initialize a session created message handler
  /// @param state Handshake state from successful session requested exchange
  /// @param encrypted Encrypted payload from session requested message
  /// @param padding Padding from session requested message
  SessionCreated(
      NoiseHandshakeState* state,
      const SessionRequestMessage& message,
      const tini2p::data::IdentHash& router_hash,
      const tini2p::crypto::aes::IV& iv)
      : state_(state),
        kdf_(state),
        encryption_(router_hash, iv),
        decryption_(router_hash, iv)
  {
    if (!state)
      exception::Exception{"SessionCreated", __func__}
          .throw_ex<std::invalid_argument>("null handshake state.");

    kdf_.derive_keys(message);
  }

  /// @brief Process the session created message based on role
  /// @param message Session created message to process
  /// @throw Runtime error if Noise library returns error
  void ProcessMessage(SessionCreatedMessage& message)
  {
    if (role_.id() == noise::InitiatorRole)
      Write(message);
    else
      Read(message);
  }

 private:
  void Write(SessionCreatedMessage& message)
  {
    namespace meta = tini2p::meta::ntcp2::session_created;
    namespace x25519 = tini2p::crypto::x25519;

    const exception::Exception ex{"SessionCreated", __func__};

    NoiseBuffer data /*output*/, payload /*input*/;

    // ensure enough room for Noise payload + padding
    message.data.resize(meta::NoisePayloadSize + message.options.pad_len);
    message.options.serialize();

    auto& in = message.options.buffer;
    auto& out = message.data;

    noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    noise::setup_buffers(data, payload, bufs);
    noise::write_message(state_, &data, &payload, ex);

    // encrypt Y in-place
    encryption_.Process(
        out.data(), x25519::PubKeyLen, out.data(), x25519::PubKeyLen);

    // save ciphertext for session confirmed KDF
    save_ciphertext(message);

    if (message.options.pad_len)
      std::copy(
          message.padding.begin(),
          message.padding.end(),
          &message.data[meta::PaddingOffset]);
  }

  void Read(SessionCreatedMessage& message)
  {
    namespace meta = tini2p::meta::ntcp2::session_created;
    namespace x25519 = tini2p::crypto::x25519;

    const exception::Exception ex{"SessionCreated", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    auto& in = message.data;
    auto& out = message.options.buffer;
    const auto& in_size = meta::NoisePayloadSize;

    if (in.size() < meta::MinSize || in.size() > meta::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    // decrypt Y in-place
    decryption_.Process(
        in.data(), x25519::PubKeyLen, in.data(), x25519::PubKeyLen);

    // save ciphertext for session confirmed KDF
    save_ciphertext(message);

    noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    noise::setup_buffers(payload, data, bufs);
    noise::read_message(state_, &data, &payload, ex);

    message.options.deserialize();

    if (message.options.pad_len < meta::MinPaddingSize
        || message.options.pad_len > meta::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid padding length.");

    if (message.data.size() - meta::NoisePayloadSize == message.options.pad_len)
      {
        message.padding.resize(message.options.pad_len);
        const auto& pad_begin = &message.data[meta::PaddingOffset];
        auto& pad = message.padding;
        std::copy(pad_begin, pad_begin + pad.size(), pad.begin());
      }
  }

  void save_ciphertext(SessionCreatedMessage& message)
  {
    namespace meta = tini2p::meta::ntcp2::session_created;

    const auto* c = &message.data[meta::CiphertextOffset];
    std::copy(c, c + meta::CiphertextSize, message.ciphertext.data());
  }
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_CREATED_SESSION_CREATED_H_
