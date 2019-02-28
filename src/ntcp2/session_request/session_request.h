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

#ifndef SRC_SESSION_REQUEST_SESSION_REQUEST_H_
#define SRC_SESSION_REQUEST_SESSION_REQUEST_H_

#include <chrono>

#include <noise/protocol/handshakestate.h>

#include "src/crypto/aes.h"
#include "src/crypto/rand.h"
#include "src/crypto/sec_bytes.h"

#include "src/data/router/info.h"

#include "src/ntcp2/session_request/kdf.h"
#include "src/ntcp2/session_request/message.h"

namespace tini2p
{
namespace ntcp2
{
template <class RoleT>
class SessionRequest
{
 public:
  using role_t = RoleT;  //< Role trait alias
  using obfse_t = tini2p::crypto::AES;  //< OBFSE impl trait alias
  using kdf_t = SessionRequestKDF;  //< KDF trait alias
  using message_t = SessionRequestMessage;  //< Message trait alias

  /// @brief Create a SessionRequest processor for a given destination
  /// @param state Pointer to initialized Noise handshake state
  /// @param router_hash Hash of destination RouterIdentity
  /// @param iv Remote AES IV for key obfuscation
  /// @throw Invalid argument on null handshake state
  SessionRequest(
      noise::HandshakeState* state,
      const tini2p::data::Identity::hash_t& router_hash,
      const obfse_t::iv_t& iv)
      : state_(state),
        kdf_(state_),
        obfse_(static_cast<obfse_t::key_t::buffer_t>(router_hash), iv)
  {
    if (!state)
      exception::Exception{"SessionRequest", __func__}
          .throw_ex<std::invalid_argument>("null handshake state.");
  }

  /// @brief Get a mutable reference to the KDF object
  kdf_t& kdf() noexcept
  {
    return kdf_;
  }

  /// @brief Get a const reference to the KDF object
  const kdf_t& kdf() const noexcept
  {
    return kdf_;
  }

  /// @brief Get a const reference to the OBFSE crypto impl
  const obfse_t& obfse() const noexcept
  {
    return obfse_;
  }

  /// @brief Process session request message based on role
  void ProcessMessage(message_t& message)
  {
    if (std::is_same<role_t, Initiator>::value)
      Write(message);  // write and encrypt message
    else
      Read(message);  // decrypt and read message
  }

 private:
  void Write(message_t& message)
  {
    using tini2p::crypto::X25519;

    const exception::Exception ex{"SessionRequest", __func__};

    NoiseBuffer data /*output*/, payload /*input*/;

    // ensure enough room to hold Noise payload + padding
    message.data.resize(
        message_t::NoisePayloadSize
        + static_cast<std::uint16_t>(message.options.pad_len));

    auto& in = message.options.buffer;
    auto& out = message.data;

    noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    noise::setup_buffers(data, payload, bufs);
    noise::write_message(state_, &data, &payload, ex);

    // encrypt ephemeral key in place
    obfse_.Process<obfse_t::encrypt_m>(out.data(), X25519::PublicKeyLen);

    // save ciphertext for session created KDF
    std::copy_n(
        &message.data[message_t::CiphertextOffset],
        message_t::CiphertextSize,
        message.ciphertext.data());

    if (message.options.pad_len < message_t::MinPaddingSize
        || message.options.pad_len > message_t::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid padding length.");

    std::copy(
        message.padding.begin(),
        message.padding.end(),
        &message.data[message_t::PaddingOffset]);
  }

  void Read(message_t& message)
  {
    using tini2p::crypto::X25519;

    const exception::Exception ex{"SessionRequest", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    auto& in = message.data;
    auto& out = message.options.buffer;
    const auto& in_size = message_t::NoisePayloadSize;

    if (in.size() < message_t::MinSize || in.size() > message_t::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    // save ciphertext for session created KDF
    std::copy_n(
        &message.data[message_t::CiphertextOffset],
        message_t::CiphertextSize,
        message.ciphertext.data());

    // decrypt ephemeral key in place
    obfse_.Process<obfse_t::decrypt_m>(in.data(), X25519::PublicKeyLen);

    noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    noise::setup_buffers(payload, data, bufs);
    noise::read_message(state_, &data, &payload, ex);

    // deserialize options from buffer
    message.options.deserialize();

    if (message.options.pad_len < message_t::MinPaddingSize
        || message.options.pad_len > message_t::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid padding length.");

    if (message.data.size() - message_t::NoisePayloadSize
        == message.options.pad_len)
      {
        auto& pad = message.padding;
        pad.resize(message.options.pad_len);
        std::copy_n(
            &message.data[message_t::PaddingOffset], pad.size(), pad.data());
      }
  }

  role_t role_;
  noise::HandshakeState* state_;
  kdf_t kdf_;
  obfse_t obfse_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_SESSION_REQUEST_SESSION_REQUEST_H_
