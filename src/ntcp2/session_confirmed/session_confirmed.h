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

#include "src/ntcp2/session_request/options.h"

#include "src/ntcp2/session_created/kdf.h"

#include "src/ntcp2/blocks/options.h"
#include "src/ntcp2/blocks/padding.h"
#include "src/ntcp2/blocks/router_info.h"

#include "src/ntcp2/session_confirmed/meta.h"

namespace ntcp2
{
/// @brief Container for session created message
struct SessionConfirmedMessage
{
  std::vector<std::uint8_t> data, payload;
  ntcp2::RouterInfoBlock ri_block;
  ntcp2::OptionsBlock opt_block;
  ntcp2::PaddingBlock pad_block;

  explicit SessionConfirmedMessage(const std::uint16_t size)
      : data(size), ri_block(), opt_block(), pad_block()
  {
  }

  /// @brief Create a SessionConfirmedMessage from a RouterInfo
  /// @param info RouterInfo pointer to use in the message
  explicit SessionConfirmedMessage(router::Info* info)
      : ri_block(info),
        pad_block(crypto::RandInRange(
            meta::session_confirmed::MinPaddingSize,
            meta::session_confirmed::MaxPaddingSize))
  {
    serialize();
  }

  /// @brief Create a SessionConfirmedMessage from a RouterInfo (w/ padding)
  /// @param info RouterInfo pointer to use in the message
  /// @param pad_len Length of padding to include
  SessionConfirmedMessage(router::Info* info, const std::uint16_t pad_len)
      : ri_block(info), pad_block(pad_len)
  {
    serialize();
  }

  /// @brief Get the total SessionConfirmed message size
  std::uint16_t size() const
  {
    return meta::session_confirmed::PartOneSize + payload_size();
  }

  /// @brief Get the SessionConfirmed part two payload size
  std::uint16_t payload_size() const
  { 
    const auto& opt_size = opt_block.data_size();
    const auto& pad_size = pad_block.data_size();

    return ri_block.size() + (opt_size ? opt_block.size() : opt_size)
           + (pad_size ? pad_block.size() : pad_size) + crypto::hash::Poly1305Len;
  }

  /// @brief Serialize the message + payload to buffer
  void serialize()
  {
    data.resize(size());
    payload.resize(payload_size());

    ntcp2::BytesWriter<decltype(payload)> writer(payload);

    // serialize and write RouterInfo block to payload buffer
    ri_block.serialize();
    writer.write_data(ri_block.buffer());

    if (opt_block.data_size())
      {  // serialize and write Options block to payload buffer
        opt_block.serialize();
        writer.write_data(opt_block.buffer());
      }

    if (pad_block.data_size())
      {  // serialize and write Padding block to payload buffer
        pad_block.serialize();
        writer.write_data(pad_block.buffer());
      }
  }

  /// @brief Deserialize the message + payload from buffer
  void deserialize()
  {
    const exception::Exception ex{"SessionConfirmedMessage", __func__};

    std::uint8_t block_count(0);
    constexpr const std::uint8_t first(0), second(1), third(2), max(3);

    ntcp2::BytesReader<decltype(payload)> reader(payload);

    // Read and deserialize a block from the buffer
    const auto read_deserialize = [&reader, this](Block& block) {
      boost::endian::big_uint16_t block_size;
      ntcp2::read_bytes(
          &payload[reader.count() + meta::block::SizeOffset], block_size);

      if (block_size)
        {
          block.buffer().resize(meta::block::HeaderSize + block_size);
          reader.read_data(block.buffer());
          block.deserialize();
        }
      else
        reader.skip_bytes(meta::block::HeaderSize);
    };

    // Process RouterInfo, Options and Padding blocks
    const auto process_blocks = [&block_count,
                                 &reader,
                                 this,
                                 read_deserialize,
                                 ex]() {
      std::uint8_t block_type;
      ntcp2::read_bytes(&payload[reader.count()], block_type);

      if (block_count == first && block_type != meta::block::RouterInfoID)
        ex.throw_ex<std::logic_error>("RouterInfo must be the first block.");

      if (block_count == second && block_type != meta::block::OptionsID
          && block_type != meta::block::PaddingID)
        ex.throw_ex<std::logic_error>(
            "second block must be Options or Padding block.");

      if (block_count == third && block_type != meta::block::PaddingID)
        ex.throw_ex<std::logic_error>("last block must be Padding block.");

      if (block_count == max)
        ex.throw_ex<std::logic_error>("Padding must be the final block.");

      if (block_type == meta::block::RouterInfoID)
        {
          read_deserialize(ri_block);
          ++block_count;
        }
      else if (block_type == meta::block::OptionsID)
        {
          read_deserialize(opt_block);
          ++block_count;
        }
      else if (block_type == meta::block::PaddingID)
        {
          read_deserialize(pad_block);
          block_count = max;
        }
    };

    if (reader.gcount() <= crypto::hash::Poly1305Len) 
      ex.throw_ex<std::logic_error>("payload must contain a RouterInfo block.");

    while (reader.gcount() >= meta::block::HeaderSize + crypto::hash::Poly1305Len)
      process_blocks();

    if (reader.gcount() > crypto::hash::Poly1305Len)
      ex.throw_ex<std::length_error>("invalid trailing bytes.");
  }
};

/// @brief Session created message handler
template <class Role_t>
class SessionConfirmed
{
  Role_t role_;
  NoiseHandshakeState* state_;
  SessionCreatedConfirmedKDF kdf_;

 public:
  /// @brief Initialize a session created message handler
  /// @param state Handshake state from successful session requested exchange
  /// @param message SessionCreated message with ciphertext + padding for KDF
  SessionConfirmed(
      NoiseHandshakeState* state,
      const ntcp2::SessionCreatedMessage& message)
      : state_(state), kdf_(state)
  {
    if (!state)
      exception::Exception{"SessionConfirmed", __func__}
          .throw_ex<std::invalid_argument>("null handshake state.");

    kdf_.derive_keys(message);
  }

  /// @brief Process the session created message based on role
  /// @param message Session created message to process
  /// @throw Runtime error if Noise library returns error
  void ProcessMessage(
      SessionConfirmedMessage& message,
      const session_request::Options& options)
  {
    if (role_.id() == noise::InitiatorRole)
      Write(message, options);
    else
      Read(message, options);
  }

 private:
  void Write(
      SessionConfirmedMessage& message,
      const session_request::Options& options)
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
    const auto& in_size = in.size() - crypto::hash::Poly1305Len;

    noise::RawBuffers bufs{in.data(), in_size, out.data(), out.size()};
    noise::setup_buffers(data, payload, bufs);
    noise::write_message(state_, &data, &payload, ex);
  }

  void Read(
      SessionConfirmedMessage& message,
      const session_request::Options& options)
  {
    namespace meta = ntcp2::meta::session_confirmed;

    const exception::Exception ex{"SessionConfirmed", __func__};

    NoiseBuffer data /*input*/, payload /*output*/;

    message.payload.resize(
        (std::uint16_t)options.m3p2_len - crypto::hash::Poly1305Len);

    auto& in = message.data;
    auto& out = message.payload;

    if (in.size() < meta::MinSize || in.size() > meta::MaxSize)
      ex.throw_ex<std::length_error>("invalid message size.");

    noise::RawBuffers bufs{in.data(), in.size(), out.data(), out.size()};
    noise::setup_buffers(payload, data, bufs);
    noise::read_message(state_, &data, &payload, ex);

    if (options.m3p2_len != message.payload.size() + crypto::hash::Poly1305Len)
      ex.throw_ex<std::logic_error>(
          "part two size must equal size sent in SessionRequest.");

    // deserialize message blocks from payload buffer
    message.deserialize();
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_CONFIRMED_SESSION_CONFIRMED_H_
