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

/// INFO: Separated to avoid forward-declaration of SessionCreatedMessage for SessionCreatedConfirmedKDF

#ifndef SRC_NTCP2_SESSION_CREATED_MESSAGE_H_
#define SRC_NTCP2_SESSION_CREATED_MESSAGE_H_

#include "src/time.h"

#include "src/crypto/poly1305.h"
#include "src/crypto/sec_bytes.h"
#include "src/crypto/x25519.h"

namespace tini2p
{
namespace ntcp2
{
/// @struct SessionCreatedMessage
/// @brief Container for session created message
struct SessionCreatedMessage
{
  enum : std::uint16_t
  {
    OptionsSize = 16,
    YSize = crypto::X25519::PublicKeyLen,
    CiphertextSize = OptionsSize + crypto::Poly1305::DigestLen,
    NoisePayloadSize = YSize + CiphertextSize,
    MinSize = NoisePayloadSize,
    MaxSize = 65535,
    MinPaddingSize = 32,
    MaxPaddingSize = MaxSize - NoisePayloadSize,
  };

  enum : std::uint8_t
  {
    PadLengthOffset = 2,
    TimestampOffset = 8,
    CiphertextOffset = YSize,
    PaddingOffset = NoisePayloadSize,
  };

  /// @brief Container for session request options
  class Options
  {
   public:
    using buffer_t = crypto::FixedSecBytes<OptionsSize>;
    using padlen_t = boost::endian::big_uint16_t;
    using timestamp_t = boost::endian::big_uint32_t;

    padlen_t pad_len;
    timestamp_t timestamp;
    buffer_t buffer;

    Options()
        : pad_len(crypto::RandInRange(MinPaddingSize, MaxPaddingSize)),
          timestamp(tini2p::time::now_s())
    {
      serialize();
    }

    Options(const std::uint16_t pad_len)
        : pad_len(pad_len), timestamp(tini2p::time::now_s())
    {
      serialize();
    }

    /// @brief Updates session created options
    /// @param pad_len Padding length for the session request
    /// @detail As initiator, must call before calling ProcessMessage
    void update(const padlen_t pad_size)
    {
      pad_len = pad_size;
      timestamp = tini2p::time::now_s();
      serialize();
    }

    /// @brief Write request options to buffer
    void serialize()
    {
      check_params({"SessionRequest", __func__});

      tini2p::BytesWriter<buffer_t> writer(buffer);
      writer.write_bytes(pad_len);
      writer.write_bytes(timestamp);
    }

    /// @brief Read request options from buffer
    void deserialize()
    {
      tini2p::BytesReader<buffer_t> reader(buffer);
      reader.read_bytes(pad_len);
      reader.read_bytes(timestamp);

      check_params({"SessionRequest", __func__});
    }

   private:
    void check_params(const exception::Exception& ex)
    {
      if (pad_len > MaxPaddingSize)
        ex.throw_ex<std::length_error>("invalid padding size.");

      if (!time::check_lag_s(timestamp))
        ex.throw_ex<std::runtime_error>("invalid timestamp.");
    }
  };

  using data_t = crypto::SecBytes;  //< Data trait alias
  using padding_t = crypto::SecBytes;  //< Data trait alias
  using options_t = Options;  //< Options trait alias
  using ciphertext_t = crypto::FixedSecBytes<CiphertextSize>;  //< Ciphertext trait alias

  data_t data;
  padding_t padding;
  options_t options;
  ciphertext_t ciphertext;

  /// @brief Create a session created message w/ minimum length
  SessionCreatedMessage() : data(MinSize), options()
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
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_CREATED_MESSAGE_H_
