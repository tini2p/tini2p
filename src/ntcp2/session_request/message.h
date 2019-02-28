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

#ifndef SRC_SESSION_REQUEST_MESSAGE_H_
#define SRC_SESSION_REQUEST_MESSAGE_H_

#include <boost/endian/arithmetic.hpp>

#include "src/bytes.h"
#include "src/time.h"

#include "src/crypto/poly1305.h"
#include "src/crypto/rand.h"
#include "src/crypto/sec_bytes.h"
#include "src/crypto/sha.h"
#include "src/crypto/x25519.h"

#include "src/data/router/meta/info.h"

#include "src/ntcp2/meta.h"

namespace tini2p
{
namespace ntcp2
{
struct SessionRequestMessage
{
  enum : std::uint8_t
  {
    CiphertextOffset = 32,
    PaddingOffset = 64,
    VersionOffset = 1,
    PadLengthOffset = 2,
    Msg3Pt2LengthOffset = 4,
    TimestampOffset = 8
  };

  enum : std::uint16_t
  {
    OptionsSize = 16,
    XSize = crypto::X25519::PublicKeyLen,
    CiphertextSize = OptionsSize + crypto::Poly1305::DigestLen,
    NoisePayloadSize = XSize + CiphertextSize,
    MinSize = NoisePayloadSize,
    MaxSize = 65535,
    MinMsg3Pt2Size = tini2p::meta::router::info::MinSize
                     + crypto::Poly1305::DigestLen,  // see spec
    MaxMsg3Pt2Size = 65471,  // see spec
    MinPaddingSize = 32,
    MaxPaddingSize = MaxSize - NoisePayloadSize,
  };

  /// @struct SessionRequestOptions
  /// @brief Container for session request options
  struct Options
  {
    using buffer_t = crypto::FixedSecBytes<OptionsSize>;
    using version_t = std::uint8_t;
    using padlen_t = boost::endian::big_uint16_t;
    using m3p2len_t = boost::endian::big_uint16_t;
    using timestamp_t = boost::endian::big_uint32_t;

    version_t version;
    padlen_t pad_len;
    m3p2len_t m3p2_len;
    timestamp_t timestamp;
    buffer_t buffer;

    Options()
        : m3p2_len(MinMsg3Pt2Size),
          pad_len(crypto::RandInRange(MinPaddingSize, MaxPaddingSize))
    {
      update(m3p2_len, pad_len);
    }

    /// @brief Updates session request options
    /// @param m3p2_len Message 3 Pt. 2 message length, see spec
    /// @param pad_len Padding length for the session request
    /// @detail As initiator, must call before calling ProcessMessage
    Options(const m3p2len_t m3p2_size, const padlen_t pad_size)
    {
      update(m3p2_size, pad_size);
    }

    /// @brief Updates session request options
    /// @param m3p2_len Message 3 Pt. 2 message length, see spec
    /// @param pad_len Padding length for the session request
    /// @detail As initiator, must call before calling ProcessMessage
    void update(const m3p2len_t m3p2_size, const padlen_t pad_size)
    {
      version = tini2p::meta::ntcp2::Version;
      m3p2_len = m3p2_size;
      pad_len = pad_size;
      timestamp = tini2p::time::now_s();

      check_params({"SessionRequest: Options", __func__});

      serialize();
    }

    /// @brief Write request options to buffer
    void serialize()
    {
      check_params({"SessionRequest: Options", __func__});

      tini2p::BytesWriter<buffer_t> writer(buffer);
      writer.write_bytes(version);
      writer.write_bytes(pad_len);
      writer.write_bytes(m3p2_len);
      writer.write_bytes(timestamp);
    }

    /// @brief Read request options from buffer
    void deserialize()
    {
      tini2p::BytesReader<buffer_t> reader(buffer);
      reader.read_bytes(version);
      reader.read_bytes(pad_len);
      reader.read_bytes(m3p2_len);
      reader.read_bytes(timestamp);

      check_params({"SessionRequest: Options", __func__});
    }

   private:
    void check_params(const exception::Exception& ex) const
    {
      if (version != tini2p::meta::ntcp2::Version)
        ex.throw_ex<std::runtime_error>("invalid version.");

      if (pad_len > MaxPaddingSize)
        ex.throw_ex<std::runtime_error>("invalid padding size.");

      if (m3p2_len < MinMsg3Pt2Size || m3p2_len > MaxMsg3Pt2Size)
        ex.throw_ex<std::runtime_error>("invalid message 3 pt 2 size.");

      if (!time::check_lag_s(timestamp))
        ex.throw_ex<std::runtime_error>("invalid timestamp.");
    }
  };

  using data_t = crypto::SecBytes;  //< Data trait alias
  using padding_t = crypto::SecBytes;  //< Padding trait alias
  using ciphertext_t = crypto::FixedSecBytes<CiphertextSize>;  //< Ciphertext trait alias
  using options_t = Options;  //< Options trait alias

  data_t data;
  padding_t padding;
  ciphertext_t ciphertext;
  options_t options;

  SessionRequestMessage() : data(NoisePayloadSize), options()
  {
    if (options.pad_len)
    {
      padding.resize(options.pad_len);
      crypto::RandBytes(padding);
    }
  }

  SessionRequestMessage(
      const std::uint16_t m3p2_len,
      const std::uint16_t pad_len)
      : data(NoisePayloadSize + pad_len), options(m3p2_len, pad_len)
  {
    if (pad_len)
    {
      padding.resize(pad_len);
      crypto::RandBytes(padding);
    }
  }
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_SESSION_REQUEST_MESSAGE_H_
