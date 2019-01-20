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

#ifndef SRC_SESSION_REQUEST_OPTIONS_H_
#define SRC_SESSION_REQUEST_OPTIONS_H_

#include <boost/endian/arithmetic.hpp>

#include "src/ntcp2/bytes.h"
#include "src/ntcp2/time.h"

#include "src/ntcp2/session_request/meta.h"
#include "src/ntcp2/session_confirmed/meta.h"

namespace ntcp2
{
namespace session_request
{
/// @brief Container for session request options
struct Options
{
  std::uint8_t version;
  boost::endian::big_uint16_t pad_len, m3p2_len;
  boost::endian::big_uint32_t timestamp;
  std::array<std::uint8_t, ntcp2::meta::session_request::OptionsSize> buf;

  Options()
      : m3p2_len(meta::session_confirmed::MinPayloadSize),
        pad_len(crypto::RandInRange(
            meta::session_request::MinPaddingSize,
            meta::session_request::MaxPaddingSize))
  {
    update(m3p2_len, pad_len);
  }

  /// @brief Updates session request options
  /// @param m3p2_len Message 3 Pt. 2 message length, see spec
  /// @param pad_len Padding length for the session request
  /// @detail As initiator, must call before calling ProcessMessage
  Options(
      const boost::endian::big_uint16_t m3p2_size,
      const boost::endian::big_uint16_t pad_size)
  {
    update(m3p2_size, pad_size);
  }

  /// @brief Updates session request options
  /// @param m3p2_len Message 3 Pt. 2 message length, see spec
  /// @param pad_len Padding length for the session request
  /// @detail As initiator, must call before calling ProcessMessage
  void update(
      const boost::endian::big_uint16_t m3p2_size,
      const boost::endian::big_uint16_t pad_size)
  {
    version = ntcp2::meta::Version;
    m3p2_len = m3p2_size;
    pad_len = pad_size;
    timestamp = ntcp2::time::now_s();

    check_params({"SessionRequest: Options", __func__});

    serialize();
  }

  /// @brief Write request options to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::session_request;

    using ntcp2::exception::Exception;

    check_params(Exception{"SessionRequest: Options", __func__});

    ntcp2::write_bytes(&buf[meta::VersionOffset], version);
    ntcp2::write_bytes(&buf[meta::PadLengthOffset], pad_len);
    ntcp2::write_bytes(&buf[meta::Msg3Pt2LengthOffset], m3p2_len);
    ntcp2::write_bytes(&buf[meta::TimestampOffset], timestamp);
  }

  /// @brief Read request options from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::session_request;

    using ntcp2::exception::Exception;

    ntcp2::read_bytes(&buf[meta::VersionOffset], version);
    ntcp2::read_bytes(&buf[meta::PadLengthOffset], pad_len);
    ntcp2::read_bytes(&buf[meta::Msg3Pt2LengthOffset], m3p2_len);
    ntcp2::read_bytes(&buf[meta::TimestampOffset], timestamp);

    check_params(Exception{"SessionRequest: Options", __func__});
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex) const
  {
    namespace meta = ntcp2::meta::session_request;

    if (version != ntcp2::meta::Version)
      ex.throw_ex<std::runtime_error>("invalid version.");

    if (pad_len > meta::MaxPaddingSize)
      ex.throw_ex<std::runtime_error>("invalid padding size.");

    if (m3p2_len < meta::MinMsg3Pt2Size || m3p2_len > meta::MaxMsg3Pt2Size)
      ex.throw_ex<std::runtime_error>("invalid message 3 pt 2 size.");

    if (!ntcp2::time::check_lag_s(timestamp))
      ex.throw_ex<std::runtime_error>("invalid timestamp.");
  }
};
}  // namespace session_request
}  // namespace ntcp2

#endif  // SRC_SESSION_REQUEST_OPTIONS_H_
