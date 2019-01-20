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

#ifndef SRC_NTCP2_SESSION_CREATED_OPTIONS_H_
#define SRC_NTCP2_SESSION_CREATED_OPTIONS_H_

#include "src/ntcp2/session_created/meta.h"

namespace ntcp2
{
namespace session_created
{
/// @brief Container for session request options
struct Options
{
  boost::endian::big_uint16_t pad_len;
  boost::endian::big_uint32_t timestamp;
  std::array<std::uint8_t, meta::session_created::OptionsSize> buf;

  Options()
      : pad_len(crypto::RandInRange(
            meta::session_created::MinPaddingSize,
            meta::session_created::MaxPaddingSize)),
        timestamp(time::now_s())
  {
    serialize();
  }

  Options(const std::uint16_t pad_len)
      : pad_len(pad_len), timestamp(time::now_s())
  {
    serialize();
  }

  /// @brief Updates session created options
  /// @param pad_len Padding length for the session request
  /// @detail As initiator, must call before calling ProcessMessage
  void update(const boost::endian::big_uint16_t pad_size)
  {
    pad_len = pad_size;
    timestamp = time::now_s();
    serialize();
  }

  /// @brief Write request options to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::session_created;

    check_params({"SessionRequest", __func__});

    ntcp2::write_bytes(&buf[meta::PadLengthOffset], pad_len);
    ntcp2::write_bytes(&buf[meta::TimestampOffset], timestamp);
  }

  /// @brief Read request options from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::session_created;

    ntcp2::read_bytes(&buf[meta::PadLengthOffset], pad_len);
    ntcp2::read_bytes(&buf[meta::TimestampOffset], timestamp);

    check_params({"SessionRequest", __func__});
  }

 private:
  void check_params(const exception::Exception& ex)
  {
    if (pad_len > meta::session_created::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid padding size.");

    if (!time::check_lag_s(timestamp))
      ex.throw_ex<std::runtime_error>("invalid timestamp.");
  }
};
}  // namespace session_created
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_CREATED_OPTIONS_H_

