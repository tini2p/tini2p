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

#ifndef SRC_NTCP2_BLOCKS_DATE_TIME_H_
#define SRC_NTCP2_BLOCKS_DATE_TIME_H_

#include <boost/endian/arithmetic.hpp>

#include "src/exception/exception.h"

#include "src/ntcp2/bytes.h"
#include "src/ntcp2/meta.h"
#include "src/ntcp2/time.h"

#include "src/ntcp2/blocks/block.h"

namespace ntcp2
{
/// @brief DateTime NTCP2 block
class DateTimeBlock : public Block
{
  boost::endian::big_uint32_t timestamp_;

 public:
  DateTimeBlock()
      : Block(meta::block::DateTimeID, meta::block::TimestampSize),
        timestamp_(time::now_s())
  {
    serialize();
  }

  template <class BegIt, class EndIt>
  DateTimeBlock(const BegIt begin, const EndIt end)
      : Block(meta::block::DateTimeID, end - begin)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Get the timestamp
  decltype(timestamp_) timestamp() const noexcept
  {
    return timestamp_;
  }

  /// @brief Set the timestamp
  /// @param timestamp Timestamp to set
  void timestamp(const boost::endian::big_uint32_t timestamp)
  {
    if (!time::check_lag_s(timestamp))
      exception::Exception{"DateTimeBlock", __func__}
          .throw_ex<std::logic_error>("invalid timestamp skew.");

    timestamp_ = timestamp;
  }

  /// @brief Serialize DateTime block to buffer
  /// @throw Length error if invalid size
  void serialize()
  {
    check_params({"DateTimeBlock", __func__});

    ntcp2::BytesWriter<decltype(buf_)> writer(buf_);

    writer.write_bytes(type_);
    writer.write_bytes(size_);
    writer.write_bytes(timestamp_);
  }

  /// @brief Deserialize DateTime block from buffer
  /// @throw Length error if invalid size
  void deserialize()
  {
    ntcp2::BytesReader<decltype(buf_)> reader(buf_);

    reader.read_bytes(type_);
    reader.read_bytes(size_);
    reader.read_bytes(timestamp_);

    check_params({"DateTimeBlock", __func__});
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex)
  {
    if (type_ != meta::block::DateTimeID)
      ex.throw_ex<std::runtime_error>("invalid block ID.");

    if (size_ != meta::block::TimestampSize)
      ex.throw_ex<std::length_error>("invalid size.");

    if (!time::check_lag_s(timestamp_))
      ex.throw_ex<std::length_error>("invalid timestamp.");
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_BLOCKS_DATE_TIME_H_
