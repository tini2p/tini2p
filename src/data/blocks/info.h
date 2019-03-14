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

#ifndef SRC_DATA_BLOCKS_INFO_H_
#define SRC_DATA_BLOCKS_INFO_H_

#include "src/exception/exception.h"

#include "src/ntcp2/meta.h"
#include "src/time.h"

#include "src/data/router/info.h"

#include "src/data/blocks/block.h"

namespace tini2p
{
namespace data
{
/// @brief RouterInfo NTCP2 block
class InfoBlock : public Block
{
 public:
  enum : std::uint16_t
  {
    FloodFlagLen = 1,
    InfoHeaderLen = HeaderLen + FloodFlagLen,
    MinInfoLen = 440,  //< min RI (439) + flag (1)
    MaxInfoLen = MaxLen,
    MACLen = 16,
    MinPayloadLen = FloodFlagLen + MinInfoLen,
    MaxPayloadLen = FloodFlagLen + MaxInfoLen,
    MinMsg3Pt2Len = MinInfoLen + MACLen,
    MaxMsg3Pt2Len = MaxInfoLen + MACLen,
    MinPaddingLen = 0,
    MaxPaddingLen = MaxMsg3Pt2Len - MinInfoLen,
  };

  enum : std::uint8_t
  {
    FloodFlagOffset = 3,
    RouterInfoOffset,
  };

  enum struct Flag : std::uint8_t
  {
    FloodFlag = 0x01,
  };

  using flag_t = Flag;  //< Flag trait alias
  using info_ptr = Info::shared_ptr;  //< RouterInfo pointer trait alias
  using const_info_ptr = Info::const_shared_ptr;  //< Constant RouterInfo pointer trait alias

  InfoBlock()
      : Block(type_t::Info, FloodFlagLen + MinInfoLen),
        flag_(flag_t::FloodFlag),
        info_(nullptr)
  {
  }

  InfoBlock(const InfoBlock& oth)
      : Block(type_t::Info, oth.size_), flag_(oth.flag_), info_(oth.info_)
  {
  }

  /// @brief Create a InfoBlock from a RouterInfo
  /// @param info RouterInfo to create the block
  explicit InfoBlock(info_ptr info)
      : Block(type_t::Info, FloodFlagLen + MinInfoLen),
        flag_(flag_t::FloodFlag),
        info_(info)
  {
    const exception::Exception ex{"InfoBlock", __func__};

    if (!info)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    size_ = FloodFlagLen + info->size();
    buf_.resize(HeaderLen + size_);

    serialize();
  }

  /// @brief Create a InfoBlock from an iterator range
  /// @tparam BegIt Beginning iterator type
  /// @tparam EndIt Ending iterator type
  /// @param begin Beginning iterator
  /// @param end Ending iterator
  template <class BegIt, class EndIt>
  InfoBlock(const BegIt begin, const EndIt end) : Block(type_t::Info)
  {
    buf_.resize(end - begin);
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  void operator=(const InfoBlock& oth)
  {
    flag_ = oth.flag_;
    info_ = oth.info_;
  }

  void operator=(InfoBlock&& oth)
  {
    flag_ = std::move(oth.flag_);
    info_ = std::move(oth.info_);
  }

  /// @brief Get a const pointer to the router info
  const_info_ptr info() const noexcept
  {
    return info_;
  }

  /// @brief Get a non-const pointer to the router info
  info_ptr info() noexcept
  {
    return info_;
  }

  /// @brief Serialize RouterInfo block to buffer
  /// @throw Length error if invalid size
  void serialize()
  {
    const exception::Exception ex{"InfoBlock", __func__};

    check_params(ex);

    buf_.resize(size());
    tini2p::BytesWriter<buffer_t> writer(buf_);

    writer.write_bytes(type_);
    writer.write_bytes(size_);
    writer.write_bytes(flag_);

    info_->serialize();
    writer.write_data(info_->buffer());
  }

  /// @brief Deserialize RouterInfo block from buffer
  /// @throw Length error if invalid size
  void deserialize()
  {
    const exception::Exception ex{"InfoBlock", __func__};

    tini2p::BytesReader<buffer_t> reader(buf_);

    reader.read_bytes(type_);
    reader.read_bytes(size_);
    reader.read_bytes(flag_);

    crypto::SecBytes ri_buf;
    ri_buf.resize(size_ - FloodFlagLen);
    reader.read_data(ri_buf);
    info_.reset(new Info(std::move(ri_buf)));

    check_params(ex);
  }

 private:
  void check_params(const exception::Exception& ex)
  {
    // check for valid block ID
    if (type_ != type_t::Info)
      ex.throw_ex<std::runtime_error>("invalid block ID.");

    // check if flag contains reserved flag bits
    if (static_cast<std::uint8_t>(flag_) >> 1 != 0)
      ex.throw_ex<std::runtime_error>("invalid flood request flag.");

    // check for a valid router info
    if (!info_)
      ex.throw_ex<std::runtime_error>("need a valid RouterInfo.");

    // check for valid total size
    if (size_ < MinPayloadLen || size_ > MaxPayloadLen
        || size_ != FloodFlagLen + info_->size())
      ex.throw_ex<std::length_error>("invalid block size.");
  }

  flag_t flag_;
  info_ptr info_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_INFO_H_
