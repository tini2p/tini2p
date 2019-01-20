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

#ifndef SRC_NTCP2_BLOCKS_ROUTER_INFO_H_
#define SRC_NTCP2_BLOCKS_ROUTER_INFO_H_

#include "src/exception/exception.h"

#include "src/ntcp2/meta.h"
#include "src/ntcp2/time.h"

#include "src/ntcp2/blocks/block.h"
#include "src/ntcp2/router/info.h"

namespace ntcp2
{
/// @brief RouterInfo NTCP2 block
class RouterInfoBlock : public Block
{
  meta::block::RouterInfoFlags flag_;
  std::unique_ptr<router::Info> own_info_;  // owning ptr for deserializing
  router::Info* info_;  // non-owning ptr

 public:
  RouterInfoBlock()
      : Block(
            meta::block::RouterInfoID,
            meta::block::FloodFlagSize + meta::router::info::DefaultSize),
        flag_(meta::block::FloodFlag),
        info_(nullptr)
  {
  }

  /// @brief Create a RouterInfoBlock from a RouterInfo
  /// @param info RouterInfo to create the block
  explicit RouterInfoBlock(router::Info* info)
      : Block(
            meta::block::RouterInfoID,
            meta::block::FloodFlagSize + info->size()),
        flag_(meta::block::FloodFlag),
        info_(info)
  {
    serialize();
  }

  /// @brief Create a RouterInfoBlock from an iterator range
  /// @tparam BegIt Beginning iterator type
  /// @tparam EndIt Ending iterator type
  /// @param begin Beginning iterator
  /// @param end Ending iterator
  template <class BegIt, class EndIt>
  RouterInfoBlock(const BegIt begin, const EndIt end)
      : Block(meta::block::RouterInfoID)
  {
    buf_.resize(end - begin);
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Get a const reference to the router info
  const router::Info& info() const noexcept
  {
    return *info_;
  }

  /// @brief Serialize RouterInfo block to buffer
  /// @throw Length error if invalid size
  void serialize()
  {
    const exception::Exception ex{"RouterInfoBlock", __func__};

    check_params(ex);

    buf_.resize(size());

    ntcp2::BytesWriter<decltype(buf_)> writer(buf_);

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
    namespace meta = ntcp2::meta::block;

    const ntcp2::exception::Exception ex{"RouterInfoBlock", __func__};

    ntcp2::BytesReader<decltype(buf_)> reader(buf_);

    reader.read_bytes(type_);
    reader.read_bytes(size_);
    reader.read_bytes(flag_);

    std::vector<std::uint8_t> ri_buf;
    ri_buf.resize(size_ - meta::FloodFlagSize);
    reader.read_data(ri_buf);
    own_info_ = std::make_unique<ntcp2::router::Info>(std::move(ri_buf));
    info_ = own_info_.get();

    check_params(ex);
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex)
  {
    namespace meta = ntcp2::meta::block;

    // check for valid block ID
    if (type_ != meta::RouterInfoID)
      ex.throw_ex<std::runtime_error>("invalid block ID.");

    // check if flag contains reserved flag bits
    if (flag_ & ~meta::FloodFlagMask)
      ex.throw_ex<std::runtime_error>("invalid flood request flag.");

    // check for a valid router info
    if (!info_)
      ex.throw_ex<std::runtime_error>("need a valid RouterInfo.");

    // check for valid total size
    if (size_ < meta::MinRIPayloadSize || size_ > meta::MaxRIPayloadSize
        || size_ != meta::FloodFlagSize + info_->size())
      ex.throw_ex<std::length_error>("invalid block size.");
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_BLOCKS_ROUTER_INFO_H_
