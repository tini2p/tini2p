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

#ifndef SRC_NTCP2_BLOCKS_PADDING_H_
#define SRC_NTCP2_BLOCKS_PADDING_H_

#include "src/exception/exception.h"

#include "src/ntcp2/blocks/block.h"

namespace ntcp2
{
/// @brief Options NTCP2 block
class PaddingBlock : public Block
{
  std::vector<std::uint8_t> padding_;

 public:
  PaddingBlock() : Block(ntcp2::meta::block::PaddingID), padding_{}
  {
    serialize();
  }

  /// @brief Create a PaddingBlock from a length
  /// @param size Length of padding in the block
  explicit PaddingBlock(const std::uint16_t size)
      : Block(ntcp2::meta::block::PaddingID, size)
  {
    padding_.resize(size);
    serialize();
  }

  /// @brief Create an PaddingBlock from an iterator range
  /// @param begin Begin of the iterator range
  /// @param end End of the iterator range
  template <class BegIt, class EndIt>
  PaddingBlock(const BegIt begin, const EndIt end)
      : Block(meta::block::PaddingID)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  //~PaddingBlock()
  //{
  //  ntcp2::crypto::RandBytes(buf_);
  //  ntcp2::crypto::RandBytes(padding_);
  //}

  /// @brief Get a const refernce to the padding
  const decltype(padding_)& padding() const noexcept
  {
    return padding_;
  }

  /// @brief Serialize options block to buffer
  void serialize()
  {
    size_ = padding_.size();

    check_params(exception::Exception{"PaddingBlock", __func__});

    buf_.resize(size());
    crypto::RandBytes(padding_);

    ntcp2::BytesWriter<decltype(buf_)> writer(buf_);

    writer.write_bytes(type_);
    writer.write_bytes(size_);

    if (size_)
      writer.write_data(padding_);
  }

  /// @brief Deserialize options block to buffer
  void deserialize()
  {
    ntcp2::BytesReader<decltype(buf_)> reader(buf_);

    reader.read_bytes(type_);
    reader.read_bytes(size_);

    check_params(exception::Exception{"PaddingBlock", __func__});

    if (size_)
      {
        padding_.resize(size_);
        reader.read_data(padding_);
      }
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex)
  {
    // check padding ratios in range (only needed on serializing)
    if (type_ != meta::block::PaddingID)
      ex.throw_ex<std::runtime_error>("invalid block type.");

    if (size_ > meta::block::MaxPaddingSize)
      ex.throw_ex<std::length_error>("invalid block size.");
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_BLOCKS_PADDING_H_
