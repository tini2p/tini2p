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

#ifndef SRC_DATA_BLOCKS_PADDING_H_
#define SRC_DATA_BLOCKS_PADDING_H_

#include "src/exception/exception.h"

#include "src/crypto/rand.h"

#include "src/data/router/info.h"

#include "src/data/blocks/block.h"

namespace tini2p
{
namespace data
{
/// @brief Options NTCP2 block
class PaddingBlock : public Block
{
 public:
  using padding_t = crypto::SecBytes;  //< Padding trait alias

  enum
  {
    MaxPaddingLen = MaxLen - (HeaderLen + data::Info::MinLen),
  };

  PaddingBlock() : Block(type_t::Padding), padding_{}
  {
    serialize();
  }

  /// @brief Create a PaddingBlock from a length
  /// @param size Length of padding in the block
  explicit PaddingBlock(const std::uint16_t size) : Block(type_t::Padding, size)
  {
    padding_.resize(size);
    serialize();
  }

  /// @brief Create an PaddingBlock from an iterator range
  /// @param begin Begin of the iterator range
  /// @param end End of the iterator range
  template <class BegIt, class EndIt>
  PaddingBlock(const BegIt begin, const EndIt end)
      : Block(type_t::Padding)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Get a const refernce to the padding
  const padding_t& padding() const noexcept
  {
    return padding_;
  }

  /// @brief Get a non-const refernce to the padding
  padding_t& padding() noexcept
  {
    return padding_;
  }

  /// @brief Serialize options block to buffer
  void serialize()
  {
    size_ = padding_.size();

    check_params({"PaddingBlock", __func__});

    buf_.resize(size());
    crypto::RandBytes(padding_);

    tini2p::BytesWriter<buffer_t> writer(buf_);

    writer.write_bytes(type_);
    writer.write_bytes(size_);

    if (size_)
      writer.write_data(padding_);
  }

  /// @brief Deserialize options block to buffer
  void deserialize()
  {
    tini2p::BytesReader<buffer_t> reader(buf_);

    reader.read_bytes(type_);
    reader.read_bytes(size_);

    check_params({"PaddingBlock", __func__});

    if (size_)
      {
        padding_.resize(size_);
        reader.read_data(padding_);
      }
  }

 private:
  void check_params(const exception::Exception& ex)
  {
    // check padding ratios in range (only needed on serializing)
    if (type_ != type_t::Padding)
      ex.throw_ex<std::runtime_error>("invalid block type.");

    if (size_ > MaxPaddingLen)
      ex.throw_ex<std::length_error>("invalid block size.");
  }

  padding_t padding_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_PADDING_H_
