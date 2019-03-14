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

#ifndef SRC_NTCP2_DATA_PHASE_MESSAGE_H_
#define SRC_NTCP2_DATA_PHASE_MESSAGE_H_

#include <mutex>

#include "src/crypto/sec_bytes.h"

#include "src/data/blocks/blocks.h"

namespace tini2p
{
namespace ntcp2
{
/// @class DataPhaseMessage
class DataPhaseMessage
{
 public:
  enum
  {
    SizeLen = 2,
    MinLen = SizeLen,
    MaxLen = 65535 + MinLen
  };

  /// @brief Direction of communication
  enum struct Dir
  {
    AliceToBob,
    BobToAlice
  };

  using buffer_t = crypto::SecBytes;  //< Buffer trait alias
  using blocks_t = data::Blocks::data_blocks_t;  //< Blocks trait alias

  constexpr std::size_t size() const
  {
    return data::Blocks::TotalSize(blocks_);
  }

  /// @brief Serialize message blocks to buffer
  void serialize()
  {
    const exception::Exception ex{"DataPhase: Message", __func__};

    std::lock_guard<std::mutex> buf_mtx(buffer_mutex_);
    std::lock_guard<std::mutex> blk_mtx(blocks_mutex_);

    const auto total_size = size();

    if (total_size > MaxLen)
      ex.throw_ex<std::length_error>("invalid total message size.");

    if (buffer_.size() < SizeLen + total_size)
      buffer_.resize(SizeLen + total_size);

    tini2p::BytesWriter<buffer_t> writer(buffer_);
    writer.skip_bytes(SizeLen);  // obfs len written elsewhere

    data::Blocks::CheckBlockOrder(blocks_, ex);

    for (auto& block : blocks_)
        data::Blocks::WriteToBuffer(writer, block, ex);
  }

  /// @brief Deserialize blocks from buffer
  void deserialize()
  {
    const exception::Exception ex{"DataPhase", __func__};

    std::lock_guard<std::mutex> buf_mtx(buffer_mutex_);

    tini2p::BytesReader<buffer_t> reader(buffer_);
    reader.skip_bytes(SizeLen);

    blocks_t n_blocks;
    while (reader.gcount() > crypto::Poly1305::DigestLen)
      {
          blocks_t::value_type block;
          data::Blocks::ReadToBlock(reader, block, ex);
          data::Blocks::AddBlock(n_blocks, std::move(block), ex);
      }  // end-while

    std::lock_guard<std::mutex> blk_mtx(blocks_mutex_);
    blocks_.swap(n_blocks);
  }

  template <class TBlock, 
            typename = std::enable_if_t<
                std::is_same<TBlock, data::DateTimeBlock>::value 
                || std::is_same<TBlock, data::I2NPBlock>::value
                || std::is_same<TBlock, data::InfoBlock>::value
                || std::is_same<TBlock, data::OptionsBlock>::value
                || std::is_same<TBlock, data::PaddingBlock>::value
                || std::is_same<TBlock, data::TerminationBlock>::value>>
  void add_block(TBlock block)
  {
    const exception::Exception ex{"DataPhase: Message", __func__};

    std::lock_guard<std::mutex> blkg(blocks_mutex_);

    if (data::Blocks::TotalSize(blocks_) + block.size() > MaxLen)
      ex.throw_ex<std::length_error>("invalid total message size.");

    data::Blocks::AddBlock(
        blocks_, 
        blocks_t::value_type(block),
        {"DataPhase: Message", __func__});
  }

  /// @brief Get the block at a given index
  /// @throw Invalid argument on out-of-range index
  blocks_t::value_type& get_block(const std::uint16_t index)
  {
    const exception::Exception ex{"DataPhase: Message", __func__};

    if (index > blocks_.size())
      ex.throw_ex<std::invalid_argument>("index out-of-range.");

    return blocks_[index];
  }

  /// @brief Get the first block of a given type
  /// @param type Type of block to search for
  /// @throw Invalid argument on out-of-range index
  blocks_t::value_type& get_block(const data::Block::type_t type)
  {
    const exception::Exception ex{"DataPhase: Message", __func__};

    std::lock_guard<std::mutex> blkg(blocks_mutex_);
    const auto it = std::find_if(
        blocks_.begin(),
        blocks_.end(),
        [type](const blocks_t::value_type& blk) {
          return boost::apply_visitor(data::Blocks::GetType(), blk) == type;
        });

    if (it == blocks_.end())
      ex.throw_ex<std::invalid_argument>("no block of search type", static_cast<int>(type));

    return *it;
  }

  void clear_blocks()
  {
    std::lock_guard<std::mutex> blkg(blocks_mutex_);
    blocks_.clear();
  }

  const buffer_t& buffer() const noexcept
  {
    return buffer_;
  }

  buffer_t& buffer() noexcept
  {
    return buffer_;
  }

  const blocks_t& blocks() const noexcept
  {
    return blocks_;
  }

 private:
  blocks_t blocks_;
  buffer_t buffer_;
  std::mutex blocks_mutex_;
  std::mutex buffer_mutex_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_DATA_PHASE_MESSAGE_H_
