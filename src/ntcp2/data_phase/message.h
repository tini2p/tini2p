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
    MinSize = SizeLen,
    MaxSize = 65535 + MinSize
  };

  /// @brief Direction of communication
  enum struct Dir
  {
    AliceToBob,
    BobToAlice
  };

  using buffer_t = crypto::SecBytes;  //< Buffer trait alias
  using blocks_t = std::vector<data::Block::pointer>;  //< Blocks trait alias

  blocks_t blocks;
  buffer_t buffer;

  std::size_t size() const
  {
    std::size_t size(0);
    for (const auto& block : blocks)
      size += block->size();

    return size;
  }

  /// @brief Serialize message blocks to buffer
  void serialize()
  {
    namespace block_m = tini2p::meta::block;

    const exception::Exception ex{"DataPhase: Message", __func__};

    std::lock_guard<std::mutex> buf_mtx(buffer_mutex_);
    std::lock_guard<std::mutex> blk_mtx(blocks_mutex_);

    const auto total_size = size();

    if (total_size > MaxSize)
      ex.throw_ex<std::length_error>("invalid total message size.");

    if (buffer.size() < total_size)
      buffer.resize(total_size);

    tini2p::BytesWriter<buffer_t> writer(buffer);
    writer.skip_bytes(SizeLen);

    bool last_block(false), term_block(false);
    for (const auto& block : blocks)
      {
        if (last_block)
          ex.throw_ex<std::logic_error>("padding must be the last block.");

        if (term_block && block->type() != block_m::PaddingID)
          ex.throw_ex<std::logic_error>(
              "termination followed by non-padding block.");

        if (block->type() == block_m::PaddingID)
          last_block = true;

        if (block->type() == block_m::TerminationID)
          term_block = true;

        block->serialize();
        writer.write_data(block->buffer());
      }
  }

  /// @brief Deserialize blocks from buffer
  void deserialize()
  {
    namespace block_m = tini2p::meta::block;

    const exception::Exception ex{"DataPhase", __func__};

    std::lock_guard<std::mutex> buf_mtx(buffer_mutex_);
    tini2p::BytesReader<buffer_t> reader(buffer);
    reader.skip_bytes(block_m::SizeSize);

    bool last_block(false);
    blocks_t n_blocks;
    while (reader.gcount() > crypto::Poly1305::DigestLen)
      {
        std::uint8_t type;
        tini2p::read_bytes(&buffer[reader.count()], type);

        boost::endian::big_uint16_t size;
        tini2p::read_bytes(&buffer[reader.count() + block_m::SizeOffset], size);

        const auto b = buffer.begin() + reader.count();
        const auto e = b + block_m::HeaderSize + size;

        // final block(s) must be: padding or termination->padding
        //   disallows multiple padding blocks
        if (last_block && blocks.back()->type() != block_m::TerminationID)
          ex.throw_ex<std::logic_error>("invalid block ordering.");

        if (type == block_m::DateTimeID)
          {
            n_blocks.emplace_back(
                blocks_t::value_type(new data::DateTimeBlock(b, e)));
          }
        else if (type == block_m::I2NPMessageID)
          {
            n_blocks.emplace_back(
                blocks_t::value_type(new data::I2NPBlock(b, e)));
          }
        else if (type == block_m::OptionsID)
          {
            n_blocks.emplace_back(
                blocks_t::value_type(new data::OptionsBlock(b, e)));
          }
        else if (type == block_m::RouterInfoID)
          {
            n_blocks.emplace_back(
                blocks_t::value_type(new data::RouterInfoBlock(b, e)));
          }
        else if (type == block_m::PaddingID)
          {
            last_block = true;
            n_blocks.emplace_back(
                blocks_t::value_type(new data::PaddingBlock(b, e)));
          }
        else if (type == block_m::TerminationID)
          {
            last_block = true;
            n_blocks.emplace_back(
                blocks_t::value_type(new data::TerminationBlock(b, e)));
          }
        else
          ex.throw_ex<std::logic_error>("invalid block type.");

        reader.skip_bytes(e - b);
      }  // end-while

    std::lock_guard<std::mutex> blk_mtx(blocks_mutex_);
    blocks = std::move(n_blocks);
  }

 private:
  std::mutex blocks_mutex_;
  std::mutex buffer_mutex_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_DATA_PHASE_MESSAGE_H_
