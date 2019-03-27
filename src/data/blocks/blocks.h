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

#ifndef SRC_DATA_BLOCKS_BLOCKS_H_
#define SRC_DATA_BLOCKS_BLOCKS_H_

#include <boost/variant.hpp>

#include "src/bytes.h"

#include "src/data/blocks/date_time.h"
#include "src/data/blocks/i2np.h"
#include "src/data/blocks/info.h"
#include "src/data/blocks/options.h"
#include "src/data/blocks/padding.h"
#include "src/data/blocks/termination.h"

namespace tini2p
{
namespace data
{
class Blocks
{
 public:
  /// @alias confirm_variant_t
  /// @brief SessionConfirmed block variant trait alias
  using confirm_variant_t =
      boost::variant<InfoBlock, OptionsBlock, PaddingBlock>;

  /// @alias data_variant_t
  /// @brief DataPhase block variant trait alias
  using data_variant_t = boost::variant<
      DateTimeBlock,
      I2NPBlock,
      InfoBlock,
      OptionsBlock,
      PaddingBlock,
      TerminationBlock>;

  using confirm_blocks_t = std::vector<confirm_variant_t>;  //< SessionConfirmed blocks container trait alias
  using data_blocks_t = std::vector<data_variant_t>;  //< DataPhase blocks container trait alias

  /// @struct GetType
  /// @brief Visitor to get type of a block variant
  struct GetType : public boost::static_visitor<Block::Type>
  {
    template <
        class TBlock,
        typename = std::enable_if_t<
            std::is_same<TBlock, DateTimeBlock>::value
            || std::is_same<TBlock, I2NPBlock>::value
            || std::is_same<TBlock, InfoBlock>::value
            || std::is_same<TBlock, OptionsBlock>::value
            || std::is_same<TBlock, PaddingBlock>::value
            || std::is_same<TBlock, TerminationBlock>::value>>
    constexpr Block::Type operator()(const TBlock& block) const
    {
      return block.type();
    }
  };

  /// @struct GetSize
  /// @brief Visitor to get size of a block variant
  struct GetSize : public boost::static_visitor<std::size_t>
  {
    template <
        class TBlock,
        typename = std::enable_if_t<
            std::is_same<TBlock, DateTimeBlock>::value
            || std::is_same<TBlock, I2NPBlock>::value
            || std::is_same<TBlock, InfoBlock>::value
            || std::is_same<TBlock, OptionsBlock>::value
            || std::is_same<TBlock, PaddingBlock>::value
            || std::is_same<TBlock, TerminationBlock>::value>>
    constexpr std::size_t operator()(const TBlock& block) const
    {
      return block.size();
    }
  };

  /// @brief Visitor to get non-const reference block variant buffer
  struct GetBuffer : public boost::static_visitor<Block::buffer_t&>
  {
    template <
        class TBlock,
        typename = std::enable_if_t<
            std::is_same<TBlock, DateTimeBlock>::value
            || std::is_same<TBlock, I2NPBlock>::value
            || std::is_same<TBlock, InfoBlock>::value
            || std::is_same<TBlock, OptionsBlock>::value
            || std::is_same<TBlock, PaddingBlock>::value
            || std::is_same<TBlock, TerminationBlock>::value>>
    Block::buffer_t& operator()(TBlock& block)
    {
      return block.buffer();
    }
  };

  struct Serialize : public boost::static_visitor<void>
  {
    template <
        class TBlock,
        typename = std::enable_if_t<
            std::is_same<TBlock, DateTimeBlock>::value
            || std::is_same<TBlock, I2NPBlock>::value
            || std::is_same<TBlock, InfoBlock>::value
            || std::is_same<TBlock, OptionsBlock>::value
            || std::is_same<TBlock, PaddingBlock>::value
            || std::is_same<TBlock, TerminationBlock>::value>>
    void operator()(TBlock& block)
    {
      block.serialize();
    }
  };

  /// @struct Deserialize
  /// @brief Deserialize block from a buffer
  /// @detail Need to instantiate before using as a visitor (mutability)
  struct Deserialize : public boost::static_visitor<void>
  {
    template <
        class TBlock,
        typename = std::enable_if_t<
            std::is_same<TBlock, DateTimeBlock>::value
            || std::is_same<TBlock, I2NPBlock>::value
            || std::is_same<TBlock, InfoBlock>::value
            || std::is_same<TBlock, OptionsBlock>::value
            || std::is_same<TBlock, PaddingBlock>::value
            || std::is_same<TBlock, TerminationBlock>::value>>
    void operator()(TBlock& block)
    {
      block.deserialize();
    }
  };

  /// @brief Read and deserialize a block from a buffer reader
  /// @tparam TBlockVar Block variant type
  /// @param reader Buffer reader
  /// @param block Block variant for deserialization result
  /// @param ex Exception handler
  template <
      class TBlockVar,
      typename = std::enable_if_t<
          std::is_same<TBlockVar, confirm_variant_t>::value
          || std::is_same<TBlockVar, data_variant_t>::value>>
  static void ReadToBlock(
      BytesReader<Block::buffer_t>& reader,
      TBlockVar& block,
      const exception::Exception& ex)
  {
    GetBuffer get_buffer;
    Deserialize deserialize;

    Block::Type type;
    Block::size_type size;

    reader.read_bytes(type);
    reader.read_bytes(size);
    reader.skip_back(Block::HeaderLen);

    TypeToBlock(type, block, ex);

    auto& buf = boost::apply_visitor(get_buffer, block);
    buf.resize(Block::HeaderLen + size);
    reader.read_data(buf);

    if (size)
      boost::apply_visitor([](auto& b) { b.deserialize(); }, block);
  }

  /// @brief Serialize and write a block to a buffer writer
  /// @tparam TBlockVar Block variant type
  /// @param writer Buffer writer
  /// @param block Block variant to serialize
  /// @param ex Exception handler
  template <
      class TBlockVar,
      typename = std::enable_if_t<
          std::is_same<TBlockVar, confirm_variant_t>::value
          || std::is_same<TBlockVar, data_variant_t>::value>>
  static void WriteToBuffer(
      BytesWriter<Block::buffer_t>& writer,
      TBlockVar& block,
      const exception::Exception& ex)
  {
    GetBuffer get_buffer;
    Serialize serialize;

    boost::apply_visitor(serialize, block);
    auto& buf = boost::apply_visitor(get_buffer, block);
    writer.write_data(buf);
  }

  static void TypeToBlock(
      const Block::Type type,
      confirm_variant_t& block,
      const exception::Exception& ex)
  {
    if (type == Block::Type::Info)
      block = data::InfoBlock();
    else if (type == Block::Type::Options)
      block = data::OptionsBlock();
    else if (type == Block::Type::Padding)
      block = data::PaddingBlock();
    else
      ex.throw_ex<std::runtime_error>("invalid block type.");
  }

  static void TypeToBlock(
      const Block::Type type,
      data_variant_t& block,
      const exception::Exception& ex)
  {
    if (type == Block::Type::DateTime)
      block = std::move(data::DateTimeBlock());
    else if (type == Block::Type::I2NP)
      block = std::move(data::I2NPBlock());
    else if (type == Block::Type::Info)
      block = std::move(data::InfoBlock());
    else if (type == Block::Type::Options)
      block = std::move(data::OptionsBlock());
    else if (type == Block::Type::Padding)
      block = std::move(data::PaddingBlock());
    else if (type == Block::Type::Termination)
      block = std::move(data::TerminationBlock());
    else
      ex.throw_ex<std::runtime_error>("invalid block type.");
  }

  /// @struct TotalSize
  /// @brief Get total size of block variant container
  template <
      class TBlocks,
      typename = std::enable_if_t<
          std::is_same<TBlocks, confirm_blocks_t>::value
          || std::is_same<TBlocks, data_blocks_t>::value>>
  static constexpr std::size_t TotalSize(const TBlocks& blocks)
  {
    std::size_t size(0);
    for (const auto& block : blocks)
      size += boost::apply_visitor(GetSize(), block);

    return size;
  }

  /// @brief Check for correct block ordering
  ///
  /// @detail
  ///
  ///   SessionConfirmed ordering must be:
  ///
  ///     - InfoBlock (required)
  ///     - OptionsBlock (optional)
  ///     - PaddingBlock (optional, must be final block if present)
  ///
  ///   Multiple padding blocks are disallowed.
  ///
  ///   See I2P [spec](https://geti2p.net/spec/ntcp2#block-ordering-rules) for details.
  ///
  /// @param blocks Block variant container
  /// @param ex Exception handler
  static void CheckBlockOrder(
      const confirm_blocks_t& blocks,
      const exception::Exception& ex)
  {
    std::uint8_t block_pos(0);
    constexpr const std::uint8_t first = 0, second = 1, third = 2, max = 4;

    for (const auto& block : blocks)
      {
        const auto& type = boost::apply_visitor(GetType(), block);

        if (block_pos == first && type != Block::Type::Info)
          ex.throw_ex<std::logic_error>("RouterInfo must be the first block.");

        if (block_pos == second && type != Block::Type::Options
            && type != Block::Type::Padding)
          ex.throw_ex<std::logic_error>(
              "second block must be Options or Padding block.");

        if (block_pos == third && type != Block::Type::Padding)
          ex.throw_ex<std::logic_error>("last block must be Padding block.");

        if (block_pos == max)
          ex.throw_ex<std::logic_error>("max block count exceeded.");

        if (type == Block::Type::Info || type == Block::Type::Options)
          ++block_pos;
        else if (type == Block::Type::Padding)
          block_pos = max;
      }
  }

  /// @brief Check for correct block ordering
  ///
  /// @detail
  ///
  ///   DataPhase final block(s) must be:
  ///  
  ///     - PaddingBlock
  ///     - TerminationBlock -> PaddingBlock
  ///
  ///   Termination block must either be last, or followed only by a single padding block.
  ///
  ///   Multiple padding blocks are disallowed.
  ///
  ///   See I2P [spec](https://geti2p.net/spec/ntcp2#block-ordering-rules) for details.
  ///
  /// @param blocks Block variant container
  /// @param ex Exception handler
  static void CheckBlockOrder(
      const data_blocks_t& blocks,
      const exception::Exception& ex)
  {
    bool last_block(false), term_block(false);
    for (const auto& block : blocks)
      {
        const auto& type = boost::apply_visitor(GetType(), block);
        if (last_block)
          ex.throw_ex<std::logic_error>("padding must be the last block.");

        if (term_block && type != Block::Type::Padding)
          ex.throw_ex<std::logic_error>(
              "only padding block can follow termination block.");

        if (type == Block::Type::Termination)
          term_block = true;
        else if (type == Block::Type::Padding)
          last_block = true;
      }
  }

  /// @brief Add a block variant to a container
  /// @tparam TBlocks Block variant container type
  /// @param blocks Block variant container
  /// @param block Block to add
  /// @param ex Exception handler
  template <
      class TBlocks,
      typename = std::enable_if_t<
          std::is_same<TBlocks, confirm_blocks_t>::value
          || std::is_same<TBlocks, data_blocks_t>::value>>
  static void AddBlock(
      TBlocks& blocks,
      typename TBlocks::value_type block,
      const exception::Exception& ex)
  {
    blocks.emplace_back(std::forward<decltype(block)>(block));
    CheckBlockOrder(blocks, ex);
  }
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_BLOCKS_H_
