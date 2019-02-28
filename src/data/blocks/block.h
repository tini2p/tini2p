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

#ifndef SRC_DATA_BLOCKS_BLOCK_H_
#define SRC_DATA_BLOCKS_BLOCK_H_

#include <boost/endian/arithmetic.hpp>

#include "src/bytes.h"
#include "src/crypto/sec_bytes.h"

#include "src/data/blocks/meta.h"

namespace tini2p 
{
namespace data
{
/// @brief Container for NTCP2 SessionConfirmed + DataPhase blocks
class Block
{
 public:
  using type_t = meta::block::Types;  //< Type trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias
  using size_type = boost::endian::big_uint16_t;  //< Size type trait alias
  using pointer = std::unique_ptr<Block>;  //< Pointer trait alias

  virtual ~Block() = default;

  /// @brief Get a const reference to the buffer
  const buffer_t& buffer() const noexcept
  {
    return buf_;
  }

  /// @brief Get a non-const reference to the buffer
  buffer_t& buffer() noexcept
  {
    return buf_;
  }

  /// @brief Get the block type
  type_t type() const noexcept
  {
    return type_;
  }

  /// @brief Get the block's total size
  std::uint16_t size() const noexcept
  {
    return meta::block::HeaderSize + size_;
  }

  /// @brief get the payload data size
  std::uint16_t data_size() const noexcept
  {
    return size_;
  }

  /// @brief Serialize block to buffer
  /// @detail Must be implemented by inheriting classes
  virtual void serialize() = 0;

  /// @brief Deserialize block from buffer
  /// @detail Must be implemented by inheriting classes
  virtual void deserialize() = 0;

 protected:
  /// @brief Create an empty Block of a given type
  /// @detail Intended to be called by inheriting classes
  Block(const type_t type)
      : type_(type), size_(0), buf_{}
  {
  }

  /// @brief Create a Block of a given type and size
  /// @param type Type of block to create
  /// @param size Size of the block payload
  /// @detail Intended to be called by inheriting classes
  Block(const type_t type, const std::uint16_t size)
      : type_(type), size_(size)
  {
    buf_.resize(meta::block::HeaderSize + size);
  }

  type_t type_;
  size_type size_;
  buffer_t buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_BLOCK_H_
