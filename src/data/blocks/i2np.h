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

#ifndef SRC_DATA_BLOCKS_I2NP_H_
#define SRC_DATA_BLOCKS_I2NP_H_

#include "src/exception/exception.h"

#include "src/crypto/rand.h"

#include "src/ntcp2/meta.h"
#include "src/time.h"

#include "src/data/blocks/block.h"

namespace tini2p
{
namespace data
{
class I2NPBlock : public Block
{
  meta::block::I2NPMessageType msg_type_;
  boost::endian::big_uint32_t msg_id_;
  boost::endian::big_uint32_t exp_;
  std::vector<std::uint8_t> msg_buf_;

 public:
  I2NPBlock()
      : Block(meta::block::I2NPMessageID, meta::block::MinI2NPSize),
        msg_type_(meta::block::Data),
        exp_(time::now_s() + meta::block::DefaultI2NPExp)
  {
    tini2p::crypto::RandBytes(
        reinterpret_cast<std::uint8_t*>(&msg_id_), sizeof(msg_id_));
    serialize();
  }

  /// @brief Convert a I2NPBlock from an iterator range
  template <class BegIt, class EndIt>
  I2NPBlock(const BegIt begin, const EndIt end)
      : Block(meta::block::I2NPMessageID, end - begin)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Set the I2NP message type
  /// @param type I2NP message type
  /// @throw Exception on invalid I2NP message type
  void msg_type(const decltype(msg_type_) type)
  {
    check_message_type(type, {"I2NPBlock", __func__});
    msg_type_ = type;
  }

  /// @brief Get const reference to the I2NP message ID
  const decltype(msg_id_)& msg_id() const noexcept
  {
    return msg_id_;
  }

  /// @brief Get const reference to the I2NP expiration
  const decltype(exp_)& expiration() const noexcept
  {
    return exp_;
  }

  /// @brief Get a const reference to I2NP message data
  const decltype(msg_buf_)& msg_data() const noexcept
  {
    return msg_buf_;
  }

  /// @brief Get a non-const reference to I2NP message data
  decltype(msg_buf_)& msg_data() noexcept
  {
    return msg_buf_;
  }

  /// @brief Serialize I2NP block to buffer
  void serialize()
  {
    const tini2p::exception::Exception ex{"I2NPBlock", __func__};

    size_ = meta::block::I2NPHeaderSize + msg_buf_.size();

    check_params(ex);

    buf_.resize(meta::block::HeaderSize + size_);

    tini2p::BytesWriter<decltype(buf_)> writer(buf_);
    writer.write_bytes(type_);
    writer.write_bytes(size_);
    writer.write_bytes(msg_type_);
    writer.write_bytes(msg_id_);
    writer.write_bytes(exp_);
    if (msg_buf_.size())
      writer.write_data(msg_buf_);
  }

  /// @brief Deserialize I2NP block from buffer
  void deserialize()
  {
    const tini2p::exception::Exception ex{"I2NPBlock", __func__};
  
    tini2p::BytesReader<decltype(buf_)> reader(buf_);
    reader.read_bytes(type_);
    reader.read_bytes(size_);
    reader.read_bytes(msg_type_);
    reader.read_bytes(msg_id_);
    reader.read_bytes(exp_);
    check_params(ex);

    if (reader.gcount())
      {
        msg_buf_.resize(reader.gcount());
        reader.read_data(msg_buf_);
      }
  }

 private:
  void check_message_type(const decltype(msg_type_) type, const tini2p::exception::Exception& ex)
  {
    switch(type)
    {
      case meta::block::DatabaseStore:
      case meta::block::DatabaseLookup:
      case meta::block::DatabaseSearchReply:
      case meta::block::DeliveryStatus:
      case meta::block::Garlic:
      case meta::block::TunnelData:
      case meta::block::TunnelGateway:
      case meta::block::Data:
      case meta::block::TunnelBuild:
      case meta::block::TunnelBuildReply:
      case meta::block::VariableTunnelBuild:
      case meta::block::VariableTunnelBuildReply:
        return;
      case meta::block::Reserved:
      case meta::block::FutureReserved:
      default:
        ex.throw_ex<std::logic_error>("invalid I2NP message type.");
    }
  }

  void check_params(const tini2p::exception::Exception& ex)
  {
    if (type_ != meta::block::I2NPMessageID)
      ex.throw_ex<std::logic_error>("invalid block type.");

    if (size_ < meta::block::MinI2NPSize || size_ > meta::block::MaxI2NPSize)
      ex.throw_ex<std::length_error>("invalid block size.");

    check_message_type(msg_type_, ex);

    if(time::now_s() >= exp_)
      ex.throw_ex<std::logic_error>("invalid expiration.");
  }
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_I2NP_H_
