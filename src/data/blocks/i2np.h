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
 public:
  enum
  {
    MsgHeaderLen = 9,
    MinMsgLen = MsgHeaderLen,
    MaxMsgLen = Block::MaxLen - MsgHeaderLen,
    MinMsgID = 1,
    MaxMsgID = 4294967295,  // int_max<uint32>
  };

  enum struct MessageType : std::uint8_t
  {
    Reserved = 0,
    DatabaseStore,
    DatabaseLookup,
    DatabaseSearchReply,
    DeliveryStatus = 10,
    Garlic,
    TunnelData = 18,
    TunnelGateway,
    Data,
    TunnelBuild,
    TunnelBuildReply,
    VariableTunnelBuild,
    VariableTunnelBuildReply,
    FutureReserved = 255,
  };

  enum
  {
    I2NPTypeOffset = 3,
    MessageIDOffset = 4,
    ExpirationOffset = 8,
    MessageOffset = 12,
    DefaultI2NPExp = 120,  //< in seconds
  };

  using msg_id_t = boost::endian::big_uint32_t;  //< Message ID trait alias
  using msg_type_t = MessageType;  //< Message type trait alias
  using expiration_t = boost::endian::big_uint32_t;  //< Expiration trait alias
  using msg_buffer_t = crypto::SecBytes;  //< Message buffer trait alias

  I2NPBlock()
      : Block(type_t::I2NP, MinMsgLen),
        msg_type_(msg_type_t::Data),
        msg_id_(crypto::RandInRange(MinMsgID, MaxMsgID)),
        exp_(time::now_s() + DefaultI2NPExp)
  {
    serialize();
  }

  /// @brief Convert a I2NPBlock from an iterator range
  template <class BegIt, class EndIt>
  I2NPBlock(const BegIt begin, const EndIt end)
      : Block(type_t::I2NP, end - begin)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }
  /// @brief Serialize I2NP block to buffer
  void serialize()
  {
    const exception::Exception ex{"I2NPBlock", __func__};

    size_ = MsgHeaderLen + msg_buf_.size();

    check_params(ex);

    buf_.resize(HeaderLen + size_);

    tini2p::BytesWriter<buffer_t> writer(buf_);
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
    const exception::Exception ex{"I2NPBlock", __func__};
  
    tini2p::BytesReader<buffer_t> reader(buf_);
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

  /// @brief Set the I2NP message type
  /// @param type I2NP message type
  /// @throw Exception on invalid I2NP message type
  void msg_type(const msg_type_t type)
  {
    check_message_type(type, {"I2NPBlock", __func__});
    msg_type_ = type;
  }

  /// @brief Get const reference to the I2NP message ID
  const msg_id_t& msg_id() const noexcept
  {
    return msg_id_;
  }

  /// @brief Get const reference to the I2NP expiration
  const expiration_t& expiration() const noexcept
  {
    return exp_;
  }

  /// @brief Get a const reference to I2NP message data
  const msg_buffer_t& msg_data() const noexcept
  {
    return msg_buf_;
  }

  /// @brief Get a non-const reference to I2NP message data
  msg_buffer_t& msg_data() noexcept
  {
    return msg_buf_;
  }

  void resize_message(const std::size_t size)
  {
    const exception::Exception ex{"I2NPBlock", __func__};

    if (size > MaxMsgLen)
      ex.throw_ex<std::invalid_argument>("invalid message size");

    msg_buf_.resize(size);
    size_ = MsgHeaderLen + size;
  }

 private:
  void check_message_type(const msg_type_t type, const exception::Exception& ex)
  {
    switch(type)
    {
      case msg_type_t::DatabaseStore:
      case msg_type_t::DatabaseLookup:
      case msg_type_t::DatabaseSearchReply:
      case msg_type_t::DeliveryStatus:
      case msg_type_t::Garlic:
      case msg_type_t::TunnelData:
      case msg_type_t::TunnelGateway:
      case msg_type_t::Data:
      case msg_type_t::TunnelBuild:
      case msg_type_t::TunnelBuildReply:
      case msg_type_t::VariableTunnelBuild:
      case msg_type_t::VariableTunnelBuildReply:
        return;
      case msg_type_t::Reserved:
      case msg_type_t::FutureReserved:
      default:
        ex.throw_ex<std::logic_error>("invalid I2NP message type.");
    }
  }

  void check_params(const exception::Exception& ex)
  {
    if (type_ != type_t::I2NP)
      ex.throw_ex<std::logic_error>("invalid block type.");

    if (size_ < MinMsgLen || size_ > MaxMsgLen)
      ex.throw_ex<std::length_error>("invalid block size.");

    check_message_type(msg_type_, ex);

    if(time::now_s() >= exp_)
      ex.throw_ex<std::logic_error>("invalid expiration.");
  }

  msg_type_t msg_type_;
  msg_id_t msg_id_;
  expiration_t exp_;
  msg_buffer_t msg_buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_I2NP_H_
