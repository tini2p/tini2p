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

#ifndef SRC_NTCP2_SESSION_CONFIRMED_MESSAGE_H_
#define SRC_NTCP2_SESSION_CONFIRMED_MESSAGE_H_
namespace tini2p
{
namespace ntcp2
{
/// @brief Container for session created message
struct SessionConfirmedMessage
{
  using data_t = crypto::SecBytes;  //< Data trait alias
  using payload_t = crypto::SecBytes;  //< Payload trait alias
  using padding_t = crypto::SecBytes;  //< Padding trait alias
  using info_block_t = data::InfoBlock;  //< RouterInfo block trait alias
  using opt_block_t = data::OptionsBlock;  //< Options block trait alias
  using pad_block_t = data::PaddingBlock;  //< Padding block trait alias
  using curve_t = crypto::X25519;  //< Elliptic curve trait alias
  using mac_t = crypto::Poly1305; //< MAC trait alias

  enum : std::uint16_t
  {
    MinPayloadSize = data::Info::MinLen + mac_t::DigestLen,
    MaxPayloadSize = 65471,  // see spec
    MinPaddingSize = 32,
    MaxPaddingSize = MaxPayloadSize - MinPayloadSize,
    PartOneSize = curve_t::PublicKeyLen + mac_t::DigestLen,
    MinSize = PartOneSize + MinPayloadSize,
    MaxSize = PartOneSize + MaxPayloadSize,
  };

  data_t data;
  payload_t payload;
  info_block_t info_block;
  opt_block_t opt_block;
  pad_block_t pad_block;

  explicit SessionConfirmedMessage(const std::uint16_t size)
      : data(size), info_block(), opt_block(), pad_block()
  {
  }

  /// @brief Create a SessionConfirmedMessage from a RouterInfo
  /// @param info RouterInfo pointer to use in the message
  explicit SessionConfirmedMessage(tini2p::data::Info::shared_ptr info)
      : info_block(info),
        pad_block(crypto::RandInRange(MinPaddingSize, MaxPaddingSize))
  {
    serialize();
  }

  /// @brief Create a SessionConfirmedMessage from a RouterInfo (w/ padding)
  /// @param info RouterInfo pointer to use in the message
  /// @param pad_len Length of padding to include
  SessionConfirmedMessage(tini2p::data::Info::shared_ptr info, const std::uint16_t pad_len)
      : info_block(info), pad_block(pad_len)
  {
    serialize();
  }

  /// @brief Get the total SessionConfirmed message size
  std::uint16_t size() const
  {
    return PartOneSize + payload_size();
  }

  /// @brief Get the SessionConfirmed part two payload size
  std::uint16_t payload_size() const
  { 
    const auto& opt_size = opt_block.data_size();
    const auto& pad_size = pad_block.data_size();

    return info_block.size() + (opt_size ? opt_block.size() : opt_size)
           + (pad_size ? pad_block.size() : pad_size) + mac_t::DigestLen;
  }

  /// @brief Serialize the message + payload to buffer
  void serialize()
  {
    data.resize(size());
    payload.resize(payload_size());

    tini2p::BytesWriter<payload_t> writer(payload);

    // serialize and write RouterInfo block to payload buffer
    info_block.serialize();
    writer.write_data(info_block.buffer());

    if (opt_block.data_size())
      {  // serialize and write Options block to payload buffer
        opt_block.serialize();
        writer.write_data(opt_block.buffer());
      }

    if (pad_block.data_size())
      {  // serialize and write Padding block to payload buffer
        pad_block.serialize();
        writer.write_data(pad_block.buffer());
      }
  }

  /// @brief Deserialize the message + payload from buffer
  void deserialize()
  {
    const exception::Exception ex{"SessionConfirmedMessage", __func__};

    std::uint8_t block_count(0);
    constexpr const std::uint8_t first(0), second(1), third(2), max(3);

    tini2p::BytesReader<payload_t> reader(payload);

    // Read and deserialize a block from the buffer
    const auto read_deserialize = [&reader, this](tini2p::data::Block& block) {
      boost::endian::big_uint16_t block_size;
      tini2p::read_bytes(
          &payload[reader.count() + data::Block::SizeOffset], block_size);

      if (block_size)
        {
          block.buffer().resize(data::Block::HeaderLen + block_size);
          reader.read_data(block.buffer());
          block.deserialize();
        }
      else
        reader.skip_bytes(data::Block::HeaderLen);
    };

    // Process RouterInfo, Options and Padding blocks
    const auto process_blocks = [&block_count,
                                 &reader,
                                 this,
                                 read_deserialize,
                                 ex]() {
      data::Block::type_t block_type;
      tini2p::read_bytes(&payload[reader.count()], block_type);

      if (block_count == first && block_type != data::Block::type_t::Info)
        ex.throw_ex<std::logic_error>("RouterInfo must be the first block.");

      if (block_count == second && block_type != data::Block::type_t::Options
          && block_type != data::Block::type_t::Padding)
        ex.throw_ex<std::logic_error>(
            "second block must be Options or Padding block.");

      if (block_count == third && block_type != data::Block::type_t::Padding)
        ex.throw_ex<std::logic_error>("last block must be Padding block.");

      if (block_count == max)
        ex.throw_ex<std::logic_error>("Padding must be the final block.");

      if (block_type == data::Block::type_t::Info)
        {
          read_deserialize(info_block);
          ++block_count;
        }
      else if (block_type == data::Block::type_t::Options)
        {
          read_deserialize(opt_block);
          ++block_count;
        }
      else if (block_type == data::Block::type_t::Padding)
        {
          read_deserialize(pad_block);
          block_count = max;
        }
    };

    if (reader.gcount() <= mac_t::DigestLen)
      ex.throw_ex<std::logic_error>("payload must contain a RouterInfo block.");

    while (reader.gcount() >= data::Block::HeaderLen + mac_t::DigestLen)
      process_blocks();

    if (reader.gcount() > mac_t::DigestLen)
      ex.throw_ex<std::length_error>("invalid trailing bytes.");
  }
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_CONFIRMED_MESSAGE_H_
