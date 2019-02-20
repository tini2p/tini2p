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

#ifndef SRC_DATA_BLOCKS_TERMINATION_H_
#define SRC_DATA_BLOCKS_TERMINATION_H_

#include "src/exception/exception.h"

#include "src/crypto/rand.h"

#include "src/ntcp2/meta.h"
#include "src/time.h"

#include "src/data/blocks/block.h"

namespace tini2p
{
namespace data
{
class TerminationBlock : public Block
{
  meta::block::TerminationReason rsn_;
  boost::endian::big_uint64_t valid_frames_;
  std::vector<std::uint8_t> add_data_;

 public:
  TerminationBlock()
      : Block(meta::block::TerminationID, meta::block::MinTermSize),
        rsn_(meta::block::NormalClose),
        valid_frames_(0)
  {
    serialize();
  }

  /// @brief Convert a TERMINATIONBlock from an iterator range
  template <class BegIt, class EndIt>
  TerminationBlock(const BegIt begin, const EndIt end)
      : Block(meta::block::TerminationID, end - begin)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Set the TERMINATION message type
  /// @param type TERMINATION message type
  /// @throw Exception on invalid TERMINATION message type
  void reason(const decltype(rsn_) reason)
  {
    check_reason(reason, {"TerminationBlock", __func__});
    rsn_ = reason;
  }

  /// @brief Get const reference to the Termination reason 
  const decltype(rsn_)& reason() const noexcept
  {
    return rsn_;
  }

  /// @brief Get a const reference to Termination additional data
  const decltype(add_data_)& add_data() const noexcept
  {
    return add_data_;
  }

  /// @brief Get a non-const reference to Termination message data
  decltype(add_data_)& add_data() noexcept
  {
    return add_data_;
  }

  /// @brief Serialize Termination block to buffer
  void serialize()
  {
    size_ = meta::block::TermHeaderSize + add_data_.size();

    check_params({"TerminationBlock", __func__});

    buf_.resize(meta::block::HeaderSize + size_);

    tini2p::BytesWriter<decltype(buf_)> writer(buf_);
    writer.write_bytes(type_);
    writer.write_bytes(size_);
    writer.write_bytes(valid_frames_);
    writer.write_bytes(rsn_);
    if (add_data_.size())
      writer.write_data(add_data_);
  }

  /// @brief Deserialize TERMINATION block from buffer
  void deserialize()
  {
    tini2p::BytesReader<decltype(buf_)> reader(buf_);
    reader.read_bytes(type_);
    reader.read_bytes(size_);
    reader.read_bytes(valid_frames_);
    reader.read_bytes(rsn_);
    
    check_params({"TerminationBlock", __func__});

    if (reader.gcount())
      {
        add_data_.resize(reader.gcount());
        reader.read_data(add_data_);
      }
  }

 private:
  void check_reason(const decltype(rsn_) reason, const tini2p::exception::Exception& ex)
  {
    switch(reason)
    {
      case meta::block::NormalClose:
      case meta::block::TerminationRecvd:
      case meta::block::IdleTimeout:
      case meta::block::RouterShutdown:
      case meta::block::DataPhaseAEADFail:
      case meta::block::IncompatibleOpts:
      case meta::block::IncompatibleSig:
      case meta::block::ClockSkew:
      case meta::block::PaddingViolation:
      case meta::block::AEADFramingError:
      case meta::block::PayloadFormatError:
      case meta::block::SessionRequestError:
      case meta::block::SessionCreatedError:
      case meta::block::SessionConfirmedError:
      case meta::block::ReadTimeout:
      case meta::block::SigVerificationFail:
      case meta::block::InvalidS:
      case meta::block::Banned:
        return;
      default:
        ex.throw_ex<std::logic_error>("invalid termination reason.");
    }
  }

  void check_params(const tini2p::exception::Exception& ex)
  {
    if (type_ != meta::block::TerminationID)
      ex.throw_ex<std::logic_error>("invalid block type.");

    if (size_ < meta::block::MinTermSize || size_ > meta::block::MaxTermSize)
      ex.throw_ex<std::length_error>("invalid block size.");

    check_reason(rsn_, ex);
  }
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_TERMINATION_H_
