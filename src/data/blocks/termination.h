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
 public:
  enum
  {
    TermHeaderLen = 9,
    MinTermLen = TermHeaderLen,
    MaxTermLen = MaxLen,
    MaxTermAddDataLen = MaxTermLen - TermHeaderLen,
  };

  enum struct Reason : std::uint8_t
  {
    NormalClose = 0,
    TerminationRecvd,
    IdleTimeout,
    RouterShutdown,
    DataPhaseAEADFail,
    IncompatibleOpts,
    IncompatibleSig,
    ClockSkew,
    PaddingViolation,
    AEADFramingError,
    PayloadFormatError,
    SessionRequestError,
    SessionCreatedError,
    SessionConfirmedError,
    ReadTimeout,
    SigVerificationFail,
    InvalidS,
    Banned
  };

  using reason_t = Reason;  //< Termination reason trait alias
  using frames_t = boost::endian::big_uint64_t;  //< Valid frames trait alias
  using ad_t = std::vector<std::uint8_t>;  //< Additional data trait alias

  TerminationBlock()
      : Block(type_t::Termination, MinTermLen),
        rsn_(reason_t::NormalClose),
        valid_frames_(0)
  {
    serialize();
  }

  /// @brief Convert a TERMINATIONBlock from an iterator range
  template <class BegIt, class EndIt>
  TerminationBlock(const BegIt begin, const EndIt end)
      : Block(type_t::Termination, end - begin)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Set the TERMINATION message type
  /// @param type TERMINATION message type
  /// @throw Exception on invalid TERMINATION message type
  void reason(const reason_t reason)
  {
    check_reason(reason, {"TerminationBlock", __func__});
    rsn_ = reason;
  }

  /// @brief Get const reference to the Termination reason 
  const reason_t& reason() const noexcept
  {
    return rsn_;
  }

  /// @brief Get a const reference to Termination additional data
  const ad_t& ad() const noexcept
  {
    return ad_;
  }

  /// @brief Get a non-const reference to Termination message data
  ad_t& ad() noexcept
  {
    return ad_;
  }

  /// @brief Serialize Termination block to buffer
  void serialize()
  {
    size_ = TermHeaderLen + ad_.size();

    check_params({"TerminationBlock", __func__});

    buf_.resize(HeaderLen + size_);

    tini2p::BytesWriter<buffer_t> writer(buf_);
    writer.write_bytes(type_);
    writer.write_bytes(size_);
    writer.write_bytes(valid_frames_);
    writer.write_bytes(rsn_);
    if (ad_.size())
      writer.write_data(ad_);
  }

  /// @brief Deserialize TERMINATION block from buffer
  void deserialize()
  {
    tini2p::BytesReader<buffer_t> reader(buf_);
    reader.read_bytes(type_);
    reader.read_bytes(size_);
    reader.read_bytes(valid_frames_);
    reader.read_bytes(rsn_);
    
    check_params({"TerminationBlock", __func__});

    if (reader.gcount())
      {
        ad_.resize(reader.gcount());
        reader.read_data(ad_);
      }
  }

 private:
  void check_reason(const reason_t reason, const exception::Exception& ex)
  {
    switch(reason)
    {
      case reason_t::NormalClose:
      case reason_t::TerminationRecvd:
      case reason_t::IdleTimeout:
      case reason_t::RouterShutdown:
      case reason_t::DataPhaseAEADFail:
      case reason_t::IncompatibleOpts:
      case reason_t::IncompatibleSig:
      case reason_t::ClockSkew:
      case reason_t::PaddingViolation:
      case reason_t::AEADFramingError:
      case reason_t::PayloadFormatError:
      case reason_t::SessionRequestError:
      case reason_t::SessionCreatedError:
      case reason_t::SessionConfirmedError:
      case reason_t::ReadTimeout:
      case reason_t::SigVerificationFail:
      case reason_t::InvalidS:
      case reason_t::Banned:
        return;
      default:
        ex.throw_ex<std::logic_error>("invalid termination reason.");
    }
  }

  void check_params(const exception::Exception& ex)
  {
    if (type_ != type_t::Termination)
      ex.throw_ex<std::logic_error>("invalid block type.");

    if (size_ < MinTermLen || size_ > MaxTermLen)
      ex.throw_ex<std::length_error>("invalid block size.");

    check_reason(rsn_, ex);
  }

  reason_t rsn_;
  frames_t valid_frames_;
  ad_t ad_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_BLOCKS_TERMINATION_H_
