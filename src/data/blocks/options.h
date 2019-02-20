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

#ifndef SRC_NTCP2_BLOCKS_OPTIONS_H_
#define SRC_NTCP2_BLOCKS_OPTIONS_H_

#include "src/exception/exception.h"
#include "src/time.h"

#include "src/data/blocks/block.h"

namespace tini2p
{
namespace data
{
/// @brief Options NTCP2 block
class OptionsBlock : public Block
{
 public:
  // avoid obnoxious getters/setters, leave these params public
  float tmin, tmax, rmin, rmax;
  boost::endian::big_uint16_t tdummy, tdelay, rdummy, rdelay;

  OptionsBlock()
      : Block(meta::block::OptionsID, meta::block::OptionsSize),
        tmin(0),
        tmax(0),
        rmin(0),
        rmax(0),
        tdummy(0),
        tdelay(0),
        rdummy(0),
        rdelay(0)
  {
    serialize();
  }

  /// @brief Create an OptionsBlock from an iterator range
  /// @param begin Begin of the iterator range
  /// @param end End of the iterator range
  template <class BegIt, class EndIt>
  OptionsBlock(const BegIt begin, const EndIt end)
      : Block(meta::block::OptionsID)
  {
    buf_.insert(buf_.begin(), begin, end);
    deserialize();
  }

  /// @brief Serialize options block to buf_
  void serialize()
  {
    const tini2p::exception::Exception ex{"OptionsBlock", __func__};

    check_params(ex);

    tini2p::BytesWriter<decltype(buf_)> writer(buf_);

    writer.write_bytes(type_);
    writer.write_bytes(size_);

    // annoying cast from float (thanks Java I2P)
    writer.write_bytes<std::uint8_t>(tmin * meta::block::CastRatio);
    writer.write_bytes<std::uint8_t>(tmax * meta::block::CastRatio);
    writer.write_bytes<std::uint8_t>(rmin * meta::block::CastRatio);
    writer.write_bytes<std::uint8_t>(rmax * meta::block::CastRatio);

    writer.write_bytes(tdummy);
    writer.write_bytes(rdummy);
    writer.write_bytes(tdelay);
    writer.write_bytes(rdelay);
  }

  /// @brief Deserialize options block to buf_
  void deserialize()
  {
    const tini2p::exception::Exception ex{"OptionsBlock", __func__};

    if (buf_.size() != meta::block::HeaderSize + meta::block::OptionsSize)
      ex.throw_ex<std::length_error>("invalid buf_ length.");

    tini2p::BytesReader<decltype(buf_)> reader(buf_);

    reader.read_bytes(type_);
    reader.read_bytes(size_);

    // annoying cast to float (thanks Java I2P)
    std::uint8_t tmp_tmin;
    reader.read_bytes(tmp_tmin);
    tmin = tmp_tmin / meta::block::CastRatio;

    std::uint8_t tmp_tmax;
    reader.read_bytes(tmp_tmax);
    tmax = tmp_tmax / meta::block::CastRatio;

    std::uint8_t tmp_rmin;
    reader.read_bytes(tmp_rmin);
    rmin = tmp_rmin / meta::block::CastRatio;

    std::uint8_t tmp_rmax;
    reader.read_bytes(tmp_rmax);
    rmax = tmp_rmax / meta::block::CastRatio;

    reader.read_bytes(tdummy);
    reader.read_bytes(rdummy);
    reader.read_bytes(tdelay);
    reader.read_bytes(rdelay);

    check_params(ex);
  }

 private:
  void check_params(const tini2p::exception::Exception& ex)
  {
    if (type_ != meta::block::OptionsID)
      ex.throw_ex<std::runtime_error>("invalid block type.");

    if (size_ != meta::block::OptionsSize)
      ex.throw_ex<std::length_error>("invalid block size.");

    // check padding ratios in range (only needed on serializing)
    const auto check_ratio = [ex](const float ratio) {
      if (ratio < meta::block::MinPaddingRatio
          || ratio > meta::block::MaxPaddingRatio)
        ex.throw_ex<std::length_error>("invalid padding ratio.");
    };

    check_ratio(tmin);
    check_ratio(tmax);
    check_ratio(rmin);
    check_ratio(rmax);
  }
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_NTCP2_BLOCKS_OPTIONS_H_
