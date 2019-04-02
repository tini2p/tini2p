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

#ifndef SRC_DATA_ROUTER_LEASE_SET_HEADER_H_
#define SRC_DATA_ROUTER_LEASE_SET_HEADER_H_

#include <mutex>

#include "src/crypto/sec_bytes.h"

#include "src/data/router/identity.h"
#include "src/data/router/mapping.h"

#include "src/data/router/key_section.h"
#include "src/data/router/lease.h"

namespace tini2p
{
namespace data
{
/// @struct LeaseSetHeader
/// @detail LeaseSet2+ header data structure
class LeaseSetHeader
{
 public:
  enum struct Flag : std::uint16_t
  {
    OfflineKeys = 0x0000,  //< 0000000000000000, see spec
    OnlineKeys = 0x0001,   //< 0000000000000001, see spec
    Published = 0x0000,    //< 0000000000000000, see spec
    Unpublished = 0x0002,  //< 0000000000000010, see spec
    ReservedMask = 0xFFFC, //< 1111111111111100, see spec
  };

  enum : std::uint16_t
  {
    MinDestLen = Identity::MinSize,
    MaxDestLen = Identity::MaxSize,
    TimestampLen = 4,
    ExpiresLen = 2,
    FlagLen = 2,
    BlindExpiresLen = 4,
    BlindSigTypeLen = 2,
    MaxBlindPubKeyLen = 32,
    MaxSignatureLen = 64,
    MetaLen = TimestampLen + ExpiresLen + FlagLen,
    MinLen = MinDestLen + MetaLen,
    MaxLen = MaxDestLen + MetaLen + BlindExpiresLen + BlindSigTypeLen + MaxBlindPubKeyLen + MaxSignatureLen,
    Timeout = 600,  //< 10 min in seconds, see spec
  };

  using flag_t = Flag; //< Flag trait alias
  using destination_t = Identity;  //< Destination trait alias
  using timestamp_t = boost::endian::big_uint32_t;  //< Timestamp trait alias
  using expires_t = boost::endian::big_uint16_t;  //< Expires trait alias
  using blind_expires_t = boost::endian::big_uint32_t;  //< Blind expires trait alias
  using blind_sigtype_t = destination_t::cert_t::sign_type_t;  //< Blind signing type trait alias
  using signature_v = destination_t::signature_v;  //< Signature trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias

  /// @brief Default ctor, creates new Destination
  LeaseSetHeader() : dest_(new destination_t()), ts_(time::now_s()), expires_(Timeout), flags_(flag_t::OnlineKeys)
  {
    serialize();
  }

  /// @brief Create a LeaseSet for a given destination
  /// @param dest Local Destination for this LeaseSet
  LeaseSetHeader(std::unique_ptr<destination_t>&& dest)
      : dest_(std::move(dest)),
        ts_(time::now_s()),
        expires_(Timeout),
        flags_(flag_t::OnlineKeys)
  {
    serialize();
  }

  /// @brief Create a LeaseSetHeader from a given buffer
  /// @param buf Buffer containing a serialized LeaseSet
  explicit LeaseSetHeader(buffer_t buf) : buf_(std::forward<buffer_t>(buf))
  {
    deserialize();
  }

  /// @brief Serialize the LeaseSetHeader to buffer
  void serialize()
  {
    buf_.resize(size());

    check_params({"LeaseSet", __func__});

    tini2p::BytesWriter<buffer_t> writer(buf_);

    // type is set in NetDb messages

    dest_->serialize();
    writer.write_data(dest_->buffer());

    writer.write_bytes(ts_);
    writer.write_bytes(expires_);
    const auto& flags = tini2p::under_cast(flags_);
    writer.write_bytes(flags);

    if (has_offline_keys())
      {
        // write blinding data
        const auto expires_offset = writer.count();
        writer.write_bytes(blind_expires_);
        writer.write_bytes(blind_type_);
        boost::apply_visitor([&writer](const auto& k) { writer.write_data(k); }, blind_key_);

        // sign + write signature
        signature_ = dest_->Sign(buf_.data() + expires_offset, writer.count() - expires_offset);
        boost::apply_visitor([&writer](const auto& s) { writer.write_data(s); }, signature_);
      }
  }

  /// @brief Deserialize the LeaseSetHeader from buffer
  /// @detail Caller must set expected header type (e.g. LeaseSet2, EncLeaseSet2, etc.) before calling
  void deserialize()
  {
    const exception::Exception ex{"LeaseSet", __func__};

    if (buf_.size() > MaxLen)
      ex.throw_ex<std::length_error>("invalid LeaseSet size.");

    tini2p::BytesReader<buffer_t> reader(buf_);

    // type is determined from NetDb messages

    if (reader.gcount() < destination_t::MinSize)
        ex.throw_ex<std::length_error>("too small for a valid LeaseSet.");

    // read destination
    const auto dest_start = buf_.begin() + reader.count();
    dest_.reset(new destination_t(dest_start, dest_start + MaxDestLen));
    reader.skip_bytes(dest_->size());
    reader.read_bytes(ts_);  // read timestamp
    reader.read_bytes(expires_);  // read expires (past timestamp)

    // read flags
    std::underlying_type_t<flag_t> flags;
    reader.read_bytes(flags);
    flags_ = static_cast<flag_t>(flags);

    // if verifiable, read the signature
    if (!dest_->cert().locally_unreachable() && has_offline_keys())
      {
        reader.read_bytes(blind_expires_);
        reader.read_bytes(blind_type_);
        boost::apply_visitor([&reader](auto& k) { reader.read_data(k); }, blind_key_);
        dest_->init_signature(signature_);
        boost::apply_visitor([&reader](auto& s) { reader.read_data(s); }, signature_);
      }
  }

  /// @brief Verify the LeaseSet signature
  /// @return True if signature passes verification
  bool Verify() const
  {
    const auto expires_offset = buf_.size() - offline_size();

    return has_online_keys()
           || (!dest_->cert().locally_unreachable()
               && dest_->Verify(buf_.data() + expires_offset, expires_offset, signature_));
  }

  /// @brief Get a const pointer to the destination
  decltype(auto) destination() const noexcept
  {
    return dest_.get();
  }

  /// @brief Get a non-const pointer to the destination
  decltype(auto) destination() noexcept
  {
    return dest_.get();
  }

  /// @brief Get the total size of the LeaseSet
  std::uint16_t size() const
  {
    return dest_->size() + TimestampLen + ExpiresLen + FlagLen + offline_size();
  }

  /// @brief Get the size of offline signing data
  std::uint16_t offline_size() const
  {
    return has_online_keys() ? 0
                             : BlindExpiresLen + BlindSigTypeLen
                                   + boost::apply_visitor([](const auto& k) { return k.size(); }, blind_key_);
  }

  /// @brief Get a const reference to the creation time
  const timestamp_t& ts() const noexcept
  {
    return ts_;
  }

  /// @brief Get a const reference to the expiration time
  const expires_t& expires() const noexcept
  {
    return expires_;
  }

  /// @brief Get a const reference to the flag
  const flag_t& flags() const noexcept
  {
    return flags_;
  }

  /// @brief Check if the online keys flag is set
  bool has_online_keys() const
  {  // mask with the online keys flag, unsets all irrelevant bits
    const auto online_f = tini2p::under_cast(flag_t::OnlineKeys);
    return (tini2p::under_cast(flags_) & online_f) == online_f;
  }

  /// @brief Check if the online keys flag is unset
  bool has_offline_keys() const
  {
    return !has_online_keys();
  }

  /// @brief Check if the unpublished flag is unset
  bool is_published() const
  {
    return !is_unpublished();
  }

  /// @brief Check if the unpublished flag is set
  bool is_unpublished() const
  {  // mask with the unpublished flag, unsets all irrelevant bits
    const auto unpublished_f = tini2p::under_cast(flag_t::Unpublished);
    return (tini2p::under_cast(flags_) & unpublished_f) == unpublished_f;
  }

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

 private:
  void check_params(const exception::Exception& ex)
  {
    const auto& buf_size = buf_.size();
    const auto& tot_size = size();

    if (buf_size < MinLen || buf_size > MaxLen || tot_size < MinLen || tot_size > MaxLen)
      ex.throw_ex<std::length_error>(
          "invalid LeaseSet size - buf_len: " + std::to_string(buf_size) + " tot_len: " + std::to_string(tot_size));

    if (tini2p::under_cast(flags_) & tini2p::under_cast(flag_t::ReservedMask))
      ex.throw_ex<std::logic_error>("invalid LeaseSet flag.");

    if (time::now_s() - expires_ >= ts_)
      ex.throw_ex<std::logic_error>("expired LeaseSet.");
  }

  std::unique_ptr<destination_t> dest_;
  timestamp_t ts_;
  expires_t expires_;
  flag_t flags_;
  blind_expires_t blind_expires_;
  blind_sigtype_t blind_type_;
  destination_t::blind_pubkey_v blind_key_;
  destination_t::signature_v signature_;
  buffer_t buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_LEASE_SET_HEADER_H_
