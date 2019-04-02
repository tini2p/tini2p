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

#ifndef SRC_DATA_ROUTER_LEASE_SET_H_
#define SRC_DATA_ROUTER_LEASE_SET_H_

#include <mutex>

#include "src/crypto/sec_bytes.h"

#include "src/data/router/identity.h"
#include "src/data/router/mapping.h"

#include "src/data/router/key_section.h"
#include "src/data/router/lease.h"
#include "src/data/router/lease_set_header.h"

namespace tini2p
{
namespace data
{
/// @class LeaseSet
/// @brief LeaseSet2+ implementation
class LeaseSet
{
 public:
  using properties_t = Mapping;  //< Properties trait alias
  using key_section_t = KeySection;  //< Key section trait alias
  using lease_t = Lease;  //< Lease trait alias
  using header_t = LeaseSetHeader;  //< Header trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias

  enum : std::uint16_t
  {
    MinKeySections = 1,  //< because what's the point without one key?
    MaxKeySections = 5,  //< somewhat arbitrary, one for each key type
    MinLeases = 0,  //< see spec, limit total number of zero-lease LS in NetDb to prevent DDoS
    MaxLeases = 255,  //< bound by uint8_t_MAX, limit more?
    MinPropertiesLen = Mapping::MinLen,
    MaxPropertiesLen = Mapping::MaxLen,
    MinSigLen = 40,  // DSA signature
    MaxSigLen = 64,  // EdDSA signature(s)
    KeySectionNumLen = 1,
    LeaseNumLen = 1,
    MetaLen = KeySectionNumLen + LeaseNumLen,
    MinLen = MetaLen + MinPropertiesLen + (MinKeySections * KeySection::MinLen) + MinSigLen,
    MaxLen = MetaLen + MaxPropertiesLen + (MaxKeySections * KeySection::MaxLen) + (MaxLeases * Lease::Len) + MaxSigLen,
  };

  /// @brief LeaseSet default-ctor
  LeaseSet() : header_(), properties_(), leases_(), buf_(MinLen)
  {
    boost::apply_visitor(
        [this](const auto& c) { key_sections_.emplace_back(c.pubkey()); }, header_.destination()->crypto());

    serialize();
  }

  /// @brief Create a LeaseSet for a given destination
  /// @param dest Local Destination for this LeaseSet
  /// @param leases Container of Leases for this LeaseSet
  LeaseSet(std::unique_ptr<header_t::destination_t>&& dest, std::vector<lease_t> leases = {})
      : leases_(std::forward<std::vector<lease_t>>(leases))
  {
    const exception::Exception ex{"LeaseSet", __func__};

    if (!dest)
      ex.throw_ex<std::invalid_argument>("null destination.");

    boost::apply_visitor([this](const auto& c) { key_sections_.emplace_back(c.pubkey()); }, dest->crypto());
    header_ = std::move(dest);

    serialize();
  }

  /// @brief Create a LeaseSet from a buffer
  /// @param data Pointer to the buffer
  /// @param len Size of the buffer
  /// @throw Invalid argument for null and/or out-of-range buffer/length
  LeaseSet(const std::uint8_t* data, const std::size_t len)
  {
    const exception::Exception ex{"LeaseSet", __func__};

    tini2p::check_cbuf(data, len, MinLen, MaxLen, ex);

    buf_.resize(len);
    std::copy_n(data, len, buf_.data());

    deserialize();
  }

  /// @brief Serialize the LeaseSet to buffer
  void serialize()
  {
    const exception::Exception ex{"LeaseSet", __func__};

    buf_.resize(size());

    check_params(ex);

    tini2p::BytesWriter<buffer_t> writer(buf_);

    properties_.serialize();
    writer.write_data(properties_.buffer());

    write_key_sections(writer);
    write_leases(writer);

    if (header_.has_online_keys())
      {
        signature_ = header_.destination()->Sign(buf_.data(), writer.count());
        boost::apply_visitor([&writer](const auto& s) { writer.write_data(s); }, signature_);
      }
    else
      {
        blind_signature_ = header_.destination()->BlindSign(buf_.data(), writer.count());
        boost::apply_visitor([&writer](const auto& s) { writer.write_data(s); }, blind_signature_);
      }
  }

  /// @brief Derialize the LeaseSet from buffer
  void deserialize()
  {
    const exception::Exception ex{"LeaseSet", __func__};

    tini2p::BytesReader<buffer_t> reader(buf_);

    properties_ = std::move(properties_t(buf_.data(), buf_.size()));
    reader.skip_bytes(properties_.size());

    read_key_sections(reader);  // read n key sections
    read_leases(reader);  // read n leases

    if (header_.has_online_keys())
      boost::apply_visitor([&reader](auto& s) { reader.read_data(s); }, signature_);
    else
      boost::apply_visitor([&reader](auto& s) { reader.read_data(s); }, blind_signature_);

    check_params(ex);
  }

  /// @brief Verify the LeaseSet signature
  bool Verify() const
  {
    const auto* dest = header_.destination();
    return header_.has_online_keys()
               ? dest->Verify(buf_.data(), buf_.size() - dest->sig_len(), signature_)
               : dest->BlindVerify(buf_.data(), buf_.size() - dest->blind_sig_len(), blind_signature_);
  }

  /// @brief Get a const reference to the properties
  const properties_t& properties() const noexcept
  {
    return properties_;
  }

  /// @brief Get a non-const reference to the properties
  properties_t& properties() noexcept
  {
    return properties_;
  }

  /// @brief Get a const reference to the KeySections
  const std::vector<key_section_t>& key_sections() const noexcept
  {
    return key_sections_;
  }

  /// @brief Add a KeySection to the LeaseSet
  /// @param ks KeySection to add
  /// @throw Logic error on reaching max key sections limit
  void add_key_section(key_section_t ks)
  {
    const exception::Exception ex{"LeaseSet", __func__};

    if (key_sections_.size() == MaxKeySections)
      ex.throw_ex<std::logic_error>("max key sections reached: " + std::to_string(MaxKeySections));

    key_sections_.emplace_back(std::forward<key_section_t>(ks));
  }

  /// @brief Get a const reference to the Leases
  const std::vector<lease_t>& leases() const noexcept
  {
    return leases_;
  }

  /// @brief Add a Lease to the LeaseSet
  /// @param le Lease to add
  /// @throw Logic error on reaching max leases limit
  void add_lease(lease_t le)
  {
    const exception::Exception ex{"LeaseSet", __func__};

    if (leases_.size() == MaxLeases)
      ex.throw_ex<std::logic_error>("max leases reached: " + std::to_string(MaxLeases));

    leases_.emplace_back(std::forward<lease_t>(le));
  }

  std::uint16_t size() const noexcept
  {
    return properties_.size() + KeySectionNumLen + key_sections_len() + LeaseNumLen + leases_len()
           + (header_.has_online_keys() ? header_.destination()->sig_len() : header_.destination()->blind_sig_len());
  }

  std::uint16_t key_sections_len() const
  {
    std::uint16_t len(0);
    for (const auto& k : key_sections_)
      len += k.size();

    return len;
  }

  std::uint16_t leases_len() const
  {
    return leases_.size() * lease_t::Len;
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
    if (key_sections_.size() > MaxKeySections)
      ex.throw_ex<std::logic_error>("too many key sections: " + std::to_string(key_sections_.size()));
  }

  void write_key_sections(tini2p::BytesWriter<buffer_t>& writer)
  {
    std::lock_guard<std::mutex> kgd(ks_mutex_);
    writer.write_bytes(static_cast<std::uint8_t>(key_sections_.size()));
    for (auto& section : key_sections_)
      {
        section.serialize();
        writer.write_data(section.buffer);
      }
  }

  void write_leases(tini2p::BytesWriter<buffer_t>& writer)
  {
    std::lock_guard<std::mutex> lgd(ls_mutex_);
    writer.write_bytes(static_cast<std::uint8_t>(leases_.size()));
    for (auto& lease : leases_)
      {
        lease.serialize();
        writer.write_data(lease.buffer);
      }
  }

  void read_key_sections(tini2p::BytesReader<buffer_t>& reader)
  {
    const exception::Exception ex{"LeaseSet", __func__};

    std::uint8_t ks_n;
    reader.read_bytes(ks_n);  // read number of key sections

    if (ks_n < MinKeySections || ks_n > MaxKeySections)
      ex.throw_ex<std::length_error>("invalid number of key sections: " + std::to_string(ks_n));

    std::lock_guard<std::mutex> kgd(ks_mutex_);
    key_sections_.clear();
    key_sections_.reserve(ks_n);
    key_section_t::key_len_t k_len;
    
    for (std::uint16_t i = 0; i < ks_n; ++i)
      {
        reader.skip_bytes(key_section_t::TypeLen);
        reader.read_bytes(k_len);  // read key length
        reader.skip_back(key_section_t::HeaderLen);  // rewind reader to beginning of key section

        const auto& section_len = key_section_t::HeaderLen + k_len;
        if (k_len < key_section_t::MinKeyLen || k_len > key_section_t::MaxKeyLen)
          ex.throw_ex<std::length_error>(
              "invalid key length: " + std::to_string(k_len) + ", min: " + std::to_string(key_section_t::MinKeyLen)
              + "max: " + std::to_string(key_section_t::MaxKeyLen));

        if (section_len > reader.gcount())
          ex.throw_ex<std::length_error>(
              "invalid section length: " + std::to_string(section_len)
              + ", remaining: " + std::to_string(reader.gcount()));

        key_sections_.emplace_back(key_section_t(buf_.data() + reader.count(), section_len));  // deserialize in-place
        reader.skip_bytes(section_len);  // advance the reader
      }
  }

  void read_leases(tini2p::BytesReader<buffer_t>& reader)
  {
    const exception::Exception ex{"LeaseSet", __func__};

    std::uint8_t ls_n;
    reader.read_bytes(ls_n);  // read number of leases

    if (ls_n < MinLeases || ls_n > MaxLeases)
      ex.throw_ex<std::length_error>("invalid number of leases.");

    std::lock_guard<std::mutex> lgd(ls_mutex_);
    leases_.clear();
    leases_.reserve(ls_n);
    for (std::uint16_t i = 0; i < ls_n; ++i)
      {
        leases_.emplace_back(lease_t(buf_.data() + reader.count(), lease_t::Len));
        reader.skip_bytes(lease_t::Len);
      }
  }

  header_t header_;
  properties_t properties_;
  std::vector<key_section_t> key_sections_;
  std::mutex ks_mutex_;
  std::vector<lease_t> leases_;
  std::mutex ls_mutex_;
  header_t::destination_t::signature_v signature_;
  header_t::destination_t::blind_signature_v blind_signature_;
  buffer_t buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_LEASE_SET_H_
