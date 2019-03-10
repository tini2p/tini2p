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

#ifndef SRC_DATA_ROUTER_INFO_H_
#define SRC_DATA_ROUTER_INFO_H_

#include <boost/asio.hpp>

#include "src/time.h"

#include "src/crypto/aes.h"
#include "src/crypto/keys.h"
#include "src/crypto/radix.h"
#include "src/crypto/signature.h"
#include "src/crypto/x25519.h"

#include "src/data/router/address.h"
#include "src/data/router/identity.h"
#include "src/data/router/meta.h"
#include "src/data/router/mapping.h"

namespace tini2p
{
namespace data
{
/// @class Info
/// @brief Class for parsing and storing an I2P RouterInfo
class Info
{
 public:
  using identity_t = Identity;  //< Identity trait alias
  using curve_t = identity_t::crypto_t::curve_t;  //< Elliptic curve trait alias
  using signature_t = identity_t::signing_t::signature_t;  //< Signature trait alias
  using date_t = std::uint64_t;  //< Date trait alias
  using addresses_t = std::vector<Address>;  //< Addresses trait alias
  using options_t = Mapping;  //< Options trait alias
  using transport_t = std::vector<std::uint8_t>;  //< Transport string trait alias
  using id_keys_t = curve_t::keypair_t;  //< Static identity keys trait alias
  using ep_keys_t = id_keys_t;  //< Ephemeral keys trait alias
  using iv_t = crypto::AES::iv_t;  //< IV trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias

  using pointer = Info*;  //< Non-owning pointer trait alias
  using unique_ptr = std::unique_ptr<Info>;  //< Unique pointer trait alias
  using shared_ptr = std::shared_ptr<Info>;  //< Shared pointer trait alias
  using const_shared_ptr = std::shared_ptr<const Info>;  //< Const shared pointer trait alias

  enum : std::uint16_t
  {
    DateLen = 8,
    PeerLen = 0,  // always zero, see spec
    MaxTransportLen = 256,
    NTCP2TransportLen = 6,
    // size of field lengths
    PeerSizeLen = 1,
    AddressSizeLen = 1,
    MinLen = 440,
    MaxLen = 65515,  // max block size - flag (1)
    DefaultLen = 440,
  };

  /// @brief Default RouterInfo ctor
  /// @detail Creates all new keys (identity + noise)
  Info()
      : identity_(),
        addresses_(),
        options_(),
        transport_(ntcp2_transport.begin(), ntcp2_transport.end()),
        id_keys_(curve_t::create_keys())
  {
    crypto::RandBytes(iv_);
    update_id_pubkey();
    update_iv();
    options_.add(std::string("v"), v_);

    serialize();
  }

  /// @brief Create RouterInfo from buffer 
  /// @param buf Buffer containing RouterIdentity bytes
  template <class Buffer>
  explicit Info(const Buffer& buf) : buf_(buf.begin(), buf.end())
  {
    deserialize();
  }

  /// @brief Create RouterInfo from identity, addresses, and options
  /// @param ident RouterIdentity (signs/verifies RouterInfo signature, encrypts/decrypts garlic)
  /// @param addrs RouterAddress(es) for contacting this RouterInfo
  /// @param opts Router mapping of RouterInfo options
  Info(identity_t ident, addresses_t addrs, options_t opts = options_t())
      : identity_(std::forward<identity_t>(ident)),
        date_(tini2p::time::now_ms()),
        addresses_(std::forward<addresses_t>(addrs)),
        options_(std::forward<options_t>(opts)),
        transport_(ntcp2_transport.begin(), ntcp2_transport.end()),
        id_keys_(curve_t::create_keys())
  {
    const exception::Exception ex{"RouterInfo", __func__};

    const auto total_size = size();

    if (total_size < MinLen || total_size > MaxLen)
      ex.throw_ex<std::length_error>("invalid size.");

    // update Noise options entries
    update_id_pubkey();
    update_iv();
    options_.add(std::string("v"), v_);

    serialize();
  }

  /// @brief Get a const reference to the Noise static identity keypair
  const id_keys_t& id_keys() const noexcept
  {
    return id_keys_;
  }

  /// @brief Get a const reference to the Noise ephemeral keypair
  const ep_keys_t& ephemeral_keys() const noexcept
  {
    return ep_keys_;
  }

  /// @brief Get a const reference to the RouterIdentity
  const identity_t& identity() const noexcept
  {
    return identity_;
  }

  /// @brief Get a non-const reference to the RouterIdentity
  identity_t& identity() noexcept
  {
    return identity_;
  }

  /// @brief Get a const reference to the creation date
  const date_t& date() const noexcept
  {
    return date_;
  }

  /// @brief Get a const reference to the RouterAddresses
  const addresses_t& addresses() const noexcept
  {
    return addresses_;
  }

  /// @brief Get a non-const reference to the RouterAddresses
  addresses_t& addresses() noexcept
  {
    return addresses_;
  }

  /// @brief Get a host IP and port from router addresses
  /// @param prefer_v6 Flag to prefer IPv6 addresses
  /// @return Endpoint object containing IP address and port
  /// @throw On empty addresses
  /// @throw On invalid IP address (non-IPv4/6)
  /// @throw On invalid port
  decltype(auto) host(const bool prefer_v6 = true)
  {
    const exception::Exception ex{"Router: Info", __func__};

    std::unique_lock<std::mutex> l(addresses_mutex_);

    if (addresses_.empty())
      ex.throw_ex<std::logic_error>("empty router addresses.");

    for (const auto& address : addresses_)
      {
        auto ret = address.ToEndpoint();

        if ((ret.address().is_v6() && prefer_v6) || (ret.address().is_v4() && !prefer_v6))
          return ret;
      }

    return addresses_.front().ToEndpoint();
  }

  /// @brief Get a const reference to the options mapping
  const options_t& options() const noexcept
  {
    return options_;
  }

  /// @brief Get a non-const reference to the options mapping
  options_t& options() noexcept
  {
    return options_;
  }

  /// @brief Get a const reference to the transport style
  const transport_t& transport() const noexcept
  {
    return transport_;
  }

  /// @brief Get a non-const reference to the transport style
  transport_t& transport() noexcept
  {
    return transport_;
  }

  /// @brief Get a const reference to the RouterInfo signature
  const signature_t& signature() const noexcept
  {
    return signature_;
  }

  /// @brief Get a const reference to the Noise IV
  const iv_t& iv() const noexcept
  {
    return iv_;
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

  /// @brief Get the total size of the RouterInfo
  std::size_t size() const
  {
    std::size_t address_size = 0;
    for (const auto& address : addresses_)
      address_size += address.size();

    return identity_.size() + sizeof(date_) + AddressSizeLen + address_size
           + PeerSizeLen + options_.size() + signature_.size();
  }

  /// @brief Serialize RouterInfo data members to buffer
  void serialize()
  {
    buf_.resize(size());

    tini2p::BytesWriter<buffer_t> writer(buf_);

    identity_.serialize();
    writer.write_data(identity_.buffer());

    date_ = tini2p::time::now_ms();
    writer.write_bytes(date_);
    writer.write_bytes<std::uint8_t>(addresses_.size());

    for (auto& address : addresses_)
      {
        address.serialize();
        writer.write_data(address.buffer);
      }

    // write zero peer-size, see spec
    writer.write_bytes(std::uint8_t(0));

    options_.serialize();
    writer.write_data(options_.buffer());

    identity_.signing().Sign(buf_.data(), writer.count(), signature_);
    writer.write_data(signature_);
  }

  /// @brief Deserialize RouterInfo data members from buffer
  void deserialize()
  {
    const tini2p::exception::Exception ex{"RouterInfo", __func__};

    tini2p::BytesReader<buffer_t> reader(buf_);

    process_identity(reader);
    reader.read_bytes(date_);

    process_addresses(reader, ex);
    reader.skip_bytes(PeerSizeLen);

    process_options(reader, ex);
    reader.read_data(signature_);

    identity_.signing().Verify(
        buf_.data(), reader.count() - signature_.size(), signature_);
  }

 private:
  void process_identity(tini2p::BytesReader<buffer_t>& reader)
  {
    auto& ident_buf = identity_.buffer();
    if (ident_buf.size() < Identity::DefaultSize)
      ident_buf.resize(Identity::DefaultSize);

    reader.read_data(ident_buf);
    identity_.deserialize();
  }

  template <class Reader>
  void process_addresses(Reader& reader, const exception::Exception& ex)
  {
    std::uint8_t num_addresses;
    reader.read_bytes(num_addresses);
    addresses_.clear();

    for (std::uint8_t addr = 0; addr < num_addresses; ++addr)
      {
        Address address;

        // copy remaining buffer, we don't know address size yet
        const auto addr_begin = buf_.begin() + reader.count();

        if (addr_begin == buf_.end())
          ex.throw_ex<std::logic_error>("addresses overflow the router info.");

        address.buffer.insert(address.buffer.begin(), addr_begin, buf_.end());

        address.deserialize();
        reader.skip_bytes(address.size());

        addresses_.emplace_back(std::move(address));
      }
  }

  void process_options(
      tini2p::BytesReader<buffer_t>& reader,
      const exception::Exception& ex)
  {
    if (!reader.gcount())
      ex.throw_ex<std::logic_error>(
          "missing router options size, options, and signature.");

    // read options size before deserializing
    std::uint16_t opt_size;
    tini2p::read_bytes(buf_.data() + reader.count(), opt_size);

    if (opt_size)
      {
        options_.buffer().resize(sizeof(opt_size) + opt_size);
        reader.read_data(options_.buffer());

        options_.deserialize();

        if (options_.entry(std::string("s")).empty())
          ex.throw_ex<std::logic_error>("null Noise static key.");

        const auto version = options_.entry(std::string("v"));
        if (version.empty() || version.front() != v_.front())
          ex.throw_ex<std::logic_error>("invalid NTCP2 version option.");
      }
    else
      reader.skip_bytes(sizeof(opt_size));
  }

  void update_id_pubkey()
  {
    options_.add(
        std::string("s"),
        crypto::Base64::Encode(id_keys_.pubkey.data(), id_keys_.pubkey.size()));
  }

  void update_iv()
  {
    crypto::RandBytes(iv_.data(), iv_.size());
    options_.add(
        std::string("i"), crypto::Base64::Encode(iv_.data(), iv_.size()));
  }

  identity_t identity_;
  date_t date_;
  addresses_t addresses_;
  std::mutex addresses_mutex_;
  options_t options_;
  transport_t transport_;
  signature_t signature_;
  const std::string v_{"2"};

  // Noise specific
  id_keys_t id_keys_;
  ep_keys_t ep_keys_;
  iv_t iv_;

  buffer_t buf_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_INFO_H_
