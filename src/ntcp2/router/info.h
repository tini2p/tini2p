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

#ifndef SRC_NTCP2_ROUTER_INFO_H_
#define SRC_NTCP2_ROUTER_INFO_H_

#include <boost/asio.hpp>

#include "src/crypto/meta.h"
#include "src/crypto/radix.h"

#include "src/ntcp2/time.h"

#include "src/ntcp2/router/address.h"
#include "src/ntcp2/router/identity.h"
#include "src/ntcp2/router/meta.h"
#include "src/ntcp2/router/mapping.h"

namespace ntcp2
{
namespace router
{
/// @class Info
/// @brief Class for parsing and storing an I2P RouterInfo
class Info
{
  std::unique_ptr<router::Identity> identity_;
  std::uint64_t date_;
  std::vector<router::Address> addresses_;
  std::mutex addresses_mutex_;
  router::Mapping options_;
  std::vector<std::uint8_t> transport_;
  crypto::ed25519::Signature signature_;
  const std::string v_{"2"};

  // Noise specific
  crypto::x25519::Keypair noise_keys_;
  crypto::aes::IV iv_;

  std::vector<std::uint8_t> buf_;

  void update_noise_key()
  {
    options_.add(
        std::string("s"),
        crypto::Base64::Encode(
            noise_keys_.pk.data(), noise_keys_.pk.size()));
  }

  void update_iv()
  {
    crypto::RandBytes(iv_.data(), iv_.size());
    options_.add(
        std::string("i"),
        crypto::Base64::Encode(iv_.data(), iv_.size()));
  }

 public:
  /// @brief Default RouterInfo ctor
  /// @detail Creates all new keys (identity + noise)
  Info()
      : identity_(new router::Identity()),
        addresses_(),
        options_(),
        transport_(
            router::ntcp2_transport.begin(),
            router::ntcp2_transport.end()),
        noise_keys_(crypto::x25519::create_keys())
  {
    crypto::RandBytes(iv_.data(), iv_.size());

    update_noise_key();
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
  Info(
      std::unique_ptr<ntcp2::router::Identity> ident,
      std::vector<router::Address>&& addrs,
      router::Mapping&& opts = ntcp2::router::Mapping())
      : identity_(std::move(ident)),
        date_(ntcp2::time::now_ms()),
        addresses_(std::forward<decltype(addresses_)>(addrs)),
        options_(std::forward<decltype(options_)>(opts)),
        transport_(
            router::ntcp2_transport.begin(),
            router::ntcp2_transport.end()),
        noise_keys_(crypto::x25519::create_keys())
  {
    namespace meta = ntcp2::meta::router::info;

    const auto total_size = size();
    if (total_size < meta::MinSize || total_size > meta::MaxSize)
      exception::Exception{"RouterInfo", __func__}.throw_ex<std::length_error>(
          "invalid size.");

    // update Noise options entries
    update_noise_key();
    update_iv();
    options_.add(std::string("v"), v_);

    serialize();
  }

  /// @brief Get a const reference to the Noise static keypair
  const decltype(noise_keys_)& noise_keys() const noexcept
  {
    return noise_keys_;
  }

  /// @brief Get a const pointer to the RouterIdentity
  const ntcp2::router::Identity& identity() const noexcept
  {
    return *identity_;
  }

  /// @brief Get a const reference to the creation date
  const decltype(date_)& date() const noexcept
  {
    return date_;
  }

  /// @brief Get a const reference to the RouterAddresses
  const decltype(addresses_)& addresses() const noexcept
  {
    return addresses_;
  }

  /// @brief Get a non-const reference to the RouterAddresses
  decltype(addresses_)& addresses() noexcept
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
    std::unique_lock<std::mutex> l(addresses_mutex_);

    if (addresses_.empty())
      exception::Exception{"Router: Info", __func__}.throw_ex<std::logic_error>(
          "empty router addresses.");

    for (const auto& address : addresses_)
      {
        auto ret = address.ToEndpoint();

        if ((ret.address().is_v6() && prefer_v6) || (ret.address().is_v4() && !prefer_v6))
          return ret;
      }

    return addresses_.front().ToEndpoint();
  }

  /// @brief Get a const reference to the options mapping
  const decltype(options_)& options() const noexcept
  {
    return options_;
  }

  /// @brief Get a non-const reference to the options mapping
  decltype(options_)& options() noexcept
  {
    return options_;
  }

  /// @brief Get a const reference to the transport style
  const decltype(transport_)& transport() const noexcept
  {
    return transport_;
  }

  /// @brief Get a non-const reference to the transport style
  decltype(transport_)& transport() noexcept
  {
    return transport_;
  }

  /// @brief Get a const reference to the RouterInfo signature
  const decltype(signature_)& signature() const noexcept
  {
    return signature_;
  }

  /// @brief Get a const reference to the Noise IV
  const decltype(iv_)& iv() const noexcept
  {
    return iv_;
  }

  /// @brief Get a const reference to the buffer
  const decltype(buf_)& buffer() const noexcept
  {
    return buf_;
  }

  /// @brief Get a non-const reference to the buffer
  decltype(buf_)& buffer() noexcept
  {
    return buf_;
  }

  /// @brief Get the total size of the RouterInfo
  std::size_t size() const
  {
    namespace meta = ntcp2::meta::router::info;

    std::size_t address_size = 0;
    for (const auto& address : addresses_)
      address_size += address.size();

    return identity_->size() + sizeof(date_) + meta::RouterAddressSizeSize
           + address_size + meta::PeerSizeSize + options_.size()
           + signature_.size();
  }

  /// @brief Serialize RouterInfo data members to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::router::info;

    buf_.resize(size());

    ntcp2::BytesWriter<decltype(buf_)> writer(buf_);

    identity_->serialize();
    writer.write_data(identity_->buffer());

    date_ = time::now_ms();
    writer.write_bytes(date_);
    writer.write_bytes<std::uint8_t>(addresses_.size());

    for (auto& address : addresses_)
      {
        address.serialize();
        writer.write_data(address.buffer);
      }

    // write zero peer-size, see spec
    writer.write_bytes<std::uint8_t>(0);

    options_.serialize();
    writer.write_data(options_.buffer());

    identity_->signing()->Sign(buf_.data(), writer.count(), signature_);
    writer.write_data(signature_);
  }

  /// @brief Deserialize RouterInfo data members from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::router::info;

    const ntcp2::exception::Exception ex{"RouterInfo", __func__};

    ntcp2::BytesReader<decltype(buf_)> reader(buf_);

    process_identity(reader);

    reader.read_bytes(date_);

    process_addresses(reader, ex);

    reader.skip_bytes(meta::PeerSizeSize);

    process_options(reader, ex);

    reader.read_data(signature_);

    identity_->signing()->Verify(
        buf_.data(), reader.count() - signature_.size(), signature_);
  }

 private:
  template <class Reader>
  void process_identity(Reader& reader)
  {
    if (!identity_)
      {
        identity_ = std::make_unique<ntcp2::router::Identity>(
            buf_.begin(), buf_.begin() + meta::router::identity::DefaultSize);
        reader.skip_bytes(identity_->size());
      }
    else
      {
        reader.read_data(identity_->buffer());
        identity_->deserialize();
      }
  }

  template <class Reader>
  void process_addresses(Reader& reader, const exception::Exception& ex)
  {
    std::uint8_t num_addresses;
    reader.read_bytes(num_addresses);
    addresses_.clear();

    for (std::uint8_t addr = 0; addr < num_addresses; ++addr)
      {
        ntcp2::router::Address address;

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

  template <class Reader>
  void process_options(Reader& reader, const exception::Exception& ex)
  {
    if (!reader.gcount())
      ex.throw_ex<std::logic_error>(
          "missing router options size, options, and signature.");

    // read options size before deserializing
    std::uint16_t opt_size;
    ntcp2::read_bytes(buf_.data() + reader.count(), opt_size);

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
};
}  // namespace router
}  // namespace ntcp2

#endif  // SRC_NTCP2_ROUTER_INFO_H_
