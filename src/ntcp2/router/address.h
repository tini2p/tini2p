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

#ifndef SRC_NTCP2_ROUTER_ADDRESS_H_
#define SRC_NTCP2_ROUTER_ADDRESS_H_

#include <boost/asio.hpp>

#include "src/ntcp2/router/meta.h"
#include "src/ntcp2/router/mapping.h"

namespace ntcp2
{
namespace router
{
struct Address
{
  std::uint8_t cost;
  std::uint64_t expiration;
  std::vector<std::uint8_t> transport;
  ntcp2::router::Mapping options;
  std::vector<std::uint8_t> buffer;

  Address()
      : cost(ntcp2::meta::router::address::DefaultCost),
        expiration(0),
        transport(
            ntcp2::router::ntcp2_transport.begin(),
            ntcp2::router::ntcp2_transport.end())
  {
    serialize();
  }

  /// @brief Create a router address from a host and port
  /// @param host Host for the router address
  /// @param port Port for the router address
  template <class Host>
  Address(const Host& host, const std::uint16_t port)
      : cost(ntcp2::meta::router::address::DefaultCost),
        expiration(0),
        transport(
            ntcp2::router::ntcp2_transport.begin(),
            ntcp2::router::ntcp2_transport.end())
  {
    namespace meta = ntcp2::meta::router::address;

    // set host and port options
    options.add(std::string("host"), host);
    options.add(std::string("port"), std::to_string(port));

    serialize();
  }

  decltype(auto) ToEndpoint() const
  {
    const exception::Exception ex{"Router: Info", __func__};

    const auto& host = options.entry(std::string("host"));
    if (host.empty())
      ex.throw_ex<std::length_error>("null host.");

    const auto& port_buf = options.entry(std::string("port"));
    if (port_buf.empty())
      ex.throw_ex<std::length_error>("null port.");

    return boost::asio::ip::tcp::endpoint(
        boost::asio::ip::make_address(std::string(host.begin(), host.end())),
        std::stoul(std::string(port_buf.begin(), port_buf.end())));
  }

  /// @brief Return the size of the mapping buffer
  std::size_t size() const noexcept
  {
    namespace meta = ntcp2::meta::router::address;

    return sizeof(cost) + meta::ExpirationSize + meta::TransportLenSize
           + transport.size() + options.size();
  }

  /// @brief Serialize the mapping to buffer
  void serialize()
  {
    namespace meta = ntcp2::meta::router::address;

    buffer.resize(size()); 

    ntcp2::BytesWriter<decltype(buffer)> writer(buffer);

    check_params(ntcp2::exception::Exception{"Router: Address", __func__});

    writer.write_bytes(cost);

    writer.write_bytes(expiration);

    writer.write_bytes<std::uint8_t>(transport.size());
    writer.write_data(transport);

    options.serialize();
    writer.write_data(options.buffer());
  }

  /// @brief Deserialize the mapping from buffer
  void deserialize()
  {
    namespace meta = ntcp2::meta::router::address;
    namespace map  = ntcp2::meta::router::mapping;

    const ntcp2::exception::Exception ex{"Router: Address", __func__};

    ntcp2::BytesReader<decltype(buffer)> reader(buffer);

    reader.read_bytes(cost);

    reader.read_bytes(expiration);

    std::uint8_t transport_size;
    reader.read_bytes(transport_size);

    transport.resize(transport_size);
    reader.read_data(transport);

    check_params(ex);

    // read options size
    std::uint16_t opt_size;
    ntcp2::read_bytes(buffer.begin() + reader.count(), opt_size);

    // read and deserialize options mapping
    auto& opt_buf = options.buffer();
    opt_buf.resize(map::SizeSize + opt_size);
    reader.read_data(opt_buf);
    options.deserialize();
  }

 private:
  void check_params(const ntcp2::exception::Exception& ex) const
  {
    using vec = std::vector<std::uint8_t>;
    using ntcp2::router::ntcp_transport;
    using ntcp2::router::ntcp2_transport;

    if (expiration)
      ex.throw_ex<std::runtime_error>("invalid expiration date.");

    if (transport != vec(ntcp_transport.begin(), ntcp_transport.end())
        && transport != vec(ntcp2_transport.begin(), ntcp2_transport.end()))
      ex.throw_ex<std::length_error>("invalid transport.");
  }
};
}  // namespace router
}  // namespace ntcp2

#endif  // SRC_NTCP2_ROUTER_ADDRESS_H_
