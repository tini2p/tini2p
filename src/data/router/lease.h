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

#ifndef SRC_DATA_ROUTER_LEASE_H_
#define SRC_DATA_ROUTER_LEASE_H_

#include <boost/endian/arithmetic.hpp>

#include "src/time.h"

#include "src/data/router/identity.h"

namespace tini2p
{
namespace data
{
/// @struct Lease
/// @detail Supports Lease2+ format
// TODO(tini2p): Do we need to be concerned about truncation of Lease1 expiration?
struct Lease
{
  enum
  {
    Len = 40,  //< gw(32) + id(4) + exp(4), see spec
    SizeLen = 1,
    MinTunnelID = 1,
    MaxTunnelID = 65534,
    Timeout = 600,  //< in secs, 10 min. see spec
  };

  using tunnel_gw_t = Identity::hash_t;  //< Tunnel gateway trait alias
  using tunnel_id_t = boost::endian::big_uint32_t;  //< Tunnel ID trait alias
  using expiration_t = boost::endian::big_uint32_t;  //< Tunnel expiration trait alias
  using buffer_t = crypto::FixedSecBytes<Len>;  //< Buffer trait alias

  tunnel_gw_t tunnel_gw;
  tunnel_id_t tunnel_id;
  expiration_t expiration;
  buffer_t buffer;

  /// @brief Create a default Lease with null tunnel gateway + ID
  Lease() : tunnel_gw(), tunnel_id(0), expiration(time::now_s() + Timeout) {}

  /// @brief Create a Lease for a given tunnel gateway + random ID
  /// @param gateway IdentHash of the tunnel gateway for this Lease
  explicit Lease(tunnel_gw_t&& gateway)
      : tunnel_gw(std::forward<tunnel_gw_t>(gateway)),
        tunnel_id(crypto::RandInRange(MinTunnelID, MaxTunnelID)),
        expiration(time::now_s() + Timeout)
  {
    serialize();
  }

  /// @brief Create a Lease for a given tunnel gateway + ID
  /// @param gateway IdentHash of the tunnel gateway for this Lease
  /// @param id Tunnel ID for this Lease
  Lease(tunnel_gw_t&& gateway, tunnel_id_t&& id)
      : tunnel_gw(std::forward<tunnel_gw_t>(gateway)),
        tunnel_id(std::forward<tunnel_id_t>(id)),
        expiration(time::now_s() + Timeout)
  {
    serialize();
  }

  Lease(const std::uint8_t* data, const std::size_t len)
  {
    tini2p::check_cbuf(data, len, Len, Len, {"Lease", __func__});
    std::copy_n(data, len, buffer.data());
    deserialize();
  }

  /// @brief Reset Lease expiration to expire after "timeout" (10 min.)
  void update_expiration()
  {
    expiration = time::now_s() + Timeout;
  }

  /// @brief Serialize Lease to buffer
  void serialize()
  {
    tini2p::BytesWriter<buffer_t> writer(buffer);
    writer.write_data(tunnel_gw);
    writer.write_bytes(tunnel_id);
    writer.write_bytes(expiration);
  }

  /// @brief Deserialize Lease from buffer
  void deserialize()
  {
    tini2p::BytesReader<buffer_t> reader(buffer);
    reader.read_data(tunnel_gw);
    reader.read_bytes(tunnel_id);
    reader.read_bytes(expiration);
  }
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_LEASE_H_
