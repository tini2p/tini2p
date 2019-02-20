/* copyright (c) 2018, tini2p
 * all rights reserved.
 *
 * redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * this software is provided by the copyright holders and contributors "as is"
 * and any express or implied warranties, including, but not limited to, the
 * implied warranties of merchantability and fitness for a particular purpose are
 * disclaimed. in no event shall the copyright holder or contributors be liable
 * for any direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute goods or
 * services; loss of use, data, or profits; or business interruption) however
 * caused and on any theory of liability, whether in contract, strict liability,
 * or tort (including negligence or otherwise) arising in any way out of the use
 * of this software, even if advised of the possibility of such damage.
*/

#include <catch2/catch.hpp>

#include "src/data/router/address.h"

namespace meta = tini2p::meta::router::address;

struct RouterAddressFixture
{
  RouterAddressFixture() : address(host, port) {}

  const std::string host{"13.37.4.2"};
  const std::uint16_t port{9111};
  tini2p::data::Address address;
};

TEST_CASE_METHOD(RouterAddressFixture, "RouterAddress has a cost", "[address]")
{
  REQUIRE(address.cost == meta::DefaultCost);
}

TEST_CASE_METHOD(RouterAddressFixture, "RouterAddress has a transport", "[address]")
{
  using Catch::Matchers::Equals;

  const std::string ntcp2_str("ntcp2");

  const std::string transport_str(
      address.transport.begin(), address.transport.end());

  REQUIRE_THAT(transport_str, Equals(ntcp2_str));
}

TEST_CASE_METHOD(RouterAddressFixture, "RouterAddress serializes a valid address", "[address]")
{
  REQUIRE_NOTHROW(address.serialize());
}

TEST_CASE_METHOD(RouterAddressFixture, "RouterAddress deserializes a valid address", "[address]")
{
  REQUIRE_NOTHROW(address.serialize());
  REQUIRE_NOTHROW(address.deserialize());
}

TEST_CASE_METHOD(
    RouterAddressFixture,
    "RouterAddress fails to serialize invalid expiration",
    "[address]")
{
  // any non-zero expiration is invalid
  ++address.expiration;

  REQUIRE_THROWS(address.serialize());
}

TEST_CASE_METHOD(
    RouterAddressFixture,
    "RouterAddress fails to serialize invalid transport",
    "[address]")
{
  // invalidate the transport length
  address.transport.push_back(0x2B);

  REQUIRE_THROWS(address.serialize());

  address.transport.pop_back();

  // invalidate the transport name
  ++address.transport.front();

  REQUIRE_THROWS(address.serialize());
}

TEST_CASE_METHOD(
    RouterAddressFixture,
    "RouterAddress fails to deserialize invalid expiration",
    "[address]")
{
  REQUIRE_NOTHROW(address.serialize());

  // any non-zero expiration is invalid
  ++address.buffer[meta::ExpirationOffset];

  REQUIRE_THROWS(address.deserialize());

}

TEST_CASE_METHOD(
    RouterAddressFixture,
    "RouterAddress fails to deserialize invalid transport",
    "[address]")
{
  REQUIRE_NOTHROW(address.serialize());

  // invalidate the transport length
  ++address.buffer[meta::TransportOffset];

  REQUIRE_THROWS(address.deserialize());

  --address.buffer[meta::TransportOffset];

  // invalidate the transport name
  ++address.buffer[meta::TransportOffset + 1];

  REQUIRE_THROWS(address.deserialize());
}
