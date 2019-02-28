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

#ifndef SRC_NTCP2_ROUTER_META_H_
#define SRC_NTCP2_ROUTER_META_H_

#include "src/crypto/aes.h"
#include "src/crypto/ecies.h"
#include "src/crypto/eddsa.h"

#include "src/data/router/meta/address.h"
#include "src/data/router/meta/certificate.h"
#include "src/data/router/meta/identity.h"
#include "src/data/router/meta/info.h"
#include "src/data/router/meta/mapping.h"

namespace tini2p
{
namespace meta
{
namespace router
{
enum Sizes : std::uint16_t
{
  MaxTranportSize = 256,
  NTCPTransportSize = 4,
  NTCP2TransportSize = 5,
};
}  // namespace router
}  // namespace meta

namespace data
{
constexpr static const std::
    array<std::uint8_t, meta::router::NTCPTransportSize>
        ntcp_transport{{0x6e, 0x74, 0x63, 0x70}};

constexpr static const std::
    array<std::uint8_t, meta::router::NTCP2TransportSize>
        ntcp2_transport{{0x6e, 0x74, 0x63, 0x70, 0x32}};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_NTCP2_ROUTER_META_H_
