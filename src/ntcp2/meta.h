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

#ifndef SRC_NTCP2_META_H_
#define SRC_NTCP2_META_H_

#include <chrono>
#include <cstdint>

namespace ntcp2
{
namespace meta
{
enum Sizes : std::uint8_t
{
  NameSize = 48,
};

enum Version : std::uint8_t
{
  Version = 2,
};

/// @brief A string-like NTCP2 protocol name
inline const char* name()
{
  return "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
}
}  // namespace meta
}  // namespace ntcp2

#endif  // SRC_NTCP2_META_H_