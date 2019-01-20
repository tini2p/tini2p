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

#ifndef SRC_NTCP2_MESSAGE1_KDF_H_
#define SRC_NTCP2_MESSAGE1_KDF_H_

#include <noise/protocol/handshakestate.h>

#include "src/exception/exception.h"

namespace ntcp2
{
  /// @brief Manager class for NTCP2 message handling
  class Messenger
  {
    NoiseHandshakeState* hs_state_;

   public:
    Messenger()
    {
      const ntcp2::exception::Exception ex{"Message1KDF", __func__};

      const int err = noise_handshakestate_new_by_name(
          &state_, ntcp2::NTCP2Meta().noise_name_chr, role_.id());

      if (err)
        ex.throw_ex<std::runtime_error>("error creating handshake state", err);
    }

    ~Messenger()
    {
      noise_handshakestate_free(state_);
    }
  };
}  // namespace ntcp2
