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

#ifndef SRC_EXCEPTION_EXCEPTION_H_
#define SRC_EXCEPTION_EXCEPTION_H_

#include <memory>
#include <string>

#include <noise/protocol/errors.h>

namespace ntcp2
{
namespace exception
{
/// @brief Auxillary struct for throwing exceptions
struct Exception
{
  /// @brief Throw an exception of type Ex
  /// @param message Exception message to throw
  /// @param err_n Error number (default none)
  template <class Ex>
  void throw_ex(const char* message, const int err_n = 0) const
  {
    std::string noise_err;
    if (err_n)
      {
        std::array<char, 30> err_msg;  // big enough to hold any error message
        noise_strerror(err_n, err_msg.data(), err_msg.size());
        noise_err.append(err_msg.begin(), err_msg.end());
      }

    throw Ex(
        class_t + ": " + func + ": " + std::string(message)
        + (noise_err.empty() ? "" : ": " + noise_err));
  }

  std::string class_t;
  std::string func;
};

}  // namespace exception
}  // namespace ntcp2

#endif  // SRC_EXCEPTION_EXCEPTION_H_
