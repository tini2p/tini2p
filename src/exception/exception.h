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

namespace tini2p
{
namespace exception
{
/// @brief Auxillary struct for throwing exceptions
struct Exception
{
  /// @brief Throw an exception of type Ex
  /// @param message Exception message (c-string)
  /// @param err_n Error number (default none)
  template <class Ex>
  void throw_ex(const char* message, const int err_n = 0) const
  {
    if (!message)
      throw_ex<std::invalid_argument>(
          std::string("null exception message."), err_n);

    throw_ex<Ex>(std::string(message), err_n);
  }

  /// @brief Throw an exception of type Ex
  /// @param message Exception message (string)
  /// @param err_n Error number (default none)
  template <class Ex>
  void throw_ex(const std::string& message, const int err_n = 0) const
  {
    std::vector<char> noise_err;
    if (err_n)
      {
        noise_err.resize(64);
        noise_strerror(err_n, noise_err.data(), noise_err.size());

        const auto err_end = noise_err.end();
        const auto null_it = std::find(noise_err.begin(), err_end, char());
        if (null_it != err_end)
          {
            noise_err.erase(null_it + 1, err_end);
            noise_err.shrink_to_fit();
          }
      }

    throw Ex(
        class_str + ": " + (func_str.empty() ? "" : func_str + ": ") + message
        + (noise_err.empty()
               ? ""
               : ": " + std::string(noise_err.begin(), noise_err.end())));
  }

  std::string class_str;
  std::string func_str;
};

}  // namespace exception
}  // namespace tini2p

#endif  // SRC_EXCEPTION_EXCEPTION_H_
