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

#ifndef SRC_NTCP2_TIME_H_
#define SRC_NTCP2_TIME_H_

#include <chrono>

namespace tini2p
{
namespace meta
{
namespace time
{
enum Limits : std::uint32_t
{
  LagDelta = 120,
  MaxLagDelta = 3 * LagDelta,
};
}  // namespace time
}  // namespace meta

namespace time
{
/// @brief Get current time in seconds
inline std::uint32_t now_s()
{
  return std::chrono::steady_clock::now().time_since_epoch().count()
         * std::chrono::steady_clock::period::num
         / std::chrono::steady_clock::period::den;
}

/// @brief Get current time in milliseconds
inline std::uint64_t now_ms()
{
  return std::chrono::steady_clock::now().time_since_epoch().count();
}

/// @brief Check if timestamp delta (seconds) is within valid range
/// @param time Timestamp to check
inline bool check_lag_s(const std::uint32_t time)
{
  return now_s() - time <= meta::time::MaxLagDelta;
}
}  // namespace time
}  // namespace tini2p

#endif  // SRC_NTCP2_TIME_H_
