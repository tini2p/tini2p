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

#ifndef SRC_CRYPTO_NONCE_H_
#define SRC_CRYPTO_NONCE_H_

#include "src/bytes.h"
#include "src/crypto/sec_bytes.h"

namespace tini2p
{
namespace crypto
{
/// @class Nonce
/// @brief Counter-based, strictly increasing nonce
class Nonce
{
 public:
  enum
  {
    KeyLen = 32,
    NonceLen = 12,
  };

  using buffer_t = FixedSecBytes<NonceLen>;  //< Buffer trait alias
  using uint_t = std::uint16_t;  //< Uint trait alias

  Nonce() : buf_{}, n_(0) {}

  /// @brief Create a nonce from a given integer
  /// @brief n Nonce value to set
  explicit Nonce(uint_t n) : buf_{}, n_(std::forward<uint_t>(n))
  {
    tini2p::write_bytes(buf_.data(), n_);
  }

  /// @brief Create a nonce from a given buffer
  /// @brief n Nonce buffer containing value to set
  explicit Nonce(buffer_t buf) : buf_{std::forward<buffer_t>(buf)}, n_()
  {
    tini2p::read_bytes(buf_.data(), n_);
  }

  /// @brief Set a new nonce value
  /// @param n New nonce value to set
  /// @throw Logic error if new nonce is not greater than current nonce
  void operator()(const uint_t& n)
  {
    if (n <= n_)
      exception::Exception{"Nonce", __func__}.throw_ex<std::logic_error>(
          "nonce is strictly increasing.");

    n_ = n;
    tini2p::write_bytes(buf_.data(), n_);
  }

  /// @brief Pre-increment the nonce by one
  /// @return Nonce value after increment
  uint_t operator++()
  {
    tini2p::write_bytes(buf_.data(), ++n_);
    return n_;
  }

  /// @brief Post-increment the nonce by one
  /// @return Nonce value before increment
  uint_t operator++(int)
  {
    decltype(n_) tmp(n_);
    tini2p::write_bytes(buf_.data(), ++n_);
    return tmp;
  }

  /// @brief Get the nonce as an unsigned int
  explicit operator uint_t() const noexcept
  {
    return n_;
  }

  /// @brief Get the nonce as a buffer
  explicit operator const buffer_t&() const noexcept
  {
    return buf_;
  }

 private:
  buffer_t buf_;
  uint_t n_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_NONCE_H_
