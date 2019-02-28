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

#ifndef SRC_CRYPTO_SIGNATURE_H_
#define SRC_CRYPTO_SIGNATURE_H_

namespace tini2p
{
namespace crypto
{
/// @brief Base class for signatures
/// @detail Protected ctors to ensure derived instantiation
/// @tparam N Size of the signature
template <std::size_t N>
class Signature
{
 public:
  using buffer_t = FixedSecBytes<N>;  //< Buffer trait alias
  using const_pointer = typename buffer_t::const_pointer;
  using pointer = typename buffer_t::pointer;
  using const_iterator = typename buffer_t::const_iterator;
  using iterator = typename buffer_t::iterator;
  using size_type = typename buffer_t::size_type;

  Signature() : buf_() {}

  Signature(buffer_t buf) : buf_(std::forward<buffer_t>(buf)) {}

  Signature(const SecBytes& buf) : buf_(buf) {}

  Signature(std::initializer_list<std::uint8_t> list) : buf_(list) {}

  decltype(auto) data() const noexcept
  {
    return buf_.data();
  }

  decltype(auto) data() noexcept
  {
    return buf_.data();
  }

  decltype(auto) begin() const noexcept
  {
    return buf_.begin();
  }

  decltype(auto) begin() noexcept
  {
    return buf_.begin();
  }

  decltype(auto) end() const noexcept
  {
    return buf_.end();
  }

  decltype(auto) end() noexcept
  {
    return buf_.end();
  }

  decltype(auto) size() const noexcept
  {
    return buf_.size();
  }

 protected:
  buffer_t buf_;
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_SIGNATURE_H_
