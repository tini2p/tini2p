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

#ifndef SRC_CRYPTO_KEYS_H_
#define SRC_CRYPTO_KEYS_H_

#include "src/crypto/sec_bytes.h"

namespace tini2p
{
namespace crypto
{
/// @brief Base class for keys
/// @tparam N Size of the key
template <std::size_t N>
class Key
{
 public:
  using buffer_t = FixedSecBytes<N>;  //< Buffer trait alias
  using const_pointer = typename buffer_t::const_pointer;
  using pointer = typename buffer_t::pointer;
  using const_iterator = typename buffer_t::const_iterator;
  using iterator = typename buffer_t::iterator;
  using size_type = typename buffer_t::size_type;

  Key() : buf_() {}

  Key(buffer_t buf) : buf_(std::forward<buffer_t>(buf)) {}

  Key(const SecBytes& buf) : buf_(buf) {}

  Key(std::initializer_list<std::uint8_t> list) : buf_(list) {}

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

  const buffer_t& buffer() const noexcept
  {
    return buf_;
  }

  buffer_t& buffer() noexcept
  {
    return buf_;
  }

  decltype(auto) operator[](size_type idx) const
  {
    return buf_[idx];
  }

  decltype(auto) operator[](size_type idx)
  {
    return buf_[idx];
  }

  bool operator==(const Key<N>& oth) const
  {
    return std::equal(buf_.begin(), buf_.end(), oth.buf_.begin());
  }

 protected:
  buffer_t buf_;
};

template <class CryptoImpl>
struct Keypair
{
  typename CryptoImpl::pubkey_t pubkey;
  typename CryptoImpl::pvtkey_t pvtkey;
};

template <class CryptoImpl>
struct KeyIV
{
  typename CryptoImpl::key_t key;
  typename CryptoImpl::iv_t iv;
};

template <class CryptoImpl>
struct KeyNonce
{
  typename CryptoImpl::key_t key;
  typename CryptoImpl::nonce_t nonce;
};

template <class PublicKeyImpl, class SharedKeyImpl>
struct DHKeys : public Keypair<PublicKeyImpl>, public KeyNonce<SharedKeyImpl>
{
  DHKeys() : Keypair<PublicKeyImpl>(), KeyNonce<SharedKeyImpl>() {}
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_KEYS_H_
