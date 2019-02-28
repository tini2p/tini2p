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

#ifndef SRC_CRYPTO_SEC_BYTES_H_
#define SRC_CRYPTO_SEC_BYTES_H_

#include <initializer_list>

#include <sodium.h>

#include "src/exception/exception.h"

namespace tini2p
{
namespace crypto
{
template <class Buffer>
class SecBase
{
 protected:
  Buffer buf_;

  using buffer_t = decltype(buf_);

  SecBase() : buf_() {}

  explicit SecBase(const typename buffer_t::size_type size) : buf_(size) {}

  explicit SecBase(buffer_t buf) : buf_(std::forward<buffer_t>(buf)) {}

  SecBase(
      const typename buffer_t::size_type size,
      const typename buffer_t::value_type& val)
      : buf_(size, val)
  {
  }

  SecBase(
      typename buffer_t::const_iterator begin,
      typename buffer_t::const_iterator end)
      : buf_(begin, end)
  {
  }

  SecBase(
      typename buffer_t::const_pointer data,
      const typename buffer_t::size_type size)
      : buf_(data, size)
  {
  }

  explicit SecBase(
      std::initializer_list<typename buffer_t::value_type> init_list)
      : buf_(init_list)
  {
  }

 public:
  using pointer = typename buffer_t::pointer;  //< Non-const pointer trait alias
  using const_pointer = typename buffer_t::const_pointer;  //< Const pointer trait alias
  using iterator = typename buffer_t::iterator;  //< Non-const iterator trait alias
  using const_iterator = typename buffer_t::const_iterator;  //< Const iterator trait alias
  using size_type = typename buffer_t::size_type;  //< Size type trait alias

  ~SecBase()
  {
    if (buf_.data())
      sodium_memzero(buf_.data(), buf_.size());
  }

  /// @brief Get a non-const pointer to the beginning of the buffer
  pointer data() noexcept
  {
    return buf_.data();
  }

  /// @brief Get a const pointer to the beginning of the buffer
  const_pointer data() const noexcept
  {
    return buf_.data();
  }

  /// @brief Get a non-const iterator to the beginning of the buffer
  iterator begin() noexcept
  {
    return buf_.begin();
  }

  /// @brief Get a non-const iterator to the end of the buffer
  iterator end() noexcept
  {
    return buf_.end();
  }

  /// @brief Get a non-const iterator to the beginning of the buffer
  const_iterator begin() const noexcept
  {
    return buf_.begin();
  }

  /// @brief Get a non-const iterator to the end of the buffer
  const_iterator end() const noexcept
  {
    return buf_.end();
  }

  /// @brief Get a non-const iterator to the beginning of the buffer
  const_iterator cbegin() const noexcept
  {
    return buf_.begin();
  }

  /// @brief Get a non-const iterator to the end of the buffer
  const_iterator cend() const noexcept
  {
    return buf_.end();
  }

  /// @brief Get a non-const reference to the value at given buffer index
  /// @param idx Retrieve value at this index in the buffer
  decltype(auto) operator[](size_type idx)
  {
    if (idx > buf_.size())
      exception::Exception{"SecBytes", __func__}
          .throw_ex<std::invalid_argument>("out-of-bounds access.");

    return buf_[idx];
  }

  /// @brief Get a const reference to the value at given buffer index
  /// @param idx Retrieve value at this index in the buffer
  decltype(auto) operator[](size_type idx) const
  {
    if (idx > buf_.size())
      exception::Exception{"SecBytes", __func__}
          .throw_ex<std::invalid_argument>("out-of-bounds access.");

    return buf_[idx];
  }

  /// @brief Get a the buffer size
  size_type size() const noexcept
  {
    return buf_.size();
  }

  /// @brief Get empty status of the buffer
  bool empty() const noexcept { return buf_.empty(); }

  /// @brief Enable static_cast to the underlying buffer type
  explicit operator const buffer_t&() const
  {
    return buf_;
  }
};

/// @class SecBytes
/// @brief Secure-wiped memory buffer (variable size)
class SecBytes : public SecBase<std::vector<std::uint8_t>>
{
 public:
  using buffer_t = std::vector<std::uint8_t>;

  SecBytes() : SecBase<buffer_t>() {}

  /// @brief Create a secure buffer with a given size
  explicit SecBytes(const std::size_t size) : SecBase<buffer_t>(size) {}

  /// @brief Create a secure buffer from a buffer
  /// @param buf Input buffer
  explicit SecBytes(buffer_t buf)
      : SecBase<buffer_t>(std::forward<buffer_t>(buf))
  {
  }

  /// @brief Create a secure buffer from a buffer pointer and size
  /// @param data Pointer to the beginning of the input buffer
  /// @param size Size of the input buffer
  SecBytes(buffer_t::const_pointer data, const std::size_t size)
      : SecBase<buffer_t>(size)
  {
    std::copy_n(data, size, SecBase<buffer_t>::begin());
  }

  /// @brief Create a secure buffer filled with size number of a given value 
  /// @param size Number of values to copy to secure buffer
  /// @param val Value to fill the secured buffer
  SecBytes(const std::size_t size, const buffer_t::value_type& val)
      : SecBase<buffer_t>(size, val)
  {
  }

  /// @brief Create a secure buffer from an iterator range
  /// @param begin Beginning iterator for the input buffer
  /// @param end Ending iterator for the input buffer
  SecBytes(buffer_t::const_iterator begin, buffer_t::const_iterator end)
      : SecBase<buffer_t>(begin, end)
  {
  }

  /// @brief Create a secure buffer from an initializer list
  /// @param init_list Initializer list for the secure buffer
  explicit SecBytes(std::initializer_list<buffer_t::value_type> init_list)
      : SecBase<buffer_t>(init_list)
  {
  }

  /// @brief Resize the underlying buffer
  void resize(const std::size_t size) { SecBase<buffer_t>::buf_.resize(size); }

  /// @brief Insert iterator range into the buffer
  /// @param self_begin Begin inserting into the internal buffer at this iterator
  /// @param oth_begin Beginning of the iterator range to insert
  /// @param oth_end Ending of the iterator range to insert
  template <class InputIt>
  void insert(iterator self_begin, InputIt oth_begin, InputIt oth_end)
  {
    using s = SecBase<buffer_t>;

    const exception::Exception ex{"SecBytes", __func__};

    const auto begin_it = SecBase<buffer_t>::buf_.begin();
    const auto end_it = SecBase<buffer_t>::buf_.end();

    if (oth_begin >= begin_it && oth_begin <= end_it)
      ex.throw_ex<std::invalid_argument>("invalid beginning of range.");

    if (oth_end >= begin_it && oth_end <= end_it)
      ex.throw_ex<std::invalid_argument>("invalid ending of range.");

    if (oth_end < oth_begin)
      ex.throw_ex<std::invalid_argument>("invalid range.");

    if (self_begin < begin_it || self_begin > end_it)
      ex.throw_ex<std::invalid_argument>("invalid starting position.");

    SecBase<buffer_t>::buf_.insert(self_begin, oth_begin, oth_end);
  }
};

/// @alias FixedSecBytes
/// @brief Alias for secure-wiped memory buffer (fixed size)
/// @detail Used for refactor ease and readability
template <std::size_t N>
class FixedSecBytes : public SecBase<std::array<std::uint8_t, N>>
{
 public:
  using buffer_t = std::array<std::uint8_t, N>;

  FixedSecBytes() : SecBase<buffer_t>{} {}

  /// @brief Create a secure buffer from a buffer
  /// @param buf Input buffer
  explicit FixedSecBytes(buffer_t buf)
      : SecBase<buffer_t>(std::forward<buffer_t>(buf))
  {
  }

  /// @brief Create a secure buffer from a buffer pointer and size
  /// @param data Pointer to the beginning of the input buffer
  /// @param size Size of the input buffer
  FixedSecBytes(
      typename buffer_t::const_pointer data,
      typename buffer_t::size_type size)
      : SecBase<buffer_t>()
  {
    const exception::Exception ex{"FixedSecBytes"};

    if (!data || !size)
      ex.throw_ex<std::invalid_argument>("null input.");

    if (size > N)
      std::copy_n(data, N, SecBase<buffer_t>::buf_.data());
    else
      std::copy_n(data, size, SecBase<buffer_t>::buf_.data());
  }

  /// @brief Create a secure buffer from an iterator range
  /// @detail Copies up to N bytes from the iterator range
  /// @param begin Beginning of the iterator range
  /// @param end End of the iterator range
  FixedSecBytes(
      typename buffer_t::const_iterator begin,
      typename buffer_t::const_iterator end)
      : SecBase<buffer_t>()
  {
    if (end < begin)
      exception::Exception{"FixedSecBytes"}.throw_ex<std::invalid_argument>(
          "invalid iterator range.");

    if (end - begin > N) 
      std::copy(begin, begin + N, SecBase<buffer_t>::buf_.begin());
    else
      std::copy(begin, end, SecBase<buffer_t>::buf_.begin());
  }

  /// @brief Create a secure buffer from an initializer list
  /// @param init_list Initializer list for the secure buffer
  explicit FixedSecBytes(std::initializer_list<std::uint8_t> init_list)
      : SecBase<buffer_t>()
  {
    if (init_list.size() > N)
      exception::Exception{"FixedSecBytes"}.throw_ex<std::invalid_argument>(
          "invalid initializer list size.");

    std::copy(init_list.begin(), init_list.end(), SecBase<buffer_t>::begin());
  }

  /// @brief Create a fixed size secure buffer from a dynamic buffer
  /// @detail Copies up to N bytes from the dynamic buffer
  /// @param buf Dynamic sized secure buffer to copy from
  explicit FixedSecBytes(const SecBytes& buf)
  {
    const auto begin = buf.begin();
    const auto end = buf.end();

    if (end - begin > N) 
      std::copy(begin, begin + N, SecBase<buffer_t>::buf_.begin());
    else
      std::copy(begin, end, SecBase<buffer_t>::buf_.begin());
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_SEC_BYTES_H_
