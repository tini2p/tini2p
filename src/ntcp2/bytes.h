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
 *
 * Parts used from the Kovri Project Copyright (c) 2013-2018.
 */

#ifndef SRC_NTCP2_BYTES_H_
#define SRC_NTCP2_BYTES_H_

#include "src/exception/exception.h"

namespace ntcp2
{
/// @brief Read byte(s) from an iterator to an integral/float
/// @param it Read byte(s) from this iterator 
/// @param bytes Read byte(s) to this value
/// @detail Bounds checking must be done by caller
template <class It, class Bytes>
inline void read_bytes(const It it, Bytes& bytes)
{
  if (it == It(nullptr))
    ntcp2::exception::Exception{"Bytes", __func__}
        .throw_ex<std::invalid_argument>("invalid iterator.");

  std::copy(it, it + sizeof(bytes), reinterpret_cast<std::uint8_t*>(&bytes));
}

/// @brief Write byte(s) to an iterator from an integral/float
/// @param it Write byte(s) to this iterator 
/// @param bytes Copy byte(s) from this value
/// @detail Bounds checking must be done by caller
template <class It, class Bytes>
inline void write_bytes(It it, const Bytes& bytes)
{
  if (it == It(nullptr))
    ntcp2::exception::Exception{"Bytes", __func__}
        .throw_ex<std::invalid_argument>("invalid iterator.");

  const auto* buf = reinterpret_cast<const std::uint8_t*>(&bytes);
  std::copy(buf, buf + sizeof(bytes), it);
}

/// @brief Utility class for reading/writing bytes
template <class Buffer>
class Bytes
{
  const bool const_;

 protected:
  typename Buffer::const_iterator cbegin_, cend_, cpos_;
  typename Buffer::iterator begin_, end_, pos_;

 public:
  /// @brief Create a Bytes reader from a buffer
  /// @param buf Buffer to read from
  explicit Bytes(const Buffer& buf)
      : const_(true), cbegin_(buf.begin()), cend_(buf.end()), cpos_(cbegin_)
  {
  }

  /// @brief Create a Bytes writer from a buffer
  /// @param buf Buffer to read from
  explicit Bytes(Buffer& buf) : const_(false), begin_(buf.begin()), end_(buf.end()), pos_(begin_)
  {
  }

  /// @brief Get a non-const iterator to the beginning of the buffer
  decltype(begin_) begin() noexcept
  {
    return begin_;
  }

  /// @brief Get a const iterator to the beginning of the buffer
  decltype(cbegin_) cbegin() const noexcept
  {
    return cbegin_;
  }

  /// @brief Get a non-const iterator to the end of the buffer
  decltype(end_) end() noexcept
  {
    return end_;
  }

  /// @brief Get a const iterator to the end of the buffer
  decltype(cend_) cend() const noexcept
  {
    return cend_;
  }

  /// @brief Get a non-const iterator to current position in the buffer
  decltype(pos_) pos() noexcept
  {
    return pos_;
  }

  /// @brief Get a const iterator to current position in the buffer
  decltype(cpos_) cpos() const noexcept
  {
    return cpos_;
  }

  /// @brief Get the amount of processed bytes
  std::size_t count() const
  {
    if (const_)
      return cpos_ - cbegin_;
    else
      return pos_ - begin_;
  }

  /// @brief Get the amount of remaining bytes in the buffer
  std::size_t gcount() const
  {
    if (const_)
      return cend_ - cpos_;
    else
      return end_ - pos_;
  }

  /// @brief Get the total amount of bytes in the buffer
  std::size_t size() const
  {
    if (const_)
      return cend_ - cbegin_;
    else
      return end_ - begin_;
  }

  /// @brief Skip past `size` bytes
  /// @param size Number of bytes to skip
  void skip_bytes(const std::size_t size)
  {
    advance(size, {"Bytes", __func__});
  }

  /// @brief Reset to beginning of the buffer
  void reset()
  {
    if (const_)
      cpos_ = cbegin_;
    else
      pos_ = begin_;
  }

 protected:
  void check_buf(const std::size_t& size, const ntcp2::exception::Exception& ex)
  {
    if ((const_ && cpos_ + size > cend_) || (!const_ && pos_ + size > end_))
      ex.throw_ex<std::runtime_error>("param overflows buffer.");
  }

  void advance(const std::size_t size, const ntcp2::exception::Exception& ex)
  {
    if (const_)
      {
        if (cpos_ + size > cend_)
          ex.throw_ex<std::length_error>("position overflows buffer.");

        cpos_ += size;
      }
    else
      {
        if (pos_ + size > end_)
          ex.throw_ex<std::length_error>("position overflows buffer.");

        pos_ += size;
      }
  }
};

/// @brief Stream-like class for reading bytes from a buffer
/// @details Removing const is necessary when the base type itself is const.
template <class Buffer>
class BytesReader : public Bytes<typename std::remove_const<Buffer>::type>
{
 public:
  BytesReader(const Buffer& buf)
      : Bytes<typename std::remove_const<Buffer>::type>(buf)
  {
  }

  /// @brief Read byte(s) from internal buffer to a buffer
  /// @param bytes Copy byte(s) to this buffer
  template <class Bytes>
  void read_data(Bytes& bytes)
  {
    const ntcp2::exception::Exception ex{"ReadBytes", __func__};

    const auto& size = bytes.size();

    this->check_buf(size, ex);
    std::copy(this->cpos_, this->cpos_ + size, bytes.begin());
    this->advance(size, ex);
  }

  /// @brief Read byte(s) from internal buffer to an integral/float
  /// @param bytes Copy byte(s) from this value
  template <class Bytes>
  void read_bytes(Bytes& bytes)
  {
    const ntcp2::exception::Exception ex{"ReadBytes", __func__};

    const std::size_t& size = sizeof(bytes);

    this->check_buf(size, ex);
    ntcp2::read_bytes(this->cpos_, bytes);
    this->advance(size, ex);
  }
};

template <class Buffer>
class BytesWriter : public Bytes<Buffer>
{
 public:
  BytesWriter(Buffer& buf) : Bytes<Buffer>(buf) {}

  /// @brief Write byte(s) to buffer from a buffer
  /// @param bytes Copy byte(s) from this value
  template <class Bytes>
  void write_data(const Bytes& bytes)
  {
    const ntcp2::exception::Exception ex{"WriteBytes", __func__};

    const auto& size = bytes.size();

    this->check_buf(size, ex);
    std::copy(bytes.begin(), bytes.end(), this->pos_);
    this->advance(size, ex);
  }

  /// @brief Write byte(s) to buffer from an integral/float
  /// @param bytes Copy byte(s) from this value
  template <class Bytes>
  void write_bytes(const Bytes& bytes)
  {
    const ntcp2::exception::Exception ex{"WriteBytes", __func__};

    const std::size_t& size = sizeof(bytes);

    this->check_buf(size, ex);
    ntcp2::write_bytes(this->pos_, bytes);
    this->advance(size, ex);
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_BYTES_H_
