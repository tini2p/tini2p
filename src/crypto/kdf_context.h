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

#ifndef SRC_CRYPTO_KDF_CONTEXT_H_
#define SRC_CRYPTO_KDF_CONTEXT_H_

namespace tini2p
{
namespace crypto
{
/// @class KDFContext
/// @brief Class for HKDF hashing functions
template <class Hasher>
class KDFContext
{
  std::vector<std::uint8_t> ctx_;

 public:
  using string_t = std::string;
  using buffer_t = decltype(ctx_);

  KDFContext() : ctx_(Hasher::DefaultContextLen) {}

  explicit KDFContext(const string_t& info) : ctx_()
  {
    context(info);
  }

  /// @brief Create an KDF_CONTEXT context from an input buffer
  template <class T, std::size_t N>
  explicit KDFContext(const std::array<T, N>& info) : ctx_{}
  {
    context(info);
  }

  explicit KDFContext(const buffer_t& info) : ctx_{}
  {
    context(info);
  }

  /// @brief Set the KDF_CONTEXT context
  /// @param info String containing the KDF_CONTEXT context info
  /// @detail Only copy up to MaxLen bytes from input
  template <class Buffer>
  void context(const Buffer& info)
  {
    if (!ctx_.empty())
      ctx_.clear();

    if (info.size() <= Hasher::MaxContextLen)
      {
        ctx_.insert(ctx_.begin(), info.begin(), info.end());
        ctx_.resize(info.size());
      }
    else
      {
        const auto info_begin = info.begin();
        ctx_.insert(
            ctx_.begin(), info_begin, info_begin + Hasher::MaxContextLen);
      }
  }

  buffer_t::size_type size() const noexcept
  {
    return ctx_.size();
  }

  explicit operator string_t() const
  {
    return std::string(ctx_.begin(), ctx_.end());
  }

  explicit operator const buffer_t&() const noexcept
  {
    return ctx_;
  }
};
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_KDF_CONTEXT_H_
