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
 * Derived in-part from original code by CodesInChaos, Thomas Pornin & libsodium
*/

#ifndef SRC_CRYPTO_BASE64_H_
#define SRC_CRYPTO_BASE64_H_

#include <boost/endian/arithmetic.hpp>

#include <sodium.h>

#include "src/bytes.h"
#include "src/exception/exception.h"

#include "src/crypto/sec_bytes.h"

namespace tini2p
{
namespace crypto
{
/// @struct CodecBase
/// @brief Base class for Base32/64 codec implementations
// TODO(tini2p): implement comparison operations with const-time helpers from libsodium
struct CodecBase
{
  /// @brief Check if two characters are equal
  /// @param ch Left-hand side char operand
  /// @param och Right-hand side char operand
  /// @return 0xff for true, 0x00 for false
  static constexpr std::uint8_t eq(const char ch, const char och)
  {
    return ch == och ? 0xff : 0x00;
  }

  /// @brief Check if lhs char is less-than-or-equal-to rhs char
  /// @param ch Left-hand side char operand
  /// @param och Right-hand side char operand
  /// @return 0xff for true, 0x00 for false
  static constexpr std::uint8_t le(const char ch, const char och)
  {
    return ch <= och ? 0xff : 0x00;
  }

  /// @brief Check if lhs char is less-than rhs char
  /// @param ch Left-hand side char operand
  /// @param och Right-hand side char operand
  /// @return 0xff for true, 0x00 for false
  static constexpr std::uint8_t lt(const char ch, const char och)
  {
    return ch < och ? 0xff : 0x00;
  }

  /// @brief Check if lhs char is greater-than-or-equal-to rhs char
  /// @param ch Left-hand side char operand
  /// @param och Right-hand side char operand
  /// @return 0xff for true, 0x00 for false
  static constexpr std::uint8_t ge(const char ch, const char och)
  {
    return ch >= och ? 0xff : 0x00;
  }

  /// @brief Check if lhs char is greater-than rhs char
  /// @param ch Left-hand side char operand
  /// @param och Right-hand side char operand
  /// @return 0xff for true, 0x00 for false
  static constexpr std::uint8_t gt(const char ch, const char och)
  {
    return ch > och ? 0xff : 0x00;
  }
};

/// @struct Base32Codec
/// @brief Base32 implementation according to [RFC 4648](https://tools.ietf.org/html/rfc4648)
struct Base32Codec : public CodecBase
{
  enum
  {
    ChunkLen = 40,
    BitsLen = 8,
    EncodedBits = 5,
    EncodeMask = 0x1f,
    DecodeMask = 0xff,
    WithPadding = 0,
  };

  /// @brief Encode masked integer to Base32 character
  static char to_char(const std::uint8_t x)
  {
    return (le(x, 25) & (x + 'a')) | (gt(x, 25) & (x + ('2' - 26)));
  }

  /// @brief Decode Base32 character to masked integer
  static std::uint8_t to_byte(const char c)
  {
    const unsigned int x = (ge(c, 'a') & le(c, 'z') & (c - ('a')))
                           | (ge(c, '2') & le(c, '7') & (c - ('2' - 26)));

    return x | (eq(x, 0) & (eq(c, 'a') ^ 0xff));
  }

  /// @brief Get the padding length of given input length
  static constexpr std::size_t pad_len(const std::size_t size)
  {
    const std::size_t rem = (size * BitsLen) % ChunkLen;
    return eq(rem, 8) ? 6 
      : eq(rem, 16) ? 4
      : eq(rem, 24) ? 3
      : eq(rem, 32) ? 1
      : 0;  // see RFC 4648
  }
};

/// @struct Base64Codec
/// @brief Base64 implementation according to [RFC 4648](https://tools.ietf.org/html/rfc4648) w/ custom I2P alphabet
struct Base64Codec : public CodecBase
{
  enum
  {
    ChunkLen = 24,
    BitsLen = 8,
    EncodedBits = 6,
    EncodeMask = 0x3f,
    DecodeMask = 0xff,
    WithPadding = 1,
  };

  /// @brief Encode masked integer to Base64 character
  static char to_char(const std::uint8_t x)
  {
    return (lt(x, 26) & (x + 'A')) | (ge(x, 26) & lt(x, 52) & (x + ('a' - 26)))
           | (ge(x, 52) & lt(x, 62) & (x + ('0' - 52))) | (eq(x, 62) & '-')
           | (eq(x, 63) & '~');
  }

  /// @brief Decode Base64 character to masked integer
  static std::uint8_t to_byte(const char c)
  {
    const unsigned int x = (ge(c, 'A') & le(c, 'Z') & (c - ('A')))
                           | (ge(c, 'a') & le(c, 'z') & (c - ('a' - 26)))
                           | (ge(c, '0') & le(c, '9') & (c - ('0' - 52)))
                           | (eq(c, '-') & 62) | (eq(c, '~') & 63);

    return x | (eq(x, 0) & (eq(c, 'A') ^ 0xff));
  }

  /// @brief Get the padding length of given input length
  static constexpr std::size_t pad_len(const std::size_t size)
  {
    const std::size_t rem = (size * BitsLen) % ChunkLen;
    return eq(rem, 8) ? 2 : eq(rem, 16) ? 1 : 0;  // see RFC 4648
  }
};

/// @class Codec
/// @brief Generic wrapper for Base32/64 codec implementations
/// @tparam TCodec Codec implementation type
template <
    class TCodec,
    typename = std::enable_if_t<
        std::is_same<TCodec, Base32Codec>::value
        || std::is_same<TCodec, Base64Codec>::value>>
class Codec
{
 public:
  using codec_t = TCodec;

  /// @brief Encode a bytes buffer
  /// @tparam TBuffer Buffer type
  /// @param in Buffer containing bytes to encode
  /// @return Encoded string
  template <class TBuffer>
  static std::string Encode(const TBuffer& in)
  {
    return Encode(reinterpret_cast<const std::uint8_t*>(in.data()), in.size());
  }

  /// @brief Encode a bytes buffer
  /// @param in_ptr Pointer to beginning of bytes buffer
  /// @param in_len Size of the bytes buffer
  /// @return Encoded string
  static std::string Encode(const std::uint8_t* in_ptr, const std::size_t in_len)
  {
    const exception::Exception ex{"Codec", __func__};

    std::string out;
    std::size_t n_pos(0);
    std::uint32_t acc(0);
    std::uint8_t acc_len(0);

    if (!in_ptr || !in_len)
      ex.throw_ex<std::invalid_argument>("null input.");

    while (n_pos < in_len)
      {  // add the next byte's bits to the accumlator
        acc = (acc << codec_t::BitsLen) + in_ptr[n_pos++];
        acc_len += codec_t::BitsLen;
        while (acc_len > codec_t::EncodedBits)
          {  // shift accumulator to next encoded bit group & mask the bits
            acc_len -= codec_t::EncodedBits;
            out.push_back(
                codec_t::to_char((acc >> acc_len) & codec_t::EncodeMask));
          }
      }

    // if remaining bytes, shift accumulator to last encoded bit group & mask the bits
    if (acc_len)
      out.push_back(codec_t::to_char(
          (acc << (codec_t::EncodedBits - acc_len)) & codec_t::EncodeMask));

    if (codec_t::WithPadding)
      {
        const auto& pad_bytes = codec_t::pad_len(in_len);
        for (std::uint8_t pad_pos = 0; pad_pos < pad_bytes; ++pad_pos)
          out.push_back('=');
      }

    return std::move(out);
  }

  /// @brief Decode an encoded string
  /// @tparam TBuffer Buffer type
  /// @param in Buffer containing encoded bytes
  /// @return Secure buffer of decoded bytes
  template <class TBuffer>
  static SecBytes Decode(const TBuffer& in)
  {
    return Decode(reinterpret_cast<const char*>(in.data()), in.size());
  }

  /// @brief Decode an encoded string
  /// @param in_ptr Pointer to beginning of string buffer
  /// @param in_len Size of the string buffer
  /// @return Secure buffer of decoded bytes
  static SecBytes Decode(const char* in_ptr, const std::size_t in_len)
  {
    const exception::Exception ex{"Codec", __func__};

    if (!in_ptr || !in_len)
      ex.throw_ex<std::invalid_argument>("null input.");

    SecBytes out(decoded_len(in_len));
    BytesWriter<SecBytes> writer(out);
    std::uint32_t acc(0);
    std::size_t b64_pos(0), acc_len(0);
    char c;
    while (b64_pos < in_len)
      {
        c = in_ptr[b64_pos++];

        if (c == '=')
          break;  // ignore padding, were done
        
        // convert char to decoded byte
        const auto& d = codec_t::to_byte(c);

        if (d == 0xff)
          ex.throw_ex<std::logic_error>("invalid byte.");

        // add decoded byte to the accumulator
        acc = (acc << codec_t::EncodedBits) + d;
        acc_len += codec_t::EncodedBits;
        if (acc_len >= codec_t::BitsLen)
          {  // shift accumulator to latest fully decoded byte & mask the bits
            acc_len -= codec_t::BitsLen;
            if (writer.gcount())
              writer.write_bytes<std::uint8_t>((acc >> acc_len) & codec_t::DecodeMask);
            else
              ex.throw_ex<std::length_error>("max length exceeded.");
          }
      }
    out.resize(writer.count());
    return std::move(out);
  }

  /// @brief Get the decoded length of given encoded length
  static constexpr std::size_t decoded_len(const std::size_t size)
  {
    return ((size * codec_t::EncodedBits)
            / static_cast<float>(codec_t::ChunkLen))
           * codec_t::EncodedBits;
  }
};

using Base32 = Codec<Base32Codec>;  //< Base32 convenience, usability alias
using Base64 = Codec<Base64Codec>;  //< Base64 convenience, usability alias
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_BASE64_H_
