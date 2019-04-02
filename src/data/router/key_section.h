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

#ifndef SRC_DATA_ROUTER_KEY_SECTION_H_
#define SRC_DATA_ROUTER_KEY_SECTION_H_

#include <boost/endian/arithmetic.hpp>

#include "src/crypto/sec_bytes.h"
#include "src/crypto/x25519.h"

#include "src/data/router/identity.h"

namespace tini2p
{
namespace data
{
/// @struct KeySection
struct KeySection
{
  /// @brief Key section public key type
  /// @detail Big-endian format for wire processing
  enum struct Type : std::uint16_t
  {
    ElGamal = 0x0000,
    P256 = 0x0100,
    P384 = 0x0200,
    P521 = 0x0300,
    X25519Hmac = 0x0400,
    X25519Blake = 0x0500,
    Unsupported = 0xFFFE,
    Reserved = 0xFFFF,
  };

  enum : std::uint16_t
  {
    TypeLen = 2,  //< uint16_be, see spec
    SizeLen = 2,  //< uint16_be, see spec
    MinKeyLen = 32,  //< all EdDSA/ECDSA variants
    MaxKeyLen = 256,  //< ElGamal
    HeaderLen = TypeLen + SizeLen,
    MinLen = HeaderLen + MinKeyLen,
    MaxLen = HeaderLen + MaxKeyLen,
  };

  using type_t = Type;  //< Type trait alias
  using key_len_t = boost::endian::big_uint16_t;  //< Size trait alias
  using key_v = Identity::crypto_pubkey_v;  //< Key variant trait alias
  using buffer_t = crypto::SecBytes;  //< Buffer trait alias

  type_t type;
  key_len_t key_len;
  key_v key;
  buffer_t buffer;

  /// @brief KeySection default ctor
  KeySection() : type(Type::X25519Blake), key_len(Identity::ecies_x25519_blake_t::PublicKeyLen), buffer(MinLen)
  {
    serialize();
  }

  /// @brief Create a KeySection for a given key buffer
  /// @param key_in Public key for this KeySection
  /// @detail Only X25519 keys currently supported
  template <class TKey, typename = std::enable_if_t<std::is_same<TKey, crypto::X25519::PublicKey>::value>>
  explicit KeySection(const TKey& key_in) : type(to_key_type<TKey>()), key_len(key_in.size()), key(key_in)
  {
    serialize();
  }

  /// @brief Create a KeySection from a buffer
  KeySection(const std::uint8_t* data, const std::size_t len) : buffer()
  {
    const exception::Exception ex{"KeySection", __func__};

    tini2p::check_cbuf(data, len, MinLen, MaxLen, ex);

    buffer.resize(len);
    std::copy_n(data, len, buffer.data());

    deserialize();
  }

  std::uint16_t size() const noexcept
  {
    return TypeLen + SizeLen + key_len;
  }

  /// @brief Serialize KeySection to buffer
  void serialize()
  {
    key_len = boost::apply_visitor([](const auto& k) { return k.size(); }, key);
    buffer.resize(size());
    check_params({"KeySection", __func__});

    tini2p::BytesWriter<buffer_t> writer(buffer);
    writer.write_bytes(type);
    writer.write_bytes(key_len);
    boost::apply_visitor([&writer](const auto& k) { writer.write_data(k); }, key);
  }

  /// @brief Deserialize KeySection from buffer
  void deserialize()
  {
    tini2p::BytesReader<buffer_t> reader(buffer);
    reader.read_bytes(type);
    reader.read_bytes(key_len);

    check_params({"KeySection", __func__});

    init_key();

    if (!locally_unreachable_)
      boost::apply_visitor([&reader](auto& k) { reader.read_data(k); }, key);
    else
      reader.skip_bytes(key_len);

    buffer.resize(reader.count());
  }

  /// @brief Convert an encryption public key type to its key section type
  template <class TKey>
  decltype(auto) to_key_type() const
  {
    return std::is_same<TKey, Identity::ecies_x25519_hmac_t>::value
               ? Type::X25519Hmac
               : std::is_same<TKey, Identity::ecies_x25519_blake_t>::value ? Type::X25519Blake : Type::Unsupported;
  }

  bool locally_unreachable() const noexcept
  {
    return locally_unreachable_;
  }

 private:
  void init_key()
  {
    if (type == type_t::X25519Hmac)
      key = Identity::ecies_x25519_hmac_t::pubkey_t();
    else if (type == type_t::X25519Blake)
      key = Identity::ecies_x25519_blake_t::pubkey_t();
    else
      {
        std::cerr << "KeySection: " << __func__ << ": unsupported encryption type." << std::endl;
        locally_unreachable_ = true;
      }
  }

  void check_params(const exception::Exception& ex)
  {
    const auto& buf_len = buffer.size();
    if (buf_len < MinLen || buf_len > MaxLen)
      ex.throw_ex<std::length_error>("invalid buffer length.");

    if (type != Type::X25519Hmac && type != Type::X25519Blake)
      locally_unreachable_ = true;

    if (key_len < MinKeyLen || key_len > MaxKeyLen)
      ex.throw_ex<std::length_error>("invalid key length: " + std::to_string(key_len));
  }

  bool locally_unreachable_;
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_KEY_SECTION_H_
