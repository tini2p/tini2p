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

#ifndef SRC_DATA_ROUTER_MAPPING_H_
#define SRC_DATA_ROUTER_MAPPING_H_

#include <set>

#include <boost/range/algorithm/lexicographical_compare.hpp>

#include "src/exception/exception.h"

#include "src/bytes.h"

#include "src/data/router/meta.h"

namespace exception = tini2p::exception;

namespace tini2p
{
namespace data
{
/// @brief Container for set-compatible mapping entry
class MappingEntry
{
  std::vector<std::uint8_t> key_, value_;

 public:
  /// @brief Create an empty mapping entry from a key
  template <class Key>
  explicit MappingEntry(const Key& key) : value_{}
  {
    namespace meta = tini2p::meta::router::mapping;

    check_param(key, {"Router: Mapping", __func__});

    key_.insert(key_.begin(), key.begin(), key.end());
  }

  /// @brief Create a mapping entry from a key-value pair
  template <class Key, class Value>
  MappingEntry(const Key& key, const Value& value)
  {
    namespace meta = tini2p::meta::router::mapping;

    const exception::Exception ex{"Router: Mapping", __func__};

    check_param(key, ex);
    check_param(value, ex);

    key_.insert(key_.begin(), key.begin(), key.end());
    value_.insert(value_.begin(), value.begin(), value.end());
  }

  /// @brief Get a const reference to the key
  const decltype(key_)& key() const noexcept
  {
    return key_;
  }

  /// @brief Set the key
  /// @param key Key to set
  template <class Key>
  void key(const Key& key)
  {
    check_param(key, {"Router: Mapping", __func__});
    key_.clear();
    key_.insert(key_.begin(), key.begin(), key.end());
  }

  /// @brief Set the value
  /// @param value Value to set
  template <class Value>
  void value(const Value& value)
  {
    check_param(value, {"Router: Mapping", __func__});
    value_.clear();
    value_.insert(value_.begin(), value.begin(), value.end());
  }

  /// @brief Get a const reference to the value
  const decltype(value_)& value() const noexcept
  {
    return value_;
  }

  /// @brief Get the total entry size (key + value + delims)
  std::uint32_t size() const noexcept
  {
    namespace meta = tini2p::meta::router::mapping;

    return key_.empty() ? 0
                        : key_.size() + value_.size() + meta::DelimSize
                              + (2 * meta::KVLenSize);
  }

  bool operator<(const MappingEntry& other) const
  {
    return boost::range::lexicographical_compare(key_, other.key());
  }

 private:
  template <class Param>
  void check_param(const Param& param, const tini2p::exception::Exception& ex)
  {  // check parameter is in valid range
    namespace meta = tini2p::meta::router::mapping;

    if (param.size() < meta::MinKVSize || param.size() > meta::MaxKVSize)
      ex.throw_ex<std::length_error>("invalid key-value size.");
  }
};

/// @brief Class for storing/processing I2P mappings
class Mapping
{
  std::set<MappingEntry> kv_;
  std::vector<std::uint8_t> buffer_;
  const std::string kv_delim_{"="}, tail_delim_{";"};

 public:
  /// @brief Get a const reference to the buffer
  const decltype(buffer_)& buffer() const noexcept
  {
    return buffer_;
  }

  /// @brief Get a mutable reference to the buffer
  decltype(buffer_)& buffer() noexcept
  {
    return buffer_;
  }

  /// @brief Get a const reference to the mapping entry at key
  /// @param key Mapping key to search for a value
  /// @return The key's value or an empty value if unfound
  template <class Key>
  decltype(auto) entry(const Key& key) const
  {
    MappingEntry search(key);
    const auto pos = kv_.find(search);

    if (pos != kv_.end())
      return pos->value();
    else
      return search.value();
  }

  /// @brief Return the size of the mapping buffer
  std::uint16_t size() const noexcept
  {
    namespace meta = tini2p::meta::router::mapping;

    std::size_t total_size = meta::SizeSize;
    for (const auto& kv : kv_)
      total_size += kv.size();

    return total_size;
  }

  /// @brief Add an entry to the mapping
  /// @param key Key for the mapping entry
  /// @param value Value for the mapping entry
  template <class Key, class Value>
  void add(const Key& key, const Value& value)
  {
    namespace meta = tini2p::meta::router::mapping;

    const MappingEntry entry(key, value);
    if (entry.size() + size() + meta::SizeSize > meta::MaxSize)
      exception::Exception{"Router: Mapping", __func__}
          .throw_ex<std::runtime_error>("entry exceeds max mapping size.");

    kv_.emplace(std::move(entry));
  }

  /// @brief Serialize the mapping to buffer
  void serialize()
  {
    namespace meta = tini2p::meta::router::mapping;

    buffer_.resize(size());
    tini2p::BytesWriter<decltype(buffer_)> writer(buffer_);

    writer.write_bytes<std::uint16_t>(size() - meta::SizeSize);

    for (const auto& kv : kv_)
      {
        // write key + key-value delimiter
        writer.write_bytes<std::uint8_t>(kv.key().size());
        writer.write_data(kv.key());
        writer.write_data(kv_delim_);

        // write value + tail delimiter
        writer.write_bytes<std::uint8_t>(kv.value().size());
        writer.write_data(kv.value());
        writer.write_data(tail_delim_);
      }
  }

  /// @brief Deserialize the mapping from buffer
  void deserialize()
  {
    namespace meta = tini2p::meta::router::mapping;

    tini2p::BytesReader<decltype(buffer_)> reader(buffer_);

    // read the mapping size
    std::uint16_t size;
    reader.read_bytes(size);

    if (!size)
      return;

    if (size < meta::MinSize || size + meta::SizeSize > buffer_.size())
      exception::Exception{"Router: Mapping", __func__}
          .throw_ex<std::length_error>("invalid mapping size.");

    // clear the key-value store
    kv_.clear();

    while (reader.gcount())
      {
        // read the key size
        std::uint8_t key_size;
        reader.read_bytes(key_size);

        // read the key, skip the key-value delim
        std::vector<std::uint8_t> key;
        key.resize(key_size);
        reader.read_data(key);

        reader.skip_bytes(kv_delim_.size());

        // read the value size
        std::uint8_t val_size;
        reader.read_bytes(val_size);

        // read the value, skip the trailing delim
        std::vector<std::uint8_t> value;
        value.resize(val_size);
        reader.read_data(value);

        reader.skip_bytes(tail_delim_.size());

        add(key, value);
      }
  }
};
}  // namespace data
}  // namespace tini2p

#endif  // SRC_DATA_ROUTER_MAPPING_H_
