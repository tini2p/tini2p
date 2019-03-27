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

#ifndef SRC_NTCP2_DATA_PHASE_DATA_PHASE_H_
#define SRC_NTCP2_DATA_PHASE_DATA_PHASE_H_

#include "src/crypto/siphash.h"

#include "src/ntcp2/data_phase/message.h"

namespace tini2p
{
namespace ntcp2
{
/// @class DataPhase
/// @brief DataPhase implementation
/// @tparam RoleT Handshake role
template <class RoleT>
class DataPhase
{
 public:
  enum
  {
    AskStringLen = 4,
    SipStringLen = 7,
    SipMasterInLen = crypto::Sha256::DigestLen + SipStringLen,
  };

  using state_t = noise::HandshakeState;  //< Handshake state trait alias
  using message_t = DataPhaseMessage;  //< Message trait alias

 private:
  /// @class DataPhase: KDF
  class KDF
  {
   public:
    /// @brief Create a DataPhaseKDF from a given handshake state and initial role
    /// @param state Pointer to valid Noise handshake state
    /// @param role Noise role during first DataPhase message
    /// @throw Invalid argument on null handshake state
    KDF(state_t* state)
        : state_(state),
          key_pt1_ab_{},
          key_pt2_ab_{},
          iv_ab_{},
          key_pt1_ba_{},
          key_pt2_ba_{},
          iv_ba_{}
    {
      const exception::Exception ex{"DataPhaseKDF", __func__};

      if (!state)
        ex.throw_ex<std::invalid_argument>("null handshake state.");

      crypto::X25519::pubkey_t temp_key;

      if (std::is_same<RoleT, Initiator>::value)
        noise::split(state_, &alice_to_bob_, &bob_to_alice_, temp_key, ex);
      else
        noise::split(state_, &bob_to_alice_, &alice_to_bob_, temp_key, ex);

      noise::get_handshake_hash(state_, h_, ex);
      InitSipKeys(temp_key);
    }

    /// @brief Process de/obfuscated encrypted message length
    /// @param length Packet length to de/obfuscate
    /// @param direction Flag indicating direction of the message
    /// @detail Advances SipHash key state, deriving a new IV every call, see spec
    void ProcessLength(
        boost::endian::big_uint16_t& length,
        const message_t::Dir direction)
    {
      length ^= DeriveMask(direction);
    }

    /// @brief Get a const reference to the final handshake hash
    decltype(auto) hash() const noexcept
    {
      return h_;
    }

    /// Get a non-const pointer to the cipherstate for messages from Alice to Bob
    decltype(auto) cipherstate(const message_t::Dir direction) noexcept
    {
      return direction == message_t::Dir::AliceToBob ? alice_to_bob_
                                                     : bob_to_alice_;
    }

   private:
    void InitSipKeys(crypto::X25519::pubkey_t& temp_key)
    {
      crypto::FixedSecBytes<SipMasterInLen> sip_master_in;

      // concat handshake hash: h || "siphash"
      tini2p::BytesWriter<decltype(sip_master_in)> sip_in_writer(sip_master_in);
      sip_in_writer.write_data(h_);
      sip_in_writer.write_data(crypto::FixedSecBytes<SipStringLen>{
          {0x73, 0x69, 0x70, 0x68, 0x61, 0x73, 0x68}});

      crypto::HmacSha256::digest_t ask_master, sip_master;

      constexpr static const std::array<std::uint8_t, 1> one_byte{0x01};

      // Derive SipHash temp key from handshake temp key
      crypto::HmacSha256::Hash(
          temp_key.buffer(),
          crypto::FixedSecBytes<AskStringLen>{{0x61, 0x73, 0x6B, 0x01}},
          ask_master);
      crypto::HmacSha256::Hash(ask_master, sip_master_in, temp_key.buffer());
      crypto::HmacSha256::Hash(temp_key.buffer(), one_byte, sip_master);
      crypto::HmacSha256::Hash(
          sip_master, std::array<std::uint8_t, 0>{}, temp_key.buffer());

      crypto::HmacSha256::digest_t sip_keys_ab, sip_keys_ba;

      // Derive SipHash keys for Alice to Bob
      crypto::HmacSha256::Hash(temp_key.buffer(), one_byte, sip_keys_ab);

      BytesReader<crypto::HmacSha256::digest_t> ab_reader(sip_keys_ab);
      ab_reader.read_data(key_pt1_ab_);
      ab_reader.read_data(key_pt2_ab_);
      ab_reader.read_data(iv_ab_);

      crypto::FixedSecBytes<crypto::HmacSha256::DigestLen + 1> sip_keys_ba_in;
      tini2p::BytesWriter<decltype(sip_keys_ba_in)> sip_ba_in_writer(sip_keys_ba_in);
      sip_ba_in_writer.write_data(sip_keys_ab);
      sip_ba_in_writer.write_bytes<std::uint8_t>(0x02);

      // Derive SipHash keys for Bob to Alice
      crypto::HmacSha256::Hash(temp_key.buffer(), sip_keys_ba_in, sip_keys_ba);

      tini2p::BytesReader<crypto::HmacSha256::digest_t> ba_reader(sip_keys_ba);
      ba_reader.read_data(key_pt1_ba_);
      ba_reader.read_data(key_pt2_ba_);
      ba_reader.read_data(iv_ba_);
    }

    boost::endian::big_uint16_t DeriveMask(const message_t::Dir direction)
    {
      boost::endian::big_uint16_t mask;
      crypto::SipHash::digest_t digest;
      if (direction == message_t::Dir::AliceToBob)
        {
          crypto::SipHash::Hash(key_pt1_ab_, key_pt2_ab_, iv_ab_, digest);
          std::copy(
              digest.begin(), digest.begin() + iv_ab_.size(), iv_ab_.begin());
        }
      else
        {
          crypto::SipHash::Hash(key_pt1_ba_, key_pt2_ba_, iv_ba_, digest);
          std::copy(
              digest.begin(), digest.begin() + iv_ba_.size(), iv_ba_.begin());
        }
      tini2p::read_bytes(digest.data(), mask);
      return mask;
    }

    crypto::SipHash::key_part_t key_pt1_ab_, key_pt2_ab_, key_pt1_ba_,
        key_pt2_ba_;
    crypto::SipHash::iv_t iv_ab_, iv_ba_;
    crypto::Sha256::digest_t h_;
    state_t* state_;
    noise::CipherState* alice_to_bob_;
    noise::CipherState* bob_to_alice_;
  };

 public:
  using role_t = RoleT;  //< Role trait alias
  using kdf_t = DataPhase::KDF;  //< KDF trait alias

  DataPhase(state_t* state) : state_(state), kdf_(state)
  {
    if (!state)
      exception::Exception{"DataPhase", __func__}
          .throw_ex<std::invalid_argument>("null handshake state.");
  }

  /// @brief Write and encrypt a message
  /// @param message DataPhase message to write
  void Write(message_t& message)
  {
    namespace block = tini2p::meta::block;

    const exception::Exception ex{"DataPhase", __func__};

    boost::endian::big_uint16_t length = message.size();
    if (!length)
      ex.throw_ex<std::invalid_argument>("empty message.");

    length += crypto::Poly1305::DigestLen;
    auto& buf = message.buffer();
    buf.resize(message_t::SizeLen + length);

    const auto dir = std::is_same<role_t, Initiator>::value
                         ? message_t::Dir::BobToAlice
                         : message_t::Dir::AliceToBob;

    // obfuscate message length
    kdf_.ProcessLength(length, dir);
    tini2p::write_bytes(buf.data(), length);

    // seriailze message blocks to buffer
    message.serialize();

    // encrypt message in place
    noise::encrypt(
        kdf_.cipherstate(dir),
        &buf[message_t::SizeLen],
        buf.size() - message_t::SizeLen,
        ex);
  }

  /// @brief Decrypt and read a message
  /// @param message DataPhase message to read
  /// @param deobfs_len Flag to de-obfuscate the message length
  void Read(message_t& message, const bool deobfs_len = true)
  {
    const exception::Exception ex{"DataPhase", __func__};

    auto& buf = message.buffer();
    if (buf.size() < message_t::MinLen || buf.size() > message_t::MaxLen)
      ex.throw_ex<std::length_error>("invalid ciphertext size.");

    boost::endian::big_uint16_t length;
    tini2p::read_bytes(buf.data(), length);

    const auto dir = std::is_same<role_t, Initiator>::value
                         ? message_t::Dir::AliceToBob
                         : message_t::Dir::BobToAlice;

    if (deobfs_len)
      kdf_.ProcessLength(length, dir);

    if ((std::int16_t)(length - crypto::Poly1305::DigestLen) <= 0)
      {
        std::cerr << "DataPhase: null message." << std::endl;
        return;
      }

    if (length > message_t::MaxLen - message_t::SizeLen)
      ex.throw_ex<std::length_error>("invalid message size.");

    noise::decrypt(kdf_.cipherstate(dir), &buf[message_t::SizeLen], length, ex);

    // deserialize blocks from buffer
    buf.resize(message_t::SizeLen + length);
    message.deserialize();
  }

  /// @brief Get a non-const reference to the KDF
  kdf_t& kdf() noexcept
  {
    return kdf_;
  }

 private:
  role_t role_;
  state_t* state_;
  kdf_t kdf_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_DATA_PHASE_DATA_PHASE_H_
