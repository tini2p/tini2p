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

#ifndef SRC_NTCP2_DATA_PHASE_KDF_H_
#define SRC_NTCP2_DATA_PHASE_KDF_H_

#include <boost/endian/arithmetic.hpp>

#include <noise/protocol/handshakestate.h>

#include "src/crypto/key.h"
#include "src/crypto/hash.h"
#include "src/crypto/siphash.h"

#include "src/bytes.h"
#include "src/ntcp2/noise.h"
#include "src/ntcp2/role.h"

#include "src/ntcp2/data_phase/meta.h"

namespace tini2p
{
namespace ntcp2
{
/// @class DataPhaseKDF
class DataPhaseKDF
{
  crypto::hash::SipHashKeyPart key_pt1_ab_, key_pt2_ab_, key_pt1_ba_,
      key_pt2_ba_;
  crypto::hash::SipHashIV iv_ab_, iv_ba_;
  crypto::hash::Sha256Digest h_;
  NoiseHandshakeState* state_;
  NoiseCipherState *alice_to_bob_, *bob_to_alice_;

 public:
  /// @brief Create a DataPhaseKDF from a given handshake state and initial role
  /// @param state Pointer to valid Noise handshake state
  /// @param role Noise role during first DataPhase message
  /// @throw Invalid argument on null handshake state
  DataPhaseKDF(NoiseHandshakeState* state, const Role& role)
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

    crypto::x25519::PubKey temp_key;

    if (role.id() == noise::InitiatorRole)
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
      const meta::ntcp2::data_phase::Direction direction)
  {
    length ^= DeriveMask(direction);
  }

  /// @brief Get a const reference to the final handshake hash
  const decltype(h_)& hash() const noexcept
  {
    return h_;
  }

  /// Get a pointer to the cipherstate for messages from Alice to Bob
  decltype(alice_to_bob_) cipherstate(
      meta::ntcp2::data_phase::Direction direction) noexcept
  {
    return direction == meta::ntcp2::data_phase::AliceToBob ? alice_to_bob_
                                                     : bob_to_alice_;
  }

 private:
  void InitSipKeys(crypto::x25519::PubKey& temp_key)
  {
    namespace meta = tini2p::meta::ntcp2::data_phase;

    using tini2p::crypto::hash::HmacSha256;

    std::array<std::uint8_t, meta::SipMasterInSize> sip_master_in;

    const std::array<std::uint8_t, meta::AskStrSize> ask_str{
        {0x61, 0x73, 0x6B, 0x01}};  // "ask" || byte(0x01)

    const std::array<std::uint8_t, meta::SipStrSize> sip_str{
        {0x73, 0x69, 0x70, 0x68, 0x61, 0x73, 0x68}};  // "siphash"

    // concat handshake hash: h || "siphash"
    tini2p::BytesWriter<decltype(sip_master_in)> sip_in_writer(sip_master_in);
    sip_in_writer.write_data(h_);
    sip_in_writer.write_data(sip_str);

    crypto::hash::Sha256Digest ask_master, sip_master;
    const std::array<std::uint8_t, 1> byte_one{0x01};

    // Derive SipHash temp key from handshake temp key
    HmacSha256(temp_key, ask_str, ask_master);
    HmacSha256(ask_master, sip_master_in, temp_key);
    HmacSha256(temp_key, byte_one, sip_master);
    HmacSha256(sip_master, std::array<std::uint8_t, 0>{}, temp_key);

    crypto::hash::Sha256Digest sip_keys_ab, sip_keys_ba;

    // Derive SipHash keys for Alice to Bob
    HmacSha256(temp_key, byte_one, sip_keys_ab);
    tini2p::BytesReader<decltype(sip_keys_ab)> ab_reader(sip_keys_ab);
    ab_reader.read_data(key_pt1_ab_);
    ab_reader.read_data(key_pt2_ab_);
    ab_reader.read_data(iv_ab_);

    std::array<std::uint8_t, crypto::hash::Sha256Len + 1> sip_keys_ba_in;
    std::copy(sip_keys_ab.begin(), sip_keys_ab.end(), sip_keys_ba_in.begin());
    sip_keys_ba_in.back() = 0x02;

    // Derive SipHash keys for Bob to Alice
    HmacSha256(temp_key, sip_keys_ba_in, sip_keys_ba);
    tini2p::BytesReader<decltype(sip_keys_ba)> ba_reader(sip_keys_ba);
    ba_reader.read_data(key_pt1_ba_);
    ba_reader.read_data(key_pt2_ba_);
    ba_reader.read_data(iv_ba_);
  }

  boost::endian::big_uint16_t DeriveMask(
      const meta::ntcp2::data_phase::Direction direction)
  {
    boost::endian::big_uint16_t mask;
    crypto::hash::SipHashDigest digest;
    if (direction == meta::ntcp2::data_phase::AliceToBob)
      {
        crypto::hash::SipHash(key_pt1_ab_, key_pt2_ab_, iv_ab_, digest);
        std::copy(
            digest.begin(), digest.begin() + iv_ab_.size(), iv_ab_.begin());
      }
    else
      {
        crypto::hash::SipHash(key_pt1_ba_, key_pt2_ba_, iv_ba_, digest);
        std::copy(
            digest.begin(), digest.begin() + iv_ba_.size(), iv_ba_.begin());
      }
    tini2p::read_bytes(digest.data(), mask);
    return mask;
  }
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_DATA_PHASE_KDF_H_
