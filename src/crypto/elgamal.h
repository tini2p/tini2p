/* Copyright (c) 2013-2018, The Kovri I2P Router Project
 * Copyright (c) 2019, tini2p
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

#ifndef SRC_CRYPTO_ELGAMAL_H_
#define SRC_CRYPTO_ELGAMAL_H_

#include "src/crypto/constants.h"
#include "src/crypto/hash.h"

#include "src/crypto/key/elgamal.h"

namespace tini2p
{
namespace meta
{
namespace crypto
{
namespace elgamal
{
enum Sizes : std::uint16_t
{
  NonceSize = 1,
  BlockSize = 256,
  PadSize = 1,
  PlaintextSize = 222,
  CiphertextSize = 514,
  DefaultSize = NonceSize + tini2p::crypto::hash::Sha256Len + PlaintextSize,
};

enum Offsets : std::uint16_t
{
  // encryption offsets
  HashOffset = NonceSize,
  PlaintextOffset = HashOffset + tini2p::crypto::hash::Sha256Len,

  // for zero-padding
  BlockOnePadOffset = 0,
  BlockOneCipherOffset = PadSize,
  BlockTwoPadOffset = PadSize + BlockSize, 
  BlockTwoCipherOffset = BlockSize + (2 * PadSize),
};
}  // namespace elgamal
}  // namespace crypto
}  // namespace meta

namespace crypto
{
namespace elgamal
{
/// @brief ElGamal plaintext alias for correctness, usability and clarity
/// @detail Wiping plaintext after use minimizes router footprint/traceability
using Plaintext =
    FixedSecBytes<std::uint8_t, meta::crypto::elgamal::PlaintextSize>;

/// @brief ElGamal ciphertext alias for correctness, usability and clarity
/// @detail Wiping ciphertext after use minimizes router footprint/traceability
using Ciphertext =
    FixedSecBytes<std::uint8_t, meta::crypto::elgamal::CiphertextSize>;

/// @brief ElGamal encryption class with I2P modifications
class Encryptor
{
  CryptoPP::AutoSeededRandomPool rng_;
  CryptoPP::Integer pk_ /*pubkey*/, s_ /*shared secret*/, y_ /*ephemeral key*/,
      c1_ /*exp(g, y)*/;

 public:
  /// @brief Create an ElGamal encryptor from a public key
  Encryptor(const elgamal::PubKey& key) : pk_(key.data(), key.size())
  {
  }

  /// @brief Encrypt plaintext message using ElGamal
  /// @param out Output buffer for ciphertext
  /// @param in Input buffer for plaintext
  /// @param zero_pad Flag for zero-padded ciphertext
  void Encrypt(Ciphertext& out, const Plaintext& in, const bool zero_pad)
  {
    namespace meta = tini2p::meta::crypto::elgamal;

    using tini2p::meta::crypto::constants::elgp;
    using tini2p::crypto::hash::Sha256Len;

    const tini2p::exception::Exception ex{"ElGamalEncryptor", __func__};

    // generate fresh ephemeral key material
    update_ephemeral();

    std::array<std::uint8_t, meta::DefaultSize> memory;

    // Don't pad with uninitialized memory
    tini2p::crypto::RandBytes(memory.data(), memory.size());

    // Ensure first byte is spec-defined, non-zero, random byte
    while (!memory.at(0))
      tini2p::crypto::RandBytes(memory.data(), meta::NonceSize);

    std::copy(in.begin(), in.end(), &memory[meta::PlaintextOffset]);

    // hash the plaintext (an I2P'ism)
    CryptoPP::SHA256().CalculateDigest(
        &memory[meta::HashOffset],
        &memory[meta::HashOffset] + Sha256Len,
        meta::PlaintextSize);

    // encrypt by: shared secret * (hash || plaintext)
    CryptoPP::Integer ct(a_times_b_mod_c(
        s_, CryptoPP::Integer(memory.data(), memory.size()), elgp));

    // Copy exp(g, y) and ciphertext
    if (zero_pad)
      {
        out[meta::BlockOnePadOffset] = 0;
        c1_.Encode(&out[meta::BlockOneCipherOffset], meta::BlockSize);

        out[meta::BlockTwoPadOffset] = 0;
        ct.Encode(&out[meta::BlockTwoCipherOffset], meta::BlockSize);
      }
    else
      {
        c1_.Encode(out.data(), meta::BlockSize);
        ct.Encode(&out[meta::BlockSize], meta::BlockSize);
      }
  };

  /// @brief Rekey the encryptor with a new public key
  /// @param key Public key to use for encryption
  void rekey(const elgamal::PubKey& key)
  {
    pk_.Decode(key.data(), key.size());
  }

  /// @brief Get the public key as a buffer
  decltype(auto) pub_key() const
  {
    elgamal::PubKey buf;
    pk_.Encode(buf.data(), buf.size());
    return buf;
  }

 private:
  void update_ephemeral()
  {  // rekey ephemeral material for every message
    using tini2p::meta::crypto::constants::elgg;
    using tini2p::meta::crypto::constants::elgp;

    y_ = CryptoPP::Integer(rng_, CryptoPP::Integer::One(), elgp - 1);
    c1_ = a_exp_b_mod_c(elgg, y_, elgp);
    s_ = a_exp_b_mod_c(pk_, y_, elgp);
  }
};

/// @brief ElGamal decryption class with I2P modifications
class Decryptor
{
  CryptoPP::Integer x_ /*private exponent*/;

 public:
  Decryptor(const elgamal::PvtKey& sk) : x_(sk.data(), sk.size()) {}

  /// @brief Decrypt an ElGamal encrypted block
  /// @param out Output plaintext buffer (must be 222 bytes, see spec)
  /// @param in Input ciphertext buffer (must be 514 bytes, see spec)
  /// @param zero_pad Flag for zero-padded ciphertext
  void Decrypt(Plaintext& out, const Ciphertext& in, const bool zero_pad)
  {
    namespace meta = tini2p::meta::crypto::elgamal;

    using tini2p::meta::crypto::constants::elgg;
    using tini2p::meta::crypto::constants::elgp;
    using tini2p::crypto::hash::Sha256Len;

    const exception::Exception ex{"ElGamalDecryptor", __func__};

    if (zero_pad
        && (in[meta::BlockOnePadOffset] || in[meta::BlockTwoPadOffset]))
      ex.throw_ex<std::invalid_argument>("bad ciphertext padding.");

    if (out.size() != meta::PlaintextSize)
      ex.throw_ex<std::length_error>("bad plaintext size.");

    if (in.size() != meta::CiphertextSize)
      ex.throw_ex<std::length_error>("bad ciphertext size.");

    const auto c1_buf = zero_pad ? &in[meta::BlockOneCipherOffset] : in.data();
    const auto ct_buf =
        zero_pad ? &in[meta::BlockTwoCipherOffset] : &in[meta::BlockSize];

    CryptoPP::Integer c1(c1_buf, meta::BlockSize), ct(ct_buf, meta::BlockSize);

    std::array<std::uint8_t, meta::DefaultSize> memory;

    // decrypt by: ciphertext * exp(exp(g, y), mod_inverse(x)) (all modulo p)
    a_times_b_mod_c(ct, a_exp_b_mod_c(c1, elgp - x_ - 1, elgp), elgp)
        .Encode(memory.data(), meta::DefaultSize);

    // verify the plaintext checksum (an I2P'ism)
    if (!CryptoPP::SHA256().VerifyDigest(
            &memory[meta::HashOffset],
            &memory[meta::HashOffset] + Sha256Len,
            meta::PlaintextSize))
      ex.throw_ex<std::runtime_error>("checksum verification failed.");

    // copy the plaintext to the output buffer
    auto plaintext = memory.data() + meta::PlaintextOffset;
    std::copy(plaintext, plaintext + meta::PlaintextSize, out.data());
  }

  /// @brief Rekey the decryptor with a new private key
  /// @param key Private key to use for decryption
  void rekey(const elgamal::PvtKey& key)
  {
    x_.Decode(key.data(), key.size());
  }
};
}  // namespace elgamal
}  // namespace crypto
}  // namespace tini2p

#endif  // SRC_CRYPTO_ELGAMAL_H_
