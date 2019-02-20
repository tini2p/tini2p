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
 * Test parameters from Crypto++
 * validat5.cpp - originally written and placed in the public domain by Wei Dai
 *                CryptoPP::Test namespace added by JW in February 2017.
 *                Source files split in July 2018 to expedite compiles.
*/

#include <catch2/catch.hpp>

#include "src/crypto/rand.h"

#include "src/crypto/siphash.h"

namespace hash = tini2p::crypto::hash;

struct SipHashFixture
{
  const hash::SipHashKeyPart key_pt1{
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}};

  const hash::SipHashKeyPart key_pt2{
      {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}};

  const hash::SipHashIV iv{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}};

  const hash::SipHashDigest digest{{0x3B, 0x62, 0xA9, 0xBA, 0x62, 0x58, 0xF5,
                                    0x61, 0x0F, 0x83, 0xE2, 0x64, 0xF3, 0x14,
                                    0x97, 0xB4}};
};

TEST_CASE_METHOD(SipHashFixture, "SipHash calculates digest", "[sip]")
{
  using Catch::Matchers::Equals;
  using vec = std::vector<std::uint8_t>;

  hash::SipHashDigest result;
  REQUIRE_NOTHROW(hash::SipHash(key_pt1, key_pt2, iv, result));
  REQUIRE_THAT(vec(result.begin(), result.end()),
               Equals(vec(digest.begin(), digest.end())));
}
