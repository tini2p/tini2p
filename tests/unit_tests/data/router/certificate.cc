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

#include <catch2/catch.hpp>

#include "src/data/router/certificate.h"

using tini2p::data::Certificate;

struct RouterCertificateFixture
{
  Certificate cert;
};

TEST_CASE_METHOD(
    RouterCertificateFixture,
    "RouterCertificate has a valid default construction",
    "[cert]")
{
  REQUIRE(cert.cert_type == Certificate::cert_type_t::KeyCert);
  REQUIRE(cert.sign_type == Certificate::sign_type_t::EdDSA);
  REQUIRE(cert.crypto_type == Certificate::crypto_type_t::EciesX25519);
}

TEST_CASE_METHOD(
    RouterCertificateFixture,
    "RouterCertificate serializes a valid certificate",
    "[cert]")
{
  REQUIRE_NOTHROW(cert.serialize());
}

TEST_CASE_METHOD(
    RouterCertificateFixture,
    "RouterCertificate deserializes a valid certificate",
    "[cert]")
{
  REQUIRE_NOTHROW(cert.serialize());
  REQUIRE_NOTHROW(cert.deserialize());
}
