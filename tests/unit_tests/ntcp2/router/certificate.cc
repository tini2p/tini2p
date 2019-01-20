/* copyright (c) 2019, tini2p
 * all rights reserved.
 *
 * redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * this software is provided by the copyright holders and contributors "as is"
 * and any express or implied warranties, including, but not limited to, the
 * implied warranties of merchantability and fitness for a particular purpose are
 * disclaimed. in no event shall the copyright holder or contributors be liable
 * for any direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute goods or
 * services; loss of use, data, or profits; or business interruption) however
 * caused and on any theory of liability, whether in contract, strict liability,
 * or tort (including negligence or otherwise) arising in any way out of the use
 * of this software, even if advised of the possibility of such damage.
*/

#include <catch2/catch.hpp>

#include "src/ntcp2/router/certificate.h"

struct RouterCertificateFixture
{
  ntcp2::router::Certificate cert;
};

TEST_CASE_METHOD(
    RouterCertificateFixture,
    "RouterCertificate has a type",
    "[cert]")
{
  namespace meta = ntcp2::meta::router::cert;

  REQUIRE(cert.cert_type == meta::KeyCert);
  REQUIRE(cert.sign_type == meta::Ed25519Sign);
  REQUIRE(cert.crypto_type == meta::ElGamalCrypto);
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
