/* copyright (c) 2018, tini2p
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

#ifndef SRC_NTCP2_ROUTER_META_CERTIFICATE_H_
#define SRC_NTCP2_ROUTER_META_CERTIFICATE_H_

namespace ntcp2
{
namespace meta
{
namespace router
{
namespace cert
{
enum CertTypes : std::uint8_t
{
  NullCert = 0,
  HashCashCert,
  HiddenCert,
  SignedCert,
  MultipleCert,
  KeyCert
};

enum SigningTypes : std::uint16_t
{
  DsaSha1Sign = 0,
  EcdsaSha256P256Sign,
  EcdsaSha384P384Sign,
  EcdsaSha512P521Sign,
  RsaSha256_2048Sign,
  RsaSha384_3072Sign,
  RsaSha512_4096Sign,
  EdDsaSha512Ed25519Sign,
  EdDsaSha512Ed25519phSign,
  // convenience definition
  Ed25519Sign = EdDsaSha512Ed25519Sign,
  ReservedSign = 65535,
};

enum CryptoTypes : std::uint16_t
{
  ElGamalCrypto = 0,
  ReservedCrypto = 65535
};

enum Offsets : std::uint8_t
{
  CertTypeOffset = 0,
  LengthOffset,
  SignTypeOffset = 3,
  CryptoTypeOffset = 5,
};

enum Sizes : std::uint8_t
{
  CertTypeSize = 1,
  NullCertSize = 3,
  KeyCertSize = 7,
};
}  // namespace cert
}  // namespace router
}  // namespace meta
}  // namespace ntcp2

#endif  // SRC_NTCP2_ROUTER_META_CERTIFICATE_H_
