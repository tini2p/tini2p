# tinI2P

tini2p is designed to be a header-only, minimal, modular C++ I2P libary.

See the [design](./DESIGN.md) document for details on design decisions and project goals.

### Prerequisites

- Catch2: [https://github.com/catchorg/Catch2](https://github.com/catchorg/Catch2)
- Boost 1.66+: [https://github.com/boostorg/boost](https://github.com/boostorg/boost)
- CMake 3.10+: [https://cmake.org](https://cmake.org)
- libsodium: [https://github.com/jedisct1/libsodium](https://github.com/jedisct1/libsodium)

### Submodules

- tiny-AES-c: [https://github.com/kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c)
  - Using local fork with header-only modifications
- NoiseC : [https://github.com/tini2p/noise-c](https://github.com/tini2p/noise-c)
  - Currently using local fork with modifications for NTCP2
  - Possible long-term refactor plans:
    - reimplement in native-C++ with wrappers around libsodium
    - maintain local refactored NoiseC with only needed components for I2P

### Cloning tini2p

```
git clone --recursive https://github.com/tini2p/tini2p.git
```

### Building tini2p

```
cd /path/to/tini2p

make tests
./build/tini2p-tests

make net-tests
./build/tini2p-net-tests

make coverage
# run lcov + lcov-genhtml, script + CI coming soon
```

### Project layout

A brief overview of the project file structure (beware somewhat volatile):

- build: Build directory
- cmake: CMake build scripts
- src: Project source code
  - crypto: Cryptographic implementations/wrappers
  - data: Common data structures
  - exception: Exception handling
  - ntcp2: NTCP2 implementation
- tests: Project test suite
  - unit_tests: Unit tests
  - net_tests: Networking tests

tini2p follows a header-only library design, enabling developers to interact with the I2P network without needing a
separate binary.

All test code also serves as examples for how to use/integrate tini2p.

One of the project goals is to release a reference router for users that prefer to run a binary without integrating into
another project.

## WIP

This project is in its earliest stages, and *SHOULD NOT* be used when strong anonymity is needed (yet).

Core components:

- [x] NTCP2 transport
- [x] SessionRequest crypto + message processing
- [x] SessionCreated crypto + message processing
- [x] SessionConfirmed crypto + message processing
- [x] DataPhase crypto + message processing
- [ ] I2NP message processing
- [ ] I2CP message processing
- [ ] Garlic encryption
- [ ] NetDb
- [ ] LeaseSet
- [x] RouterInfo
- [x] RouterIdentity
- [x] RouterAddress
- [x] Mapping
- [ ] Tunnels
- [ ] RouterContext

Client components:

- [ ] ClientContext
- [ ] ClientDestination
- [ ] ClientTunnels
- [ ] AddressBook
- [ ] Reseed
- [ ] Key + config storage
- [ ] Proxies (SOCKS4a/5, HTTP & ZMQ)
- [ ] Streaming API
- [ ] SAMv3 API

Crypto components:

- [x] X25519 key generation
- [x] X3DH Diffie-Hellman exchange
- [x] Ed25519 key generation, signing/verification
- [x] Base32/64 en/decoding
- [x] Blake2b hashing
- [x] SHA256 hashing + HMAC
- [x] HKDF key derivation
- [x] SipHash obfuscation
- [x] AES key generation, CBC-256 en/decryption
- [ ] Ed25519ph key generation, signing/verification (via libsodium)
- [ ] Ecies-X25519-AEAD-Ratchet-[HKDF-HMAC-Sha256 / HKDF-Blake2b]
  - [x] Basic implementation
  - full implementation pending on finalized [Proposal 144](https://geti2p.net/spec/proposals/144-ecies-x25519-aead-ratchet)
- [ ] RedDSA key generation, signing/verification
- [ ] XEdDSA key generation, signing/verification

Global components:

- [ ] Logging
- [ ] Storage: LMDB (AddressBook, NetDb storage)

Only one of Ed25519ph or RedDSA need to be implemented for reseed signature processing.

Since RedDSA may also be needed for key blinding, Ed25519ph may be extraneous and unwanted.

### Donate

For those beautiful spirits that want to support the cause:

XMR:

- 8ACEQ1HiziMafAnyEdmzL2G99vKNSvRMLDdrmDNCRVczRFpShZA7YvAGzvGH1g8WMQd2iH5REkcwTKMjKCwJWdxHNoUFcGH

BTC:

- 1MNLhCnKpagruVkcGQY4z3GvUN7r4mRdwj

Grin:

Eepsite: coming soon
Onion address: coming soon
