# tinI2P

tini2p is designed to be a minimal, modular C++ I2P router.

See the [design](./DESIGN.md) document for details on design decisions and project goals.

### Prerequisites

- Catch2: [https://github.com/catchorg/Catch2](https://github.com/catchorg/Catch2)
- Boost 1.66+: [https://github.com/boostorg/boost](https://github.com/boostorg/boost)
- CMake 3.10+: [https://cmake.org](https://cmake.org)

### Submodules

- Crypto++: [https://github.com/weidai11/crytopp](https://github.com/weidai11/crytopp)
- NoiseC : [https://github.com/tini2p/noise-c](https://github.com/tini2p/noise-c)
  - Currently using local fork with modifications for NTCP2

### Cloning tini2p

```
git clone --recursive https://github.com/tini2p/tini2p.git
```

### Building tini2p

```
cd /path/to/tini2p
make tests
./build/tini2p-tests
```

## WIP

This project is in its earliest stages, and shouldn't be used when strong anonymity is needed (yet).

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
- [ ] RouterInfo (still need additional options parsing)
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

Global components:

- [x] X25519 key generation (via Crypto++), DH crypto (via Noise-C)
- [x] Ed25519 key generation, signing/verification (via TweetNaCl in Crypto++)
- [x] Base32/64 en/decoding (via Crypto++)
- [x] SHA256 hashing + HMAC (via Crypto++)
- [x] SipHash obfuscation (via Crypto++)
- [x] ElGamal key generation, en/decryption, DH crypto (via Crypto++)
- [x] AES key generation, CBC-256 en/decryption (via Crypto++)
- [ ] Ed25519ph key generation, signing/verification (via Crypto++)
- [ ] RSA-SHA512-4096 key generation, signing/verification (via Crypto++)
- [ ] Logging
- [ ] Networking
- [ ] Multithreading
- [ ] LMDB (AddressBook, NetDb storage)

Only one of Ed25519ph or RSA-SHA512-4096 need to be implemented for reseed signature processing.
