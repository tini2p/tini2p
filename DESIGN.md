# Tiny I2P Router Design Ideas

## Overall design

Minimal as possible. I2P is full of crypto primitives, file formats, and protocols.

The goal is to implement the smallest functional set of I2P concepts for a working router.

To begin, only implement the NTCP2 transport. This is a TCP-like end-to-end encrypted transport.

If we decide to support UDP-like traffic in the future, we will need to implement the SSU transport.

Components should be modular, minimal, and use clear interfaces.

Use good coding practices like TDD, DRY, SRP, RAII, etc.

All new code must have accompanying tests, and cannot decrease test coverage (barring rare exceptions).

To the largest extent possible, use standard-library algorithms and C++11/14 (maybe 17?) style/features.

Supported crypto:

- X25519
- ChaCha-Poly1305
- SipHash
- Ed25519
- For Reseed:
  - Ed25519ph and/or
  - RSA-SHA512-4096
- Hopefully soon deprecated for ECIES (X25519 + ChaChaPoly1305):
  - ElGamal
  - AES-256-CBC

### Module layout

Each of these modules (other than `Common Structures`) should be mostly independent of one another.

#### Common Structures

- Contains classes common to most/all modules
  - convert from/to message buffers
  - [RouterInfo](https://geti2p.net/spec/common-structures#routerinfo)
    - contains information needed to contact a router
    - RouterIdentity
    - RouterAddress
    - Mapping (key-value mapping)
    - Signature
  - [RouterIdentity](https://geti2p.net/spec/common-structures#routeridentity)
    - has key material needed to contact a router
  - [LeaseSet](https://geti2p.net/spec/common-structures#leaseset)
    - short-term (10 minutes) set of Leases for contacting a Destination
  - [Lease](https://geti2p.net/spec/common-structures#lease)
    - has the Destination's InboundGateway IdentHash (SHA256 of the RouterIdentity)
    - has the TunnelID for the Destination's tunnel
    - has the creation time

### Core

#### Router

- RouterContext
  - manage router:
    - Transports
    - Tunnels
    - NetDb
  - contains:
    - RouterInfo
  
#### NTCP2 (transport):

- [Specification](https://geti2p.net/spec/ntcp2)
- Message handling:
  - SessionRequest
  - SessionCreated
  - SessionConfirmed
  - DataPhase
- Session
  - establish session via Noise handshake
    - handle message padding algorithm
  - manage an NTCP2 session
  - protect against
    - replay
    - flooding
    - lag
- SessionManager
  - track existing sessions
  - reject bad peers
    - connection spamming
    - frequent failed sessions

#### NetDb

- [Specification](https://geti2p.net/en/docs/how/network-database)
- DHT (distributed hash table)
  - store router (`RouterInfo`) and destination (`LeaseSet`) contact info
  - sort closest routers via the XOR metric
- [Peer selection](https://www.geti2p.net/en/docs/how/peer-selection)
- I2NP message handling:
  - DatabaseStoreHandler
  - DatabaseLookupHandler
  - DatabaseSearchReplyHandler

### I2NP

- [Specification](https://geti2p.net/spec/i2np)
- Messages for inter-router communication
- Message processors:
  - NetDb
  - GarlicClove
  - Tunnel classes
- Message types (convert from/to message buffers):
  - DatabaseStore
  - DatabaseLookup
  - DatabaseSearchReply
  - DeliveryStatus
  - Garlic
  - TunnelData
  - TunnelGateway
  - Data
  - TunnelBuild
  - TunnelBuildReply
  - VariableTunnelBuild
  - VariableTunnelBuildReply

#### Tunnels
- [Specification](https://www.i2p.net/en/docs/how/tunnel-routing)
  - [Tunnel creation](https://geti2p.net/spec/tunnel-creation)
  - [Tunnel messages](https://geti2p.net/spec/tunnel-message)
- I2NP message processors:
  - InboundTunnel
    - Gateway
    - Endpoint
  - OutboundTunnel
    - Gateway
    - Endpoint
  - ExploratoryTunnel
  - TunnelHop
- TunnelPool
  - manage tunnel creation, destruction, and access
  - templated to handle the three pool types (inbound, outbound, exploratory)
- TunnelTest
  - test the health of a given tunnel
- TunnelPoolManager
  - manage TunnelPool creation, destruction, and access

### Client

#### Client context

- Owns:
  - AddressBook
  - Reseed
  - Destination
  - Proxies
  - SAM API Server

#### AddressBook

- [Specification](https://geti2p.net/en/docs/naming#addressbook)
- Publisher
  - subscription publisher processing
  - download subscription
- Subscription
  - peer subscription processing
- Entry
  - host
  - address
- Jump services
  - provide contact info to another router for a requested Destination
  - used together with the HTTP proxy
- Storage

#### Reseed

- [Specification](https://geti2p.net/spec/updates#su3-reseed-file-specification)
- SU3Reseed
  - SU3 zip file processing
  - needed to bootstrap a new router

#### Destination

- [Specification](https://geti2p.net/spec/common-structures#destination)
  - endpoint for message delivery
  - manage LeaseSets

#### APIs

- [I2CP](https://geti2p.net/spec/i2cp)
  - low-level API for applications to communicate with the router
  - mostly used by other router components
- [Streaming](https://geti2p.net/spec/common-structures#destination)
  - mid-level API between I2CP and SAM for TCP-like connections
- [SAMv3](https://geti2p.net/en/docs/api/samv3)
  - high-level API for external applications to use
- Investigate a minimal API (minimized SAMv3)?

#### Proxies

- SOCKS
  - v4a/v5 only
    - possibly only v4a
  - v4 w/ no DNS-name entry doesn't make sense in this context
- HTTP
  - like Tor, TLS is unneeded for in-network connections
  - so many layers of crypto, one more isn't needed

## Module descriptions

### NTCP2

TCP-like transport using a modified `Noise_XK_25519_ChaChaPoly_SHA256` handshake protocol.

The Noise protocol uses:

- X25519 for Diffie-Hellman key agreement
- ChaChaPoly1305 for authenticated symmetric encryption
- AES and SipHash for obfuscation
- SHA256 as the hash for MixHash, MixKey Noise operations.

See the specification page for more details: [https://geti2p.net/spec/ntcp2](https://geti2p.net/spec/ntcp2)

Associated structures/protocols: 

- [RouterIdentity](https://geti2p.net/spec/common-structures#routeridentity)
- [RouterInfo](https://geti2p.net/spec/common-structures#routerinfo)
- [I2NP](https://geti2p.net/spec/i2np)

### SSU

UDP-like transport needed for peer introduction.

Uses ElGamal/AES+SessionTags with HMAC-MD5-128 to encrypt packets.

Do we need/want to implement?

Should we wait for an SSU2 based on a Noise protocol to implement UDP?

Is there a way to do peer introduction over NTCP2?

The non-standard, home-rolled HMAC-MD5-128 is also a bit of a nasty beast we might be better without.

See the specification page for all the gory details: [https://geti2p.net/spec/ssu](https://geti2p.net/spec/ssu)

Associated structures/protocols:

- [Peer Testing](https://geti2p.net/en/docs/transport/ssu#peerTesting)

### SU3: Reseed

Reseeding allows a new i2p peer to get an initial list of peers.

Downloading reseed files is usually done out-of-network, since it serves as a bootstrapping protocol.

Files are compressed and signed with either `RSA_SHA512_4096` or `EdDSA_SHA512_Ed25519ph`.

See the specification for more details: [https://geti2p.net/spec/updates#su3-reseed-file-specification](https://geti2p.net/spec/updates#su3-reseed-file-specification)

### I2NP

I2NP is a meta networking layer for communication between routers.

[Garlic cloves](https://geti2p.net/en/docs/how/garlic-routing) are used to bundle and encrypt multiple I2NP messages, using ElGamal/AES+SessionTags for encryption.

[Tunnel building](https://www.i2p.net/en/docs/how/tunnel-routing) uses I2NP messages for the various stages of tunnel creation/maintenance.

See the specification for more details: [https://geti2p.net/spec/i2np](https://geti2p.net/spec/i2np)

### Tunnels

I2P traffic is segmented into inbound and outbound tunnels.

As an example, traffic leaves at Alice's `Outbound Gateway` (OBGW) to another router selected as the `Outbound Endpoint` (OBEP), 
via a predetermined number `Hop` routers.

The OBEP processes packets to send to an `Inbound Gateway` (IBGW), a router selected by Bob to forward traffic to the `Inbound Endpoint` (IBEP), i.e. Bob's router.

Traffic is encrypted between each hop, with `Delivery Instructions` for routing.

See the specification for more details: [https://www.i2p.net/en/docs/how/tunnel-routing](https://www.i2p.net/en/docs/how/tunnel-routing)

Associated structes/protocols:

- [Tunnel Messages](https://geti2p.net/spec/tunnel-message)
- [Tunnel Creation](https://geti2p.net/spec/tunnel-creation)

