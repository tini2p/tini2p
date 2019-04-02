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
*/

#include <catch2/catch.hpp>

#include "src/data/router/lease_set.h"

/*--------------------------------------------\
| LeaseSet Header tests                       |
\--------------------------------------------*/
using LeaseSetHeader = tini2p::data::LeaseSetHeader;

struct LeaseSetHeaderFixture
{
  LeaseSetHeader ls_header;
};

TEST_CASE_METHOD(LeaseSetHeaderFixture, "LeaseSetHeader has valid fields", "[ls]")
{
  REQUIRE(ls_header.ts() + ls_header.expires() == tini2p::time::now_s() + LeaseSetHeader::Timeout);

  const auto flags = tini2p::under_cast(ls_header.flags());
  const auto online_keys_f = tini2p::under_cast(LeaseSetHeader::Flag::OnlineKeys);
  const auto published_f = tini2p::under_cast(LeaseSetHeader::Flag::Published);

  REQUIRE((flags & online_keys_f) == online_keys_f);
  REQUIRE((flags >> 1 | published_f) == published_f);
}

TEST_CASE_METHOD(LeaseSetHeaderFixture, "LeaseSetHeader serializes + signs with initializing ctor", "[ls]")
{
  REQUIRE_NOTHROW(LeaseSetHeader(std::make_unique<LeaseSetHeader::destination_t>()));
  REQUIRE(LeaseSetHeader(std::make_unique<LeaseSetHeader::destination_t>()).Verify());
}

TEST_CASE_METHOD(LeaseSetHeaderFixture, "LeaseSetHeader deserializes from a buffer + verifies", "[ls]")
{
  std::unique_ptr<LeaseSetHeader> ls_ptr;
  REQUIRE_NOTHROW(ls_ptr.reset(new LeaseSetHeader(std::make_unique<LeaseSetHeader::destination_t>())));

  bool valid(false);
  REQUIRE_NOTHROW(valid = LeaseSetHeader(ls_ptr->buffer()).Verify());
  REQUIRE(valid);
}

/*--------------------------------------------\
| Key Section tests                           |
\--------------------------------------------*/
using KeySection = tini2p::data::KeySection;

struct KeySectionFixture
{
  KeySection ks;
};

TEST_CASE_METHOD(KeySectionFixture, "KeySection has valid fields", "[ls]")
{
  REQUIRE(ks.type == KeySection::Type::X25519Blake);
  REQUIRE(ks.key_len == tini2p::crypto::X25519::PublicKeyLen);
  boost::apply_visitor([](const auto& k) { REQUIRE(k.size() == tini2p::crypto::X25519::PublicKeyLen); }, ks.key);
}

TEST_CASE_METHOD(KeySectionFixture, "KeySection serializes to a buffer", "[ls]")
{
  REQUIRE_NOTHROW(ks.serialize());
}

TEST_CASE_METHOD(KeySectionFixture, "KeySection deserializes from buffer", "[ls]")
{
  REQUIRE_NOTHROW(KeySection(ks.buffer.data(), ks.buffer.size()));
}

TEST_CASE_METHOD(KeySectionFixture, "KeySection rejects null buffer", "[ls]")
{
  REQUIRE_THROWS(KeySection(nullptr, ks.buffer.size()));
  REQUIRE_THROWS(KeySection(ks.buffer.data(), 0));
}

/*--------------------------------------------\
| Lease tests                                 |
\--------------------------------------------*/
using Lease = tini2p::data::Lease;

struct LeaseFixture
{
  Lease l;
};

TEST_CASE_METHOD(LeaseFixture, "Lease has valid fields", "[ls]")
{
  REQUIRE(l.tunnel_gw.size() == LeaseSetHeader::destination_t::hash_t().size());
  REQUIRE(l.tunnel_id == 0);  // default tunnel ID
  REQUIRE(l.expiration >= tini2p::time::now_s() + Lease::Timeout);
}

TEST_CASE_METHOD(LeaseFixture, "Lease serializes to a buffer", "[ls]")
{
  REQUIRE_NOTHROW(l.serialize());
}

TEST_CASE_METHOD(LeaseFixture, "Lease deserializes from buffer", "[ls]")
{
  REQUIRE_NOTHROW(Lease(l.buffer.data(), l.buffer.size()));
}

TEST_CASE_METHOD(LeaseFixture, "Lease rejects null buffer", "[ls]")
{
  REQUIRE_THROWS(Lease(nullptr, l.buffer.size()));
  REQUIRE_THROWS(Lease(l.buffer.data(), 0));
}

/*--------------------------------------------\
| LeaseSet tests                              |
\--------------------------------------------*/
using LeaseSet = tini2p::data::LeaseSet;

struct LeaseSetFixture
{
  LeaseSet ls;
};

TEST_CASE_METHOD(LeaseSetFixture, "LeaseSet has valid fields", "[ls]")
{
  REQUIRE_NOTHROW(ls.properties());
  REQUIRE(ls.key_sections().size() * KeySection::MinLen == ls.key_sections_len());
  REQUIRE(ls.leases().size() * LeaseSet::lease_t::Len == ls.leases_len());
}

TEST_CASE_METHOD(LeaseSetFixture, "LeaseSet serializes to a buffer", "[ls]")
{
  REQUIRE_NOTHROW(ls.serialize());
  REQUIRE_NOTHROW(ls.deserialize());
}

TEST_CASE_METHOD(LeaseSetFixture, "LeaseSet deserializes from buffer", "[ls]")
{
  REQUIRE_NOTHROW(LeaseSet(ls.buffer().data(), ls.buffer().size()));
}

TEST_CASE_METHOD(LeaseSetFixture, "LeaseSet rejects null buffer", "[ls]")
{
  REQUIRE_THROWS(LeaseSet(nullptr, ls.buffer().size()));
  REQUIRE_THROWS(LeaseSet(ls.buffer().data(), 0));
}

TEST_CASE_METHOD(LeaseSetFixture, "LeaseSet rejects invalid KeySection", "[ls]")
{
  REQUIRE_NOTHROW(ls.serialize());

  tini2p::BytesWriter<LeaseSet::buffer_t> writer(ls.buffer());
  // skip to first key section key length offset
  writer.skip_bytes(ls.properties().size() + LeaseSet::KeySectionNumLen + KeySection::TypeLen);

  writer.write_bytes(KeySection::MinKeyLen - 1);  // invalidate the key length (lower)
  REQUIRE_THROWS(ls.deserialize());

  writer.skip_back(KeySection::SizeLen);
  writer.write_bytes(KeySection::MaxKeyLen + 1);  // invalidate the key length (upper)
  REQUIRE_THROWS(ls.deserialize());
}

TEST_CASE_METHOD(LeaseSetFixture, "LeaseSet has valid signature", "[ls]")
{
  REQUIRE(ls.Verify());
}

// TODO(tini2p): implement and test blinded signing
