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

#include <iostream>

#include <catch2/catch.hpp>

#include "src/ntcp2/session/session.h"
#include "src/ntcp2/session/listener.h"
#include "src/ntcp2/session/manager.h"

namespace crypto = tini2p::crypto;

using Info = tini2p::data::Info;
using SessionManager = tini2p::ntcp2::SessionManager;
using init_session_t = SessionManager::out_session_t;
using resp_session_t = SessionManager::listener_t::session_t;

struct SessionFixture
{
  SessionFixture()
      : host(resp_session_t::tcp_t::v4(), crypto::RandInRange(9111, 10135)),
        host_v6(resp_session_t::tcp_t::v6(), crypto::RandInRange(9111, 10135)),
        dest(new Info(
            Info::identity_t(),
            Info::addresses_t{
                Info::address_t(host.address().to_string(), host.port()),
                Info::address_t(
                    host_v6.address().to_string(),
                    host_v6.port())})),
        info(new Info()),
        manager(dest, host, host_v6)
  {
    msg.add_block(tini2p::data::PaddingBlock(32));
  }

  ~SessionFixture()
  {
    REQUIRE_NOTHROW(manager.Stop());
  }

  resp_session_t::tcp_t::endpoint host, host_v6;
  Info::shared_ptr dest, info;
  SessionManager manager;
  resp_session_t::data_msg_t msg;
};

TEST_CASE_METHOD(
    SessionFixture,
    "Manager Session writes and reads after successful connection",
    "[session]")
{
  auto mgr_init = manager.session(dest);

  REQUIRE(mgr_init);
  REQUIRE_NOTHROW(mgr_init->Start(init_session_t::meta_t::IP::v6));
  REQUIRE_NOTHROW(mgr_init->Wait());
  REQUIRE(mgr_init->ready());

  auto remote_v6 = manager.listener(init_session_t::meta_t::IP::v6)
                       ->session(mgr_init->key());

  REQUIRE(remote_v6);
  REQUIRE_NOTHROW(remote_v6->Wait());
  REQUIRE(remote_v6->ready());

  REQUIRE_NOTHROW(mgr_init->Write(msg));
  REQUIRE_NOTHROW(remote_v6->Read(msg));

  REQUIRE_NOTHROW(remote_v6->Write(msg));
  REQUIRE_NOTHROW(mgr_init->Read(msg));

  REQUIRE_NOTHROW(mgr_init->Stop());
}

TEST_CASE_METHOD(
    SessionFixture,
    "SessionManager rejects null RouterInfo for outbound sessions",
    "[session]")
{
  REQUIRE_THROWS(manager.session(nullptr));
}

TEST_CASE_METHOD(
    SessionFixture,
    "Session rejects reading/writing data phase messages w/o valid handshake",
    "[session]")
{

  init_session_t init(dest, info);
  REQUIRE(!init.ready());
  REQUIRE_THROWS(init.Write(msg));
  REQUIRE_THROWS(init.Read(msg));

  resp_session_t::context_t ctx;
  resp_session_t resp(
      dest, resp_session_t::tcp_t::socket(ctx, resp_session_t::tcp_t::v6()));

  REQUIRE(!resp.ready());
  REQUIRE_THROWS(resp.Write(msg));
  REQUIRE_THROWS(resp.Read(msg));
}

TEST_CASE_METHOD(
    SessionFixture,
    "SessionManager rejects new connection for already existing session",
    "[session]")
{
  auto s0 = manager.session(dest);

  REQUIRE(s0);
  REQUIRE_NOTHROW(s0->Start(init_session_t::meta_t::IP::v6));

  REQUIRE_THROWS(manager.session(dest));
  REQUIRE_NOTHROW(
      init_session_t(dest, info).Start(init_session_t::meta_t::IP::v6));

  REQUIRE(manager.blacklisted(s0->key()));
}
