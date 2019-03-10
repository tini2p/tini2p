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
namespace meta = tini2p::meta::ntcp2::session;

using namespace tini2p::ntcp2;

struct SessionFixture
{
  SessionFixture()
      : host(
            boost::asio::ip::tcp::v4(),
            static_cast<std::uint16_t>(crypto::RandInRange(9111, 10135))),
        host_v6(
            boost::asio::ip::tcp::v6(),
            static_cast<std::uint16_t>(crypto::RandInRange(9111, 10135))),
        dest(new tini2p::data::Info(
            tini2p::data::Identity(),
            std::vector<tini2p::data::Address>{
                tini2p::data::Address(host.address().to_string(), host.port()),
                tini2p::data::Address(
                    host_v6.address().to_string(),
                    host_v6.port())})),
        info(new tini2p::data::Info()),
        manager(dest.get(), host, host_v6),
        init(dest.get(), info.get())
  {
    using BlockPtr = std::unique_ptr<tini2p::data::Block>;

    msg.blocks.emplace_back(BlockPtr(new tini2p::data::PaddingBlock(3)));

    // give session listeners time to start before sending requests
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  ~SessionFixture()
  {
    REQUIRE_NOTHROW(init.Stop());
    REQUIRE_NOTHROW(manager.Stop());

    // wait while all sessions + listeners shut down
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  void InitializeSession(const meta::IP_t proto)
  {
    REQUIRE_NOTHROW(init.Start(proto));
    REQUIRE_NOTHROW(init.Wait());
    REQUIRE(init.ready());

    REQUIRE_NOTHROW(
        remote = manager.listener(proto)->session(info->id_keys().pubkey));
  }

  boost::asio::ip::tcp::endpoint host, host_v6;
  std::unique_ptr<tini2p::data::Info> dest, info;
  Session<Initiator> init;
  Session<Responder>* remote;
  SessionManager manager;
  DataPhaseMessage msg;
};

TEST_CASE_METHOD(
    SessionFixture,
    "IPv4 Session writes and reads after successful connection",
    "[session]")
{
  InitializeSession(meta::IP_t::v4);

  REQUIRE(remote);

  REQUIRE_NOTHROW(init.Write(msg));
  REQUIRE_NOTHROW(remote->Read(msg));

  REQUIRE_NOTHROW(remote->Write(msg));
  REQUIRE_NOTHROW(init.Read(msg));
}

TEST_CASE_METHOD(
    SessionFixture,
    "IPv6 Session writes and reads after successful connection",
    "[session]")
{
  InitializeSession(meta::IP_t::v6);

  REQUIRE_NOTHROW(init.Write(msg));
  REQUIRE_NOTHROW(remote->Read(msg));

  REQUIRE_NOTHROW(remote->Write(msg));
  REQUIRE_NOTHROW(init.Read(msg));
}

TEST_CASE_METHOD(
    SessionFixture,
    "Manager Session writes and reads after successful connection",
    "[session]")
{
  auto* mgr_init = manager.session(dest.get());

  REQUIRE(mgr_init);
  REQUIRE_NOTHROW(mgr_init->Start(meta::IP_t::v6));
  REQUIRE_NOTHROW(mgr_init->Wait());
  REQUIRE(mgr_init->ready());

  auto* remote_v6 =
      manager.listener(meta::IP_t::v6)->session(dest->id_keys().pubkey);

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
    "SessionManager rejects multiple sessions to same destination",
    "[session]")
{
  REQUIRE_NOTHROW(manager.session(dest.get()));

  REQUIRE_THROWS(manager.session(dest.get()));
}

TEST_CASE_METHOD(
    SessionFixture,
    "Session rejects reading/writing data phase messages w/o valid handshake",
    "[session]")
{
  REQUIRE(!init.ready());
  REQUIRE_THROWS(init.Write(msg));
  REQUIRE_THROWS(init.Read(msg));

  boost::asio::io_context ctx;
  Session<Responder> resp(
      dest.get(),
      boost::asio::ip::tcp::socket(ctx, boost::asio::ip::tcp::v6()));

  REQUIRE(!resp.ready());
  REQUIRE_THROWS(resp.Write(msg));
  REQUIRE_THROWS(resp.Read(msg));
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
    "SessionManager rejects new connection for already existing session",
    "[session]")
{
  Session<Initiator> s0(dest.get(), info.get()), s1(dest.get(), info.get());

  REQUIRE_NOTHROW(s0.Start(meta::IP_t::v6));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  REQUIRE_NOTHROW(s1.Start(meta::IP_t::v6));
  REQUIRE_NOTHROW(s1.Stop());
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  REQUIRE(manager.blacklisted(s0.connect_key()));
}
