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

namespace ntcp2
{
class SessionListener
{
  ntcp2::router::Info* info_;
  boost::asio::ip::tcp::acceptor acc_;
  std::vector<std::unique_ptr<ntcp2::Session<ntcp2::SessionResponder>>>
      sessions_;
  std::unique_ptr<std::thread> thread_;

 public:
  SessionListener(
      const decltype(info_) info,
      const boost::asio::ip::tcp::endpoint& host,
      boost::asio::io_context& ctx)
      : info_(info), acc_(ctx, host, true)
  {
    acc_.listen();
  }

  ~SessionListener()
  {
    Stop();
  }

  void Start()
  {
    const auto func = __func__;
    acc_.async_accept([this, func](
                          const boost::system::error_code& ec,
                          boost::asio::ip::tcp::socket socket) {
      if (ec)
        ntcp2::exception::Exception{"SessionListener", __func__}
            .throw_ex<std::runtime_error>(ec.message().c_str());

      sessions_.emplace_back(
          std::make_unique<ntcp2::Session<ntcp2::SessionResponder>>(
              info_, std::move(socket)));

      sessions_.back()->Start();
    });

    Run();
  }

  void Run()
  {
    thread_ = std::make_unique<std::thread>([=]() {
      try
        {
          acc_.get_io_service().run();
        }
      catch (const std::exception& ex)
        {
          std::cerr << "SessionListener: " << ex.what() << std::endl;
          Stop();
        }
    });
  }

  void Stop()
  {
    try
      {
        for (const auto& session : sessions_)
          session->Stop();

        sessions_.clear();

        acc_.get_io_service().stop();

        if (thread_)
          {
            thread_->join();
            thread_.reset(nullptr);
          }
      }
    catch (const std::exception& ex)
      {
        std::cerr << "SessionListener: " << __func__ << ": " << ex.what()
                  << std::endl;
      }
  }
};
}  // namespace ntcp2

struct SessionFixture
{
  SessionFixture()
      : init_ctx(),
        resp_ctx(),
        host(
            boost::asio::ip::tcp::v4(),
            ntcp2::crypto::RandInRange<std::uint16_t>(9111, 10135)),
        dest(new ntcp2::router::Info(
            std::make_unique<ntcp2::router::Identity>(),
            std::vector<ntcp2::router::Address>{ntcp2::router::Address(
                host.address().to_string(),
                host.port())})),
        info(new ntcp2::router::Info()),
        init(dest.get(), info.get(), init_ctx),
        resp(dest.get(), host, resp_ctx)
  {
  }

  boost::asio::io_context init_ctx, resp_ctx;
  boost::asio::ip::tcp::endpoint host;
  std::unique_ptr<ntcp2::router::Info> dest, info;
  ntcp2::Session<ntcp2::SessionInitiator> init;
  ntcp2::SessionListener resp;
};

TEST_CASE_METHOD(
    SessionFixture,
    "Session creates a connection to a destination",
    "[session]")
{
  REQUIRE_NOTHROW(resp.Start());
  REQUIRE_NOTHROW(init.Start());

  REQUIRE_NOTHROW(init.Wait());

  REQUIRE(init.ready());
}

TEST_CASE_METHOD(
    SessionFixture,
    "Session rejects reading/writing data phase messages w/o valid handshake",
    "[session]")
{
  ntcp2::DataPhaseMessage msg;

  REQUIRE(!init.ready());
  REQUIRE_THROWS(init.Write({}));
  REQUIRE_THROWS(init.Read(msg));

  boost::asio::io_context ctx;
  ntcp2::Session<ntcp2::SessionResponder> resp(
      dest.get(),
      boost::asio::ip::tcp::socket(ctx, boost::asio::ip::tcp::v6()));

  REQUIRE(!resp.ready());
  REQUIRE_THROWS(resp.Write({}));
  REQUIRE_THROWS(resp.Read(msg));
}
