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

#ifndef SRC_NTCP2_SESSION_SESSION_H_
#define SRC_NTCP2_SESSION_SESSION_H_

#include <boost/asio.hpp>

#include "src/ntcp2/router/info.h"
#include "src/ntcp2/noise.h"

#include "src/ntcp2/session_request/session_request.h"
#include "src/ntcp2/session_created/session_created.h"
#include "src/ntcp2/session_confirmed/session_confirmed.h"
#include "src/ntcp2/data_phase/data_phase.h"

namespace ntcp2
{
/// @class Session
/// @tparam SessionRole Noise role for the first data phase message
/// @detail On first data phase message, session initiator will be responder, vice versa
template <class SessionRole>
class Session
{
  NoiseHandshakeState* state_;
  router::Info *dest_, *info_;
  boost::asio::ip::tcp::endpoint remote_host_;
  crypto::pk::X25519 remote_key_;
  crypto::aes::IV aes_iv_;
  boost::asio::ip::tcp::socket sock_;
  std::unique_ptr<ntcp2::SessionRequestMessage> srq_msg_;
  std::unique_ptr<ntcp2::SessionCreatedMessage> scr_msg_;
  std::unique_ptr<ntcp2::SessionConfirmedMessage> sco_msg_;
  std::unique_ptr<ntcp2::DataPhaseMessage> dp_msg_;
  std::unique_ptr<ntcp2::DataPhase<SessionRole>> dp_;
  std::size_t srq_xfer_, scr_xfer_, sco_xfer_, dp_xfer_;
  std::condition_variable cv_;
  bool ready_;
  std::mutex ready_mutex_;
  std::mutex msg_mutex_;
  std::unique_ptr<std::thread> thread_;

 public:
  /// @brief Create a session for a destination
  /// @param dest RouterInfo for remote destination
  /// @param info RouterInfo for local router
  /// @param ctx IO context for sockets
  Session(
      decltype(dest_) dest,
      decltype(info_) info,
      boost::asio::io_context& ctx)
      : dest_(dest),
        info_(info),
        sock_(ctx),
        sco_msg_(new ntcp2::SessionConfirmedMessage(
            info_,
            crypto::RandInRange(
                meta::session_confirmed::MinPaddingSize,
                meta::session_confirmed::MaxPaddingSize))),
        ready_(false)
  {
    noise::init_handshake<ntcp2::Initiator>(&state_, {"Session", __func__});

    const auto& b64_key = dest_->options().entry(std::string("s"));
    remote_key_.Assign(
        crypto::Base64::Decode(
            reinterpret_cast<const char*>(b64_key.data()), b64_key.size())
            .data(),
        remote_key_.size());

    const auto& b64_iv = dest_->options().entry(std::string("i"));
    aes_iv_.Assign(
        crypto::Base64::Decode(
            reinterpret_cast<const char*>(b64_iv.data()), b64_iv.size())
            .data(),
        aes_iv_.size());
  }

  /// @brief Create a session for an incoming connection
  /// @param dest RouterInfo for remote destination
  /// @param info RouterInfo for local router
  Session(decltype(info_) info, boost::asio::ip::tcp::socket socket)
      : info_(info),
        sock_(std::move(socket)),
        ready_(false)
  {
    noise::init_handshake<ntcp2::Responder>(&state_, {"Session", __func__});

    const auto& b64_iv = info_->options().entry(std::string("i"));
    aes_iv_.Assign(
        crypto::Base64::Decode(
            reinterpret_cast<const char*>(b64_iv.data()), b64_iv.size())
            .data(),
        aes_iv_.size());
  }

  ~Session()
  {
    Stop();
  }

  /// @brief Get a non-const reference to the socket
  /// @return Reference to session socket
  decltype(sock_)& socket() noexcept
  {
    return sock_;
  }

  /// @brief Get if session is ready for processing data phase messages
  /// @return Session ready status
  bool ready() const noexcept
  {
    return ready_;
  }

  /// @brief Start the NTCP2 session
  void Start()
  {
    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      Connect();
    else
      HandleSessionRequest();
  }

  void Run()
  {
    thread_ = std::make_unique<std::thread>([=]() {
      try
        {
          sock_.get_executor().context().run();
        }
      catch (const std::exception& ex)
        {
          std::cerr << "Session: " << __func__ << ": " << ex.what() << std::endl;
          Stop();
        }
    });
  }

  void Wait()
  {
    std::unique_lock<std::mutex> l(ready_mutex_);
    // if(!cv_.wait_for(l, std::chrono::seconds(3), [=]() { return ready_; }))
    if(!cv_.wait_for(l, std::chrono::seconds(100), [=]() { return ready_; }))
      {
        l.unlock();
        exception::Exception{"Session", __func__}.throw_ex<std::runtime_error>(
            "handshake timed out.");
      }
    l.unlock();
    cv_.notify_all();
  }

  void Stop()
  {
    try
      {
        sock_.get_executor().context().stop();
        sock_.close();
        if (thread_)
          {
            thread_->join();
            thread_.reset(nullptr);
          }
      }
    catch (const std::exception& ex)
      {
        std::cerr << "Session: " << __func__ << ": " << ex.what() << std::endl;
      }
  }

  /// @brief Write a data phase message
  /// @param message Data phase message to write
  void Write(const ntcp2::DataPhaseMessage& message)
  {
    const exception::Exception ex{"Session", __func__};
    if (!ready_)
      ex.throw_ex<std::runtime_error>("session not ready for data phase.");

    ex.throw_ex<std::runtime_error>("unimplemented");
  }

  /// @brief Read a data phase message
  /// @param message Data phase message to store read results
  void Read(ntcp2::DataPhaseMessage& message)
  {
    const exception::Exception ex{"Session", __func__};
    if (!ready_)
      ex.throw_ex<std::runtime_error>("session not ready for data phase.");

    ex.throw_ex<std::runtime_error>("unimplemented");
  }

 private:
  void Connect()
  {
    boost::system::error_code ec;
    remote_host_ = dest_->host();

    const exception::Exception ex{"Session", __func__};

    sock_.open(remote_host_.protocol());
    sock_.set_option(boost::asio::ip::tcp::socket::reuse_address(true));
    sock_.bind(boost::asio::ip::tcp::endpoint(remote_host_.protocol(), 0), ec);
    if (ec)
      ex.throw_ex<std::runtime_error>(ec.message().c_str());

    sock_.async_connect(
        remote_host_, [this, ex](const boost::system::error_code& ec) {
          if (ec)
            ex.throw_ex<std::runtime_error>(ec.message().c_str());

          HandleSessionRequest();
        });

    Run();
  }

  void HandleSessionRequest()
  {
    if (std::is_same<SessionRole, ntcp2::SessionResponder>::value)
      {
        const auto func = __func__;
        sock_.async_wait(
            boost::asio::ip::tcp::socket::wait_read,
            [this, func](const boost::system::error_code& ec) {
              if (ec)
                exception::Exception{"Session", func}
                    .throw_ex<std::runtime_error>(ec.message().c_str());

              DoSessionRequest();
            });
       }
    else
      DoSessionRequest();
  }

  void DoSessionRequest()
  {
    namespace meta = ntcp2::meta::session_request;

    const exception::Exception ex{"Session", __func__};

    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      {
        ntcp2::SessionRequest<ntcp2::Initiator> srq(
            state_, dest_->identity().hash(), aes_iv_);

        srq.kdf().set_local_keys(info_->noise_keys());
        srq.kdf().derive_keys(remote_key_);

        std::lock_guard<std::mutex> lg(msg_mutex_);
        srq_msg_ = std::make_unique<ntcp2::SessionRequestMessage>(
            sco_msg_->payload_size(),
            crypto::RandInRange(meta::MinPaddingSize, meta::MaxPaddingSize));

        srq.ProcessMessage(*srq_msg_);
        boost::asio::async_write(
            sock_,
            boost::asio::buffer(srq_msg_->data),
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              srq_xfer_ += bytes_transferred;
              return srq_msg_->data.size() - srq_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              HandleSessionCreated();
            });
      }
    else
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        srq_msg_ = std::make_unique<ntcp2::SessionRequestMessage>();
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(srq_msg_->data),
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              srq_xfer_ += bytes_transferred;
              return meta::NoisePayloadSize - srq_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              ntcp2::SessionRequest<ntcp2::Responder> srq(
                  state_, info_->identity().hash(), aes_iv_);

              srq.kdf().set_local_keys(info_->noise_keys());
              srq.kdf().derive_keys();

              srq.ProcessMessage(*srq_msg_);

              if (srq_msg_->options.pad_len)
                {
                  srq_xfer_ = 0;
                  srq_msg_->padding.resize(srq_msg_->options.pad_len);
                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(srq_msg_->padding),
                      [this, ex](
                          const boost::system::error_code& ec,
                          const std::size_t bytes_transferred) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        srq_xfer_ += bytes_transferred;
                        return srq_msg_->padding.size() - srq_xfer_;
                      },
                      [this, ex](
                          const boost::system::error_code& ec,
                          const std::size_t bytes_transferred) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        HandleSessionCreated();
                      });
                }
              else
                HandleSessionCreated();
            });
      }
  }

  void HandleSessionCreated()
  {
    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      {
        const auto func = __func__;
        sock_.async_wait(
            boost::asio::ip::tcp::socket::wait_read,
            [this, func](const boost::system::error_code& ec) {
              if (ec && ec != boost::asio::error::eof)
                exception::Exception{"Session", func}
                    .throw_ex<std::runtime_error>(ec.message().c_str());

              DoSessionCreated();
            });
      }
    else
      DoSessionCreated();
  }

  void DoSessionCreated()
  {
    namespace meta = ntcp2::meta::session_created;

    const exception::Exception ex{"Session", __func__};

    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        scr_msg_ = std::make_unique<ntcp2::SessionCreatedMessage>();
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(scr_msg_->data, meta::NoisePayloadSize),
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

                scr_xfer_ += bytes_transferred;
                return meta::NoisePayloadSize - scr_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              ntcp2::SessionCreated<ntcp2::Responder> scr(
                  state_, *srq_msg_, dest_->identity().hash(), aes_iv_);

              scr.ProcessMessage(*scr_msg_);
              if (scr_msg_->options.pad_len)
                {
                  scr_xfer_ = 0;
                  scr_msg_->padding.resize(scr_msg_->options.pad_len);
                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(scr_msg_->padding),
                      [this, ex](
                          const boost::system::error_code& ec,
                          const std::size_t bytes_transferred) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        scr_xfer_ += bytes_transferred;
                        return scr_msg_->padding.size() - scr_xfer_;
                      },
                      [this, ex](
                          const boost::system::error_code& ec,
                          const std::size_t bytes_transferred) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        HandleSessionConfirmed();
                      });
                }
              else
                ex.throw_ex<std::length_error>("null padding length.");
            });
      }
    else
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        scr_msg_ = std::make_unique<ntcp2::SessionCreatedMessage>();

        ntcp2::SessionCreated<ntcp2::Initiator> scr(
            state_, *srq_msg_, info_->identity().hash(), aes_iv_);

        scr.ProcessMessage(*scr_msg_);
        boost::asio::async_write(
            sock_,
            boost::asio::buffer(scr_msg_->data),
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              scr_xfer_ += bytes_transferred;
              return scr_msg_->data.size() - scr_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              HandleSessionConfirmed();
            });
      }
  }

  void HandleSessionConfirmed()
  {
    if (std::is_same<SessionRole, ntcp2::SessionResponder>::value)
      {
        const auto func = __func__;
        sock_.async_wait(
            boost::asio::ip::tcp::socket::wait_read,
            [this, func](const boost::system::error_code& ec) {
              if (ec && ec != boost::asio::error::eof)
                exception::Exception{"Session", func}
                    .throw_ex<std::runtime_error>(ec.message().c_str());

              DoSessionConfirmed();
            });
      }
    else
      DoSessionConfirmed();
  }

  void DoSessionConfirmed()
  {
    const exception::Exception ex{"Session", __func__};

    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        ntcp2::SessionConfirmed<ntcp2::Initiator> sco(state_, *scr_msg_);

        sco.ProcessMessage(*sco_msg_, srq_msg_->options);

        boost::asio::async_write(
            sock_,
            boost::asio::buffer(sco_msg_->data),
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              sco_xfer_ += bytes_transferred;
              return sco_msg_->data.size() - sco_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              HandleDataPhase();
            });
      }
    else
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        sco_msg_ = std::make_unique<ntcp2::SessionConfirmedMessage>(
            meta::session_confirmed::PartOneSize + srq_msg_->options.m3p2_len);

        boost::asio::async_read(
            sock_,
            boost::asio::buffer(sco_msg_->data),
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              sco_xfer_ += bytes_transferred;
              return sco_msg_->data.size() - sco_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              ntcp2::SessionConfirmed<ntcp2::Responder> sco(state_, *scr_msg_);

              sco.ProcessMessage(*sco_msg_, srq_msg_->options);

              HandleDataPhase();
            });
      }
  }

  void HandleDataPhase()
  {
    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      {
        const auto func = __func__;
        sock_.async_wait(
            boost::asio::ip::tcp::socket::wait_read,
            [this, func](const boost::system::error_code& ec) {
              if (ec && ec != boost::asio::error::eof)
                exception::Exception{"Session", func}
                    .throw_ex<std::runtime_error>(ec.message().c_str());

              DoDataPhase();
            });
      }
    else
      DoDataPhase();

  }

  void DoDataPhase()
  {
    const exception::Exception ex{"Session", __func__};
    if (std::is_same<SessionRole, ntcp2::SessionInitiator>::value)
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        dp_msg_ = std::make_unique<ntcp2::DataPhaseMessage>();
        dp_msg_->buffer.resize(meta::data_phase::MaxSize);

        // read message length from the socket
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(dp_msg_->buffer, meta::data_phase::SizeSize),
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_xfer_ += bytes_transferred;
              return meta::data_phase::SizeSize - dp_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_ = std::make_unique<ntcp2::DataPhase<SessionRole>>(state_);

              boost::endian::big_uint16_t obfs_len, len;
              ntcp2::read_bytes(dp_msg_->buffer.data(), obfs_len);

              dp_->kdf().ProcessLength(obfs_len, meta::data_phase::BobToAlice);

              if(obfs_len)
                {
                  dp_xfer_ = 0;
                  // read remaing message bytes
                  dp_msg_->buffer.resize(meta::data_phase::SizeSize + obfs_len);
                  auto* data = &dp_msg_->buffer[meta::data_phase::SizeSize];
                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(data, obfs_len),
                      [this, ex, obfs_len](
                          const boost::system::error_code& ec,
                          std::size_t bytes_transferred) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        dp_xfer_ += bytes_transferred;
                        return obfs_len - dp_xfer_;
                      },
                      [this, ex, obfs_len](
                          const boost::system::error_code& ec,
                          std::size_t bytes_transferred) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        // write deobfuscated length back to message
                        ntcp2::write_bytes(dp_msg_->buffer.data(), obfs_len);
                        dp_->ReadMessage(*dp_msg_, false /*deobfs len*/);

                        for (const auto& block : dp_msg_->blocks)
                          if (block->type() == meta::block::RouterInfoID)
                            if (reinterpret_cast<ntcp2::RouterInfoBlock*>(
                                    block.get())
                                    ->info()
                                    .options()
                                    .entry(std::string("s"))
                                != dest_->options().entry(std::string("s")))
                              ex.throw_ex<std::logic_error>(
                                  "invalid static key.");

                        {
                          std::lock_guard<std::mutex> l(ready_mutex_);
                          ready_ = true;
                        }
                        cv_.notify_all();
                      });
                }
            });
      }
    else
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        dp_ = std::make_unique<ntcp2::DataPhase<SessionRole>>(state_);

        dp_msg_ = std::make_unique<ntcp2::DataPhaseMessage>();
        dp_msg_->blocks.emplace_back(
            std::unique_ptr<ntcp2::Block>(new ntcp2::RouterInfoBlock(info_)));

        dp_->WriteMessage(*dp_msg_);

        boost::asio::async_write(
            sock_,
            boost::asio::buffer(dp_msg_->buffer),
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_xfer_ += bytes_transferred;
              return dp_msg_->buffer.size() - dp_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              {
                std::lock_guard<std::mutex> l(ready_mutex_);
                ready_ = true;
              }
              cv_.notify_all();
            });
      }
  }
};
}  // namespace ntcp2

#endif  // SRC_NTCP2_SESSION_SESSION_H_
