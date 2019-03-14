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

#include "src/data/router/info.h"

#include "src/ntcp2/noise.h"

#include "src/ntcp2/session_request/session_request.h"
#include "src/ntcp2/session_created/session_created.h"
#include "src/ntcp2/session_confirmed/session_confirmed.h"
#include "src/ntcp2/data_phase/data_phase.h"

#include "src/ntcp2/session/meta.h"
#include "src/ntcp2/session/key.h"

namespace tini2p
{
namespace ntcp2
{
/// @class Session
/// @tparam TRole Noise role for the first data phase message
/// @detail On first data phase message, session initiator will be responder, vice versa
template <class TRole>
class Session
{
 public:
  using state_t = NoiseHandshakeState;  //< Handshake state alias
  using info_ptr = data::Info::shared_ptr;  //< RouterInfo trait alias
  using dest_ptr = data::Info::shared_ptr;  //< Destination trait alias
  using obfse_t = crypto::AES;  //< Obfse crypto trait alias
  using key_t = SessionKey;  //< Key trait alias

  /// @alias created_impl_t
  /// @brief SessionRequest implementation trait
  using request_impl_t = std::conditional_t<
      std::is_same<TRole, Initiator>::value,
      SessionRequest<Initiator>,
      SessionRequest<Responder>>;

  /// @alias created_impl_t
  /// @brief SessionCreated implementation trait
  using created_impl_t = std::conditional_t<
      std::is_same<TRole, Initiator>::value,
      SessionCreated<Responder>,
      SessionCreated<Initiator>>;

  /// @alias confirmed_impl_t
  /// @brief SessionConfirmed implementation trait
  using confirmed_impl_t = std::conditional_t<
      std::is_same<TRole, Initiator>::value,
      SessionConfirmed<Initiator>,
      SessionConfirmed<Responder>>;

  /// @alias data_impl_t
  /// @brief DataPhase implementation trait
  using data_impl_t = std::conditional_t<
      std::is_same<TRole, Initiator>::value,
      DataPhase<Responder>,
      DataPhase<Initiator>>;

  using request_msg_t = typename request_impl_t::message_t;  //< SessionRequest message trait alias
  using created_msg_t = typename created_impl_t::message_t;  //< SessionCreated message trait alias
  using confirmed_msg_t = typename confirmed_impl_t::message_t;  //< SessionConfirmed message trait alias
  using data_msg_t = typename data_impl_t::message_t;  //< DataPhase message trait alias

  using context_t = boost::asio::io_context;  //< ASIO context trait alias
  using socket_t = boost::asio::ip::tcp::socket;  //< Socket trait alias
  using endpoint_t = boost::asio::ip::tcp::endpoint;  //< Endpoint trait alias

  /// @brief Create a session for a destination
  /// @param dest RouterInfo for remote destination
  /// @param info RouterInfo for local router
  Session(dest_ptr dest, info_ptr info)
      : dest_(dest),
        info_(info),
        ctx_(),
        sock_(ctx_),
        sco_msg_(new confirmed_msg_t(
            info_,
            crypto::RandInRange(
                confirmed_msg_t::MinPaddingSize,
                confirmed_msg_t::MaxPaddingSize))),
        ready_(false)
  {
    const exception::Exception ex{"Session", __func__};

    if (!dest || !info)
      ex.throw_ex<std::invalid_argument>("null remote or local RouterInfo.");

    noise::init_handshake<Initiator>(&state_, ex);

    const auto& b64_key = dest_->options().entry(std::string("s"));
    std::copy_n(
        crypto::Base64::Decode(
            reinterpret_cast<const char*>(b64_key.data()), b64_key.size())
            .data(),
        remote_key_.key.size(),
        remote_key_.key.data());

    const auto& b64_iv = dest_->options().entry(std::string("i"));
    std::copy_n(
        crypto::Base64::Decode(
            reinterpret_cast<const char*>(b64_iv.data()), b64_iv.size())
            .data(),
        aes_iv_.size(),
        aes_iv_.data());
  }

  /// @brief Create a session for an incoming connection
  /// @param dest RouterInfo for remote destination
  /// @param info RouterInfo for local router
  Session(info_ptr info, socket_t socket)
      : info_(info),
        sock_(std::move(socket)),
        ready_(false)
  {
    const exception::Exception ex{"Session", __func__};

    if (!info)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    noise::init_handshake<Responder>(&state_, ex);

    const auto& b64_iv = info_->options().entry(std::string("i"));
    std::copy_n(
        crypto::Base64::Decode(
            reinterpret_cast<const char*>(b64_iv.data()), b64_iv.size())
            .data(),
        aes_iv_.size(),
        aes_iv_.data());
  }

  ~Session()
  {
    Stop();
    sock_.close();
    noise::free_handshake(state_);
  }

  /// @brief Start the NTCP2 session
  void Start(const meta::ntcp2::session::IP_t proto)
  {
    if (std::is_same<TRole, Initiator>::value)
      Connect(proto);
    else
      HandleSessionRequest();
  }

  /// @brief Wait for session to be ready
  /// @throw Runtime error on handshake timeout
  void Wait()
  {
    using ms = std::chrono::milliseconds;
    using tini2p::meta::ntcp2::session::WaitTimeout;

    std::unique_lock<std::mutex> l(ready_mutex_);
    if (!cv_.wait_for(l, ms(WaitTimeout), [=]() { return ready_; }))
      {
        l.unlock();
        Stop();
        exception::Exception{"Session", __func__}.throw_ex<std::runtime_error>(
            "handshake timed out.");
      }
    l.unlock();
    cv_.notify_all();
  }

  /// @brief Stop the session
  void Stop()
  {
    try
      {
        sock_.get_executor().context().stop();
        ready_ = false;
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
  void Write(data_msg_t& message)
  {
    if (!ready_)
      exception::Exception{"Session", __func__}.throw_ex<std::runtime_error>(
          "session not ready for data phase.");

    dp_->Write(message);
  }

  /// @brief Read a data phase message
  /// @param message Data phase message to store read results
  void Read(data_msg_t& message)
  {
    if (!ready_)
      exception::Exception{"Session", __func__}.throw_ex<std::runtime_error>(
          "session not ready for data phase.");

    dp_->Read(message);
  }

  /// @brief Get a non-const reference to the socket
  /// @return Reference to session socket
  socket_t& socket() noexcept
  {
    return sock_;
  }

  /// @brief Get if session is ready for processing data phase messages
  /// @return Session ready status
  bool ready() const noexcept
  {
    return ready_;
  }

  /// @brief Get a const reference to the session key
  /// @detail Keyed under Bob's key for outbound connections, and under Alice's for inbound connections
  const key_t& key() const noexcept
  {
    return remote_key_;
  }

  /// @brief Get a const reference to the connection key
  /// @detail Keyed as a Sha256 hash of initiating endpoint address
  const key_t& connect_key() const noexcept
  {
    return connect_key_;
  }

 private:
  void CalculateConnectKey()
  {
    const auto& host = std::is_same<TRole, Initiator>::value
                           ? sock_.local_endpoint().address().to_string()
                           : sock_.remote_endpoint().address().to_string();

    crypto::Sha256::Hash(connect_key_.key.buffer(), host);
  }

  void Run()
  {
    const auto func = __func__;
    thread_ = std::make_unique<std::thread>([=]() {
      try
        {
          sock_.get_executor().context().run();
        }
      catch (const std::exception& ex)
        {
          std::cerr << "Session: " << func << ": " << ex.what() << std::endl;
          Stop();
        }
    });
  }

  void Connect(const meta::ntcp2::session::IP_t proto)
  {
    boost::system::error_code ec;
    remote_host_ = dest_->host((bool)proto);

    const exception::Exception ex{"Session", __func__};

    sock_.open(remote_host_.protocol());
    sock_.set_option(socket_t::reuse_address(true));
    sock_.bind(endpoint_t(remote_host_.protocol(), 0), ec);
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
    if (std::is_same<TRole, Initiator>::value)
      DoSessionRequest();
    else
      {
        const auto func = __func__;
        sock_.async_wait(
            socket_t::wait_read,
            [this, func](const boost::system::error_code& ec) {
              if (ec)
                exception::Exception{"Session", func}
                    .throw_ex<std::runtime_error>(ec.message().c_str());

              DoSessionRequest();
            });
       }

    CalculateConnectKey();
  }

  void DoSessionRequest()
  {
    const exception::Exception ex{"Session", __func__};

    if (std::is_same<TRole, Initiator>::value)
      {
        request_impl_t srq(
            state_, dest_->identity().hash(), aes_iv_);

        srq.kdf().set_local_keys(info_->id_keys());
        srq.kdf().Derive(remote_key_.key);

        std::lock_guard<std::mutex> lg(msg_mutex_);
        srq_msg_ = std::make_unique<request_msg_t>(
            sco_msg_->payload_size(),
            crypto::RandInRange(
                request_msg_t::MinPaddingSize,
                request_msg_t::MaxPaddingSize));

        srq.ProcessMessage(*srq_msg_);
        boost::asio::async_write(
            sock_,
            boost::asio::buffer(srq_msg_->data.data(), srq_msg_->data.size()),
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
        srq_msg_ = std::make_unique<request_msg_t>();
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(srq_msg_->data.data(), srq_msg_->data.size()),
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              srq_xfer_ += bytes_transferred;
              return request_msg_t::NoisePayloadSize - srq_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              request_impl_t srq(state_, info_->identity().hash(), aes_iv_);

              auto& kdf = srq.kdf();
              kdf.set_local_keys(info_->id_keys());
              kdf.Derive();
              srq.ProcessMessage(*srq_msg_);
              if (srq_msg_->options.pad_len)
                {
                  srq_xfer_ = 0;
                  srq_msg_->padding.resize(srq_msg_->options.pad_len);
                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(
                          srq_msg_->padding.data(), srq_msg_->padding.size()),
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
    if (std::is_same<TRole, Initiator>::value)
      {
        const auto func = __func__;
        sock_.async_wait(
            socket_t::wait_read,
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
    const exception::Exception ex{"Session", __func__};

    if (std::is_same<TRole, Initiator>::value)
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        scr_msg_ = std::make_unique<created_msg_t>();
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(
                scr_msg_->data.data(), created_msg_t::NoisePayloadSize),
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              scr_xfer_ += bytes_transferred;
              return created_msg_t::NoisePayloadSize - scr_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                const std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              created_impl_t scr(
                  state_, *srq_msg_, dest_->identity().hash(), aes_iv_);

              scr.ProcessMessage(*scr_msg_);
              if (scr_msg_->options.pad_len)
                {
                  scr_xfer_ = 0;
                  scr_msg_->padding.resize(scr_msg_->options.pad_len);
                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(
                          scr_msg_->padding.data(), scr_msg_->options.pad_len),
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
        scr_msg_ = std::make_unique<created_msg_t>();

        created_impl_t scr(
            state_, *srq_msg_, info_->identity().hash(), aes_iv_);

        scr.ProcessMessage(*scr_msg_);
        boost::asio::async_write(
            sock_,
            boost::asio::buffer(scr_msg_->data.data(), scr_msg_->data.size()),
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
    if (std::is_same<TRole, Initiator>::value)
      DoSessionConfirmed();
    else
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
  }

  void DoSessionConfirmed()
  {
    const exception::Exception ex{"Session", __func__};

    if (std::is_same<TRole, Initiator>::value)
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        confirmed_impl_t sco(state_, *scr_msg_);

        sco.ProcessMessage(*sco_msg_, srq_msg_->options);

        boost::asio::async_write(
            sock_,
            boost::asio::buffer(sco_msg_->data.data(), sco_msg_->data.size()),
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
        sco_msg_ = std::make_unique<confirmed_msg_t>(
            confirmed_msg_t::PartOneSize + srq_msg_->options.m3p2_len);

        boost::asio::async_read(
            sock_,
            boost::asio::buffer(sco_msg_->data.data(), sco_msg_->data.size()),
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

              confirmed_impl_t sco(state_, *scr_msg_);
              sco.ProcessMessage(*sco_msg_, srq_msg_->options);

              // get static key from Alice's RouterInfo
              dest_ = sco_msg_->info_block.info();
              auto& b64_s = dest_->options().entry(std::string("s"));
              auto s = crypto::Base64::Decode(reinterpret_cast<const char*>(b64_s.data()), b64_s.size());

              // get Alice's static key from first frame
              noise::get_remote_public_key(state_, remote_key_.key, ex);

              // check static key from first frame matches RouterInfo static key, see spec
              const bool match = std::equal(s.begin(), s.end(), remote_key_.key.begin());
              crypto::RandBytes(s);  // overwrite key, no longer needed

              if (!match)
                ex.throw_ex<std::logic_error>("static key does not match initial SessionRequest key.");

              HandleDataPhase();
            });
      }
  }

  void HandleDataPhase()
  {
    if (std::is_same<TRole, Initiator>::value)
      {
        const auto func = __func__;
        sock_.async_wait(
            socket_t::wait_read,
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
    if (std::is_same<TRole, Initiator>::value)
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        dp_msg_ = std::make_unique<data_msg_t>();
        dp_msg_->buffer().resize(data_msg_t::MaxLen);

        // read message length from the socket
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(dp_msg_->buffer().data(), data_msg_t::SizeLen),
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_xfer_ += bytes_transferred;
              return data_msg_t::SizeLen - dp_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_ = std::make_unique<data_impl_t>(state_);

              boost::endian::big_uint16_t obfs_len;
              tini2p::read_bytes(dp_msg_->buffer().data(), obfs_len);

              dp_->kdf().ProcessLength(obfs_len, data_msg_t::Dir::BobToAlice);

              if(obfs_len)
                {
                  dp_xfer_ = 0;
                  // read remaing message bytes
                  dp_msg_->buffer().resize(data_msg_t::SizeLen + obfs_len);
                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(
                          &dp_msg_->buffer()[data_msg_t::SizeLen], obfs_len),
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
                        tini2p::write_bytes(dp_msg_->buffer().data(), obfs_len);
                        dp_->Read(*dp_msg_, false /*deobfs len*/);

                        const auto& info_block =
                            dp_msg_->get_block(data::Block::type_t::Info);
                        if (boost::get<tini2p::data::InfoBlock>(info_block)
                                .info()
                                ->options()
                                .entry(std::string("s"))
                            != dest_->options().entry(std::string("s")))
                          ex.throw_ex<std::logic_error>("invalid static key.");
                        //--------------------------------------------
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
        dp_ = std::make_unique<data_impl_t>(state_);

        dp_msg_ = std::make_unique<data_msg_t>();
        dp_msg_->add_block(data::InfoBlock(info_));

        dp_->Write(*dp_msg_);

        boost::asio::async_write(
            sock_,
            boost::asio::buffer(dp_msg_->buffer().data(), dp_msg_->buffer().size()),
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_xfer_ += bytes_transferred;
              return dp_msg_->buffer().size() - dp_xfer_;
            },
            [this, ex](
                const boost::system::error_code& ec,
                std::size_t bytes_transferred) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());
              //--------------------------------------------
              {
                std::lock_guard<std::mutex> l(ready_mutex_);
                ready_ = true;
              }
              cv_.notify_all();
            });
      }
  }

  state_t* state_;
  dest_ptr dest_;
  info_ptr info_;
  key_t remote_key_, connect_key_;
  obfse_t::iv_t aes_iv_;
  context_t ctx_;
  socket_t sock_;
  endpoint_t remote_host_;
  std::unique_ptr<request_msg_t> srq_msg_;
  std::unique_ptr<created_msg_t> scr_msg_;
  std::unique_ptr<confirmed_msg_t> sco_msg_;
  std::unique_ptr<data_msg_t> dp_msg_;
  std::unique_ptr<data_impl_t> dp_;
  std::size_t srq_xfer_, scr_xfer_, sco_xfer_, dp_xfer_;
  std::condition_variable cv_;
  bool ready_;
  std::mutex ready_mutex_;
  std::mutex msg_mutex_;
  std::unique_ptr<std::thread> thread_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_SESSION_H_
