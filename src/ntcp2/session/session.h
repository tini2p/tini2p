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

#include "src/ntcp2/session/key.h"

namespace tini2p
{
namespace ntcp2
{
struct SessionMeta
{
enum
{
  CleanTimeout = 5000,  //< in milliseconds
  WaitTimeout = 3000,  //< in milliseconds
  MaxSessions = 3,  //< max sessions in CleanTimeout
  MaxConnections = 11,  //< max connections in CleanTimeout
  ShutdownTimeout = 13, //< in milliseconds, somewhat arbitrary, adjust based on performance tests
};

enum struct IP : bool
{
  v4,
  v6,
};
};

/// @class Session
/// @tparam TRole Noise role for the first data phase message
/// @detail On first data phase message, session initiator will be responder, vice versa
template <class TRole>
class Session
{
 public:
  using state_t = NoiseHandshakeState;  //< Handshake state trait alias
  using meta_t = SessionMeta;  //< Meta trait alias
  using info_t = data::Info;  //< RouterInfo trait alias
  using dest_t = data::Info;  //< Destination trait alias
  using obfse_t = crypto::AES;  //< Obfse crypto trait alias
  using key_t = crypto::X25519::pubkey_t;  //< Key trait alias

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
  using tcp_t = boost::asio::ip::tcp;  //< TCP trait alias
  using error_c = boost::system::error_code;  //< Error code trait alias

  using pointer = Session<TRole>*;  //< Non-owning pointer trait alias
  using const_pointer = const Session<TRole>*;  //< Const non-owning pointer trait alias
  using unique_ptr = std::unique_ptr<Session<TRole>>;  //< Unique pointer trait alias
  using const_unique_ptr = std::unique_ptr<const Session<TRole>>;  //< Const unique pointer trait alias
  using shared_ptr = std::shared_ptr<Session<TRole>>;  //< Shared pointer trait alias
  using const_shared_ptr = std::shared_ptr<const Session<TRole>>;  //< Const shared pointer trait alias

  /// @brief Create a session for a destination
  /// @param dest RouterInfo for remote destination
  /// @param info RouterInfo for local router
  Session(dest_t::shared_ptr dest, info_t::shared_ptr info)
      : dest_(dest),
        info_(info),
        ctx_(),
        sock_(ctx_),
        strand_(ctx_),
        ready_(false)
  {
    const exception::Exception ex{"Session", __func__};

    if (!dest_ || !info_)
      ex.throw_ex<std::invalid_argument>("null remote or local RouterInfo.");

    sco_msg_.reset(new confirmed_msg_t(
        info_,
        crypto::RandInRange(
            confirmed_msg_t::MinPaddingSize,
            confirmed_msg_t::MaxPaddingSize - info_->size())));

    noise::init_handshake<Initiator>(&state_, ex);

    std::copy_n(
        crypto::Base64::Decode(dest_->options().entry(std::string("s"))).data(),
        remote_key_.size(),
        remote_key_.data());

    std::copy_n(
        crypto::Base64::Decode(dest_->options().entry(std::string("i"))).data(),
        aes_iv_.size(),
        aes_iv_.data());
  }

  /// @brief Create a session for an incoming connection
  /// @param dest RouterInfo for remote destination
  /// @param info RouterInfo for local router
  Session(info_t::shared_ptr info, tcp_t::socket socket)
      : info_(info),
        sock_(std::move(socket)),
        strand_(sock_.get_executor().context()),
        ready_(false)
  {
    const exception::Exception ex{"Session", __func__};

    if (!info_)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    noise::init_handshake<Responder>(&state_, ex);

    std::copy_n(
        crypto::Base64::Decode(info_->options().entry(std::string("i"))).data(),
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
  void Start(const meta_t::IP proto)
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

    const exception::Exception ex{"Session", __func__};

    std::unique_lock<std::mutex> l(ready_mutex_);
    if (!cv_.wait_for(l, ms(meta_t::WaitTimeout), [this, &l, ex]() { return ready_; }))
      {
        l.unlock();
        Stop();
        ex.throw_ex<std::runtime_error>("handshake timed out.");
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
    const exception::Exception ex{"Session", __func__};

    if (!ready_)
      ex.throw_ex<std::runtime_error>("session not ready for data phase.");

    dp_->Write(message);
  }

  /// @brief Read a data phase message
  /// @param message Data phase message to store read results
  void Read(data_msg_t& message)
  {
    const exception::Exception ex{"Session", __func__};

    if (!ready_)
      ex.throw_ex<std::runtime_error>("session not ready for data phase.");

    dp_->Read(message);
  }

  /// @brief Get a non-const reference to the socket
  /// @return Reference to session socket
  tcp_t::socket& socket() noexcept
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

    crypto::Sha256::Hash(connect_key_.buffer(), host);
  }

  void Run()
  {
    const auto func = __func__;
    thread_ = std::make_unique<std::thread>([this, func]() {
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

  void Connect(const meta_t::IP proto)
  {
    error_c ec;
    remote_host_ = dest_->host(static_cast<bool>(proto));

    const exception::Exception ex{"Session", __func__};

    sock_.open(remote_host_.protocol());
    sock_.set_option(tcp_t::socket::reuse_address(true));
    sock_.bind(tcp_t::endpoint(remote_host_.protocol(), 0), ec);
    if (ec)
      ex.throw_ex<std::runtime_error>(ec.message().c_str());

    const auto connect_handler = [this, ex](const error_c& ec) {
      if (ec)
        ex.throw_ex<std::runtime_error>(ec.message().c_str());

      HandleSessionRequest();
    };

    sock_.async_connect(remote_host_, strand_.wrap(connect_handler));

    Run();
  }

  void HandleSessionRequest()
  {

    if (std::is_same<TRole, Initiator>::value)
      DoSessionRequest();
    else
      {
        const exception::Exception ex{"Session", __func__};

        const auto do_session_request = [this, ex](const error_c& ec) {
          if (ec)
            ex.throw_ex<std::runtime_error>(ec.message().c_str());

          DoSessionRequest();
        };
        sock_.async_wait(tcp_t::socket::wait_read, strand_.wrap(do_session_request));
       }

    CalculateConnectKey();
  }

  void DoSessionRequest()
  {
    using ecies_x25519_hmac_t = info_t::identity_t::ecies_x25519_hmac_t;
    using ecies_x25519_blake_t = info_t::identity_t::ecies_x25519_blake_t;

    const exception::Exception ex{"Session", __func__};

    const auto get_id_keys = [](const auto& c) { return c.id_keys(); };

    if (std::is_same<TRole, Initiator>::value)
      {
        const auto& ident = dest_->identity();
        request_impl_t srq(state_, ident.hash(), aes_iv_);
        auto& kdf = srq.kdf();
        kdf.set_local_keys(boost::apply_visitor(get_id_keys, ident.crypto()));
        kdf.Derive(remote_key_);

        std::lock_guard<std::mutex> lg(msg_mutex_);
        srq_msg_ = std::make_unique<request_msg_t>(
            sco_msg_->payload_size(),
            crypto::RandInRange(
                request_msg_t::MinPaddingSize,
                request_msg_t::MaxPaddingSize));

        srq.ProcessMessage(*srq_msg_);

        const auto write_completion_handler =
            [this, ex](const error_c& ec, const std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message());

              HandleSessionCreated();
            };

        boost::asio::async_write(
            sock_,
            boost::asio::buffer(srq_msg_->data.data(), srq_msg_->data.size()),
            strand_.wrap(write_completion_handler));
      }
    else
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        srq_msg_ = std::make_unique<request_msg_t>();

        const auto read_completion_handler =
            [this, get_id_keys, ex](const error_c& ec, const std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              const auto& ident = info_->identity();
              request_impl_t srq(state_, ident.hash(), aes_iv_);
              auto& kdf = srq.kdf();
              kdf.set_local_keys(
                  boost::apply_visitor(get_id_keys, ident.crypto()));
              srq.kdf().Derive();
              srq.ProcessMessage(*srq_msg_);

              if (srq_msg_->options.pad_len)
                {
                  srq_xfer_ = 0;
                  srq_msg_->padding.resize(srq_msg_->options.pad_len);

                  const auto padding_completion_handler =
                      [this, ex](const error_c& ec, const std::size_t) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        HandleSessionCreated();
                      };

                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(
                          srq_msg_->padding.data(), srq_msg_->padding.size()),
                      strand_.wrap(padding_completion_handler));
                }
              else
                HandleSessionCreated();
            };

        boost::asio::async_read(
            sock_,
            boost::asio::buffer(srq_msg_->data.data(), srq_msg_->data.size()),
            strand_.wrap(read_completion_handler));
      }
  }

  void HandleSessionCreated()
  {
    if (std::is_same<TRole, Initiator>::value)
      {
        const exception::Exception ex{"Session", __func__};
        sock_.async_wait(
            tcp_t::socket::wait_read, strand_.wrap([this, ex](const error_c& ec) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              DoSessionCreated();
            }));
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

        const auto read_completion_handler =
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
                      strand_.wrap([this, ex](
                                       const error_c& ec, const std::size_t) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        HandleSessionConfirmed();
                      }));
                }
              else
                ex.throw_ex<std::length_error>("null padding length.");
            };

        boost::asio::async_read(
            sock_,
            boost::asio::buffer(
                scr_msg_->data.data(), created_msg_t::NoisePayloadSize),
            strand_.wrap(read_completion_handler));
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
            strand_.wrap([this, ex](const error_c& ec, const std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              HandleSessionConfirmed();
            }));
      }
  }

  void HandleSessionConfirmed()
  {
    if (std::is_same<TRole, Initiator>::value)
      DoSessionConfirmed();
    else
      {
        const exception::Exception ex{"Session", __func__};
        sock_.async_wait(
            tcp_t::socket::wait_read, strand_.wrap([this, ex](const error_c& ec) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              DoSessionConfirmed();
            }));
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
            strand_.wrap([this, ex](const error_c& ec, std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              HandleDataPhase();
            }));
      }
    else
      {
        std::lock_guard<std::mutex> lg(msg_mutex_);
        sco_msg_.reset(new confirmed_msg_t(
            confirmed_msg_t::PartOneSize + srq_msg_->options.m3p2_len));

        const auto read_completion_handler =
            [this, ex](const error_c& ec, std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              confirmed_impl_t sco(state_, *scr_msg_);
              sco.ProcessMessage(*sco_msg_, srq_msg_->options);

              // get static key from Alice's RouterInfo
              dest_ = sco_msg_->info_block.info();
              const crypto::SecBytes s(crypto::Base64::Decode(
                  dest_->options().entry(std::string("s"))));

              // get Alice's static key from first frame
              noise::get_remote_public_key(state_, remote_key_, ex);

              // check static key from first frame matches RouterInfo static key, see spec
              const bool match = std::equal(s.begin(), s.end(), remote_key_.begin());

              if (!match)
                ex.throw_ex<std::logic_error>(
                    "static key does not match initial SessionRequest key.");

              HandleDataPhase();
            };

        boost::asio::async_read(
            sock_,
            boost::asio::buffer(sco_msg_->data.data(), sco_msg_->data.size()),
            strand_.wrap(read_completion_handler));
      }
  }

  void HandleDataPhase()
  {
    if (std::is_same<TRole, Initiator>::value)
      {
        const exception::Exception ex{"Session", __func__};

        sock_.async_wait(
            tcp_t::socket::wait_read, strand_.wrap([this, ex](const error_c& ec) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              DoDataPhase();
            }));
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

        const auto read_completion_handler =
            [this, ex](const error_c& ec, std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());

              dp_ = std::make_unique<data_impl_t>(state_);

              boost::endian::big_uint16_t obfs_len;
              tini2p::read_bytes(dp_msg_->buffer().data(), obfs_len);

              dp_->kdf().ProcessLength(obfs_len, data_msg_t::Dir::BobToAlice);

              if(obfs_len)
                {
                  dp_xfer_ = 0;
                  dp_msg_->buffer().resize(data_msg_t::SizeLen + obfs_len);

                  // read remaing message bytes
                  const auto data_completion_handler =
                      [this, ex, obfs_len](const error_c& ec, std::size_t) {
                        if (ec && ec != boost::asio::error::eof)
                          ex.throw_ex<std::runtime_error>(ec.message().c_str());

                        // write deobfuscated length back to message
                        tini2p::write_bytes(dp_msg_->buffer().data(), obfs_len);
                        dp_->Read(*dp_msg_, false /*deobfs len*/);
                        const auto& info_block = dp_msg_->get_block(data::Block::type_t::Info);
                        if (info_block
                            && boost::get<tini2p::data::InfoBlock>(*info_block)
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
                      };

                  boost::asio::async_read(
                      sock_,
                      boost::asio::buffer(
                          &dp_msg_->buffer()[data_msg_t::SizeLen], obfs_len),
                      strand_.wrap(data_completion_handler));
                }
            };

        // read message length from the socket
        boost::asio::async_read(
            sock_,
            boost::asio::buffer(dp_msg_->buffer().data(), data_msg_t::SizeLen),
            strand_.wrap(read_completion_handler));
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
            boost::asio::buffer(
                dp_msg_->buffer().data(), dp_msg_->buffer().size()),
            strand_.wrap([this, ex](const error_c& ec, std::size_t) {
              if (ec && ec != boost::asio::error::eof)
                ex.throw_ex<std::runtime_error>(ec.message().c_str());
              //--------------------------------------------
              {
                std::lock_guard<std::mutex> l(ready_mutex_);
                ready_ = true;
              }
              cv_.notify_all();
            }));
      }
  }

  state_t* state_;
  dest_t::shared_ptr dest_;
  info_t::shared_ptr info_;
  key_t remote_key_, connect_key_;
  obfse_t::iv_t aes_iv_;
  context_t ctx_;
  tcp_t::socket sock_;
  context_t::strand strand_;
  tcp_t::endpoint remote_host_;
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
