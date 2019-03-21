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

#ifndef SRC_NTCP2_SESSION_LISTENER_H_
#define SRC_NTCP2_SESSION_LISTENER_H_

#include <unordered_map>
#include <unordered_set>

#include "src/ntcp2/session/key.h"

namespace tini2p
{
namespace ntcp2
{
/// @class SessionListener
/// @brief Listen for incoming sessions on a given local endpoint
class SessionListener
{
 public:
  using info_t = data::Info;  //< RouterInfo trait alias
  using key_t = crypto::X25519::pubkey_t;  //< Session key trait alias
  using session_t = Session<Responder>;  //< Session trait alias
  using sessions_t = std::vector<session_t::shared_ptr>;  //< Sessions container trait alias
  using session_count_t = std::unordered_map<key_t, std::uint16_t, key_t::hasher_t>;  //< Session count trait alias
  using blacklist_t = std::unordered_set<key_t, key_t::hasher_t>;  //< Blacklist trait alias

  using pointer = SessionListener*;  //< Non-owning pointer trait alias
  using const_pointer = const SessionListener*;  //< Const non-owning pointer trait alias
  using unique_ptr = std::unique_ptr<SessionListener>;  //< Unique pointer trait alias
  using const_unique_ptr = std::unique_ptr<const SessionListener>;  //< Const unique pointer trait alias
  using shared_ptr = std::shared_ptr<SessionListener>;  //< Shared pointer trait alias
  using const_shared_ptr = std::shared_ptr<const SessionListener>;  //< Const shared pointer trait alias

  /// @brief Create a session listener for local router on a given local endpoint
  /// @param info Local router info
  /// @param host Local endpoint to bind the listener
  /// @param ctx Boost IO context for listener
  SessionListener(
      const info_t::shared_ptr info,
      const session_t::tcp_t::endpoint& host)
      : info_(info),
        ctx_(),
        acc_(ctx_, host, true),
        timer_(ctx_, std::chrono::milliseconds(session_t::meta_t::CleanTimeout))
  {
    acc_.listen();

    timer_.async_wait(
        [this](const session_t::error_c& ec) { CleanSessions(ec); });
  }

  ~SessionListener()
  {
    Stop();
    acc_.cancel();
    acc_.close();
  }

  /// @brief Start the session listener
  void Start()
  {
    Accept();
    Run();
  }

  /// @brief Stop the session listener
  void Stop()
  {
    using ms = std::chrono::milliseconds;

    try
      {
        {  // clean up sessions
          std::lock_guard<std::mutex> l(sessions_mutex_);
          for (const auto& session : sessions_)
            session->Stop();

          sessions_.clear();
        }

        acc_.get_executor().context().stop();
        timer_.expires_from_now(ms(session_t::meta_t::ShutdownTimeout));

        if (thread_)
          {
            thread_->join();
            thread_.reset();
          }

        std::this_thread::sleep_for(ms(session_t::meta_t::ShutdownTimeout));
      }
    catch (const std::exception& ex)
      {
        std::cerr << "SessionListener: " << __func__ << ": " << ex.what()
                  << std::endl;
      }
  }

  /// @brief Get a session indexed by the remote key
  /// @param key Alice's static Noise key
  /// @return Non-const pointer to an NTCP2 session, or nullptr when no session found
  session_t::shared_ptr session(const key_t& key)
  {
    std::lock_guard<std::mutex> l(sessions_mutex_);

    const auto it = std::find_if(
        sessions_.begin(),
        sessions_.end(),
        [key](const sessions_t::value_type& session) {
          return session->key() == key;
        });

    return it != sessions_.end() ? *it : nullptr;
  }

  /// @brief Get if a session is blacklisted
  /// @param key Session key to search for in the blacklist
  /// @return True if session key found in the blacklist
  bool blacklisted(const key_t& key) const
  {
    return blacklist_.find(key) != blacklist_.end();
  }

 private:
  void Accept()
  {
    const exception::Exception ex{"SessionListener", __func__};

    acc_.async_accept([this, ex](
                          const session_t::error_c& ec,
                          session_t::tcp_t::socket socket) {
      if (ec)
        ex.throw_ex<std::runtime_error>(ec.message().c_str());
      //--------------------------------------------------
      {  // create new session for the incoming connection
        std::lock_guard<std::mutex> l(sessions_mutex_);

        sessions_t::value_type session(new session_t(info_, std::move(socket)));
        session->Start(session_t::meta_t::IP::v6);  // try IPv6, fallback to IPv4

        // try inserting new connection, or get existing entry
        auto count_it =
            connect_count_.emplace(std::make_pair(session->connect_key(), 0)).first;

        const bool blacklisted =
            blacklist_.find(count_it->first) != blacklist_.end();

        if (++count_it->second > session_t::meta_t::MaxConnections || blacklisted)
          {
            const std::string err_msg(
                "SessionListener: blacklisted host with connection key: "
                + crypto::Base64::Encode(count_it->first));

            if (!blacklisted)
              blacklist_.emplace(std::move(count_it->first));

            connect_count_.erase(count_it);
            ex.throw_ex<std::runtime_error>(std::move(err_msg));
          }
        else if (
            std::find_if(
                sessions_.begin(),
                sessions_.end(),
                [count_it](const sessions_t::value_type& session_ptr) {
                  return session_ptr->connect_key() == count_it->first;
                })
            != sessions_.end())
          {
            const std::string err_msg(
                "SessionListener: session already exists for connection key: "
                + crypto::Base64::Encode(count_it->first));

            if (!blacklisted)
              {
                blacklist_.emplace(std::move(count_it->first));
                connect_count_.erase(count_it);
              }

            ex.throw_ex<std::runtime_error>(std::move(err_msg));
          }
        else
          sessions_.emplace_back(std::move(session));
      }  // end session-lock scope

      Accept();
    });
  }

  void Run()
  {
    const auto func = __func__;
    thread_ = std::make_unique<std::thread>([this, func]() {
      try
        {
          acc_.get_io_service().run();
        }
      catch (const std::exception& ex)
        {
          std::cerr << "SessionListener: " << func << ": " << ex.what()
                    << std::endl;
        }
    });
  }

  void CleanSessions(const session_t::error_c& ec)
  {
    const exception::Exception ex{"SessionListener", __func__};

    if (ec && ec != boost::asio::error::eof)
      ex.throw_ex<std::runtime_error>(ec.message().c_str());
    //------------------------------------------
    {  // remove failed and blacklisted sessions
      std::lock_guard<std::mutex> l(sessions_mutex_);

      std::remove_if(
          sessions_.begin(),
          sessions_.end(),
          [=](const decltype(sessions_)::value_type& session) {
            const auto& key = session->key();
            const bool remove =
                !session->ready() || blacklist_.find(key) != blacklist_.end();
            if (remove)
              session_count_[key]++;  // increase session count if removing

            return remove;
          });

      for (auto it = session_count_.begin(); it != session_count_.end(); ++it)
        {
          if (it->second > session_t::meta_t::MaxSessions)
            {
              blacklist_.emplace(std::move(it->first));
              session_count_.erase(it);
            }
        }
    }  // end session-lock scope

    timer_.async_wait(
        [this](const session_t::error_c& ec) { CleanSessions(ec); });
  }

  info_t::shared_ptr info_;
  session_t::context_t ctx_;
  session_t::tcp_t::acceptor acc_;
  sessions_t sessions_;
  session_count_t session_count_, connect_count_;
  blacklist_t blacklist_;
  boost::asio::steady_timer timer_;
  std::unique_ptr<std::thread> thread_;
  std::mutex sessions_mutex_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_LISTENER_H_
