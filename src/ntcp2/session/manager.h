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

#ifndef SRC_NTCP2_SESSION_MANAGER_H_
#define SRC_NTCP2_SESSION_MANAGER_H_

#include "src/data/router/info.h"

#include "src/ntcp2/session/session.h"
#include "src/ntcp2/session/listener.h"

namespace tini2p
{
namespace ntcp2
{
/// @class SessionManager
/// @brief Class for managing NTCP2 sessions
class SessionManager
{
 public:
  using info_t = data::Info;  //< RouterInfo trait alias
  using dest_t = data::Info;  //< Destination trait alias
  using listener_t = SessionListener;  //< Session listener trait alias
  using out_session_t = Session<Initiator>;  //< Outbound session trait alias
  using out_sessions_t = std::vector<out_session_t::shared_ptr>;  //< Outbound session container trait alias

  /// @brief Create a session listener for a given RouterInfo and local endpoints
  /// @param info RouterInfo to receive incoming connections
  /// @param ipv4_ep IPv4 Local ASIO endpoint to listen for connections
  /// @param ipv6_ep IPv6 Local ASIO endpoint to listen for connections
  /// @detail Sessions will be created for both IPv4 and IPv6 routers
  SessionManager(
      info_t::shared_ptr info,
      const listener_t::session_t::tcp_t::endpoint& ipv4_ep,
      const listener_t::session_t::tcp_t::endpoint& ipv6_ep)
      : info_(info)
  {
    const exception::Exception ex{"SessionManager", __func__};

    if (!info)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    if (!ipv4_ep.address().is_v4() || !ipv6_ep.address().is_v6())
      ex.throw_ex<std::invalid_argument>("invalid listener endpoints.");

    listener_.reset(new listener_t(info_, ipv4_ep));
    listener_v6_.reset(new listener_t(info_, ipv6_ep));

    listener_->Start();
    listener_v6_->Start();
  }

  /// @brief Create a session listener for a given RouterInfo and local endpoint
  /// @param info RouterInfo to receive incoming connections
  /// @param ep Local ASIO endpoint to listen for connections
  /// @detail Local endpoint can be either IPv4 or IPv6
  /// @detail Incoming sessions will only be created for either IPv4 or IPv6 routers
  /// @detail Outgoing sessions will be created for both IPv4 and IPv6 routers
  SessionManager(
      info_t::shared_ptr info,
      const listener_t::session_t::tcp_t::endpoint& ep)
      : info_(info)
  {
    const exception::Exception ex{"SessionManager", __func__};

    if (!info)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    if (ep.address().is_v4())
      {
        listener_.reset(new listener_t(info_, ep));
        listener_->Start();
      }
    else
      {
        listener_v6_.reset(new listener_t(info_, ep));
        listener_v6_->Start();
      }
  }

  ~SessionManager()
  {
    Stop();
  }

  /// @brief Stop all in/outbound sessions and listeners
  void Stop()
  {
    try
      {
        {  // clean up open sessions
          std::lock_guard<std::mutex> l(out_sessions_mutex_);
          for (const auto& session : out_sessions_)
            session->Stop();

          out_sessions_.clear();
        }  // end session-lock scope

        if (listener_)
          {
            listener_->Stop();
            listener_.reset();
          }

        if (listener_v6_)
          {
            listener_v6_->Stop();
            listener_v6_.reset();
          }
      }
    catch (const std::exception& ex)
      {
        std::cerr << "SessionManager: " << __func__ << ": " << ex.what();
      }
  }

  /// @brief Create a new outbound session to a given destination
  /// @param dest Pointer to remote destination RouterInfo
  /// @return Non-owning ointer to newly created session
  /// @throw Invalid argument if dest is null
  /// @throw Runtime error if session already exists for given destination
  out_session_t::shared_ptr session(dest_t::shared_ptr dest)
  {
    const exception::Exception ex{"SessionManager", __func__};

    if (!dest)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    std::lock_guard<std::mutex> l(out_sessions_mutex_);

    // search for existing session to given destination
    const auto& id_crypto = dest->identity().crypto();

    if(boost::apply_visitor(
        [this, ex](const auto& c) -> bool { return blacklisted(c.pubkey()); },
        id_crypto))
      ex.throw_ex<std::runtime_error>("session destination is blacklisted.");

    const auto it = std::find_if(
        out_sessions_.begin(),
        out_sessions_.end(),
        [id_crypto](const out_sessions_t::value_type& session) -> bool {
          return boost::apply_visitor(
              [&session](const auto& c) -> bool {
                return session->key() == c.pubkey();
              },
              id_crypto);
        });

    if (it != out_sessions_.end())
      {
        const std::string err_msg(
            "session already exists for key: "
            + crypto::Base64::Encode((*it)->key()));

        blacklist_.emplace(std::move((*it)->key()));
        blacklist_.emplace(std::move((*it)->connect_key()));

        out_sessions_.erase(it);
        ex.throw_ex<std::runtime_error>(std::move(err_msg));
      }

    out_sessions_.emplace_back(new out_session_t(dest, info_));

    return out_sessions_.back();
  }

  /// @brief Get a const shared pointer to a session listener
  /// @param ip IP protocol of the listener to retrieve
  /// @throw Invalid argument if ip is invalid protocol
  listener_t::const_shared_ptr listener(
      const listener_t::session_t::meta_t::IP ip) const
  {
    using IP = listener_t::session_t::meta_t::IP;

    const exception::Exception ex{"SessionManager", __func__};

    if (ip != IP::v4 && ip != IP::v6)
      ex.throw_ex<std::invalid_argument>("invalid listener protocol.");

    return ip == IP::v4 ? listener_ : listener_v6_;
  }

  /// @brief Get a non-const shared pointer to a session listener
  /// @param ip IP protocol of the listener to retrieve
  /// @throw Invalid argument if ip is invalid protocol
  listener_t::shared_ptr listener(const listener_t::session_t::meta_t::IP ip)
  {
    using IP = listener_t::session_t::meta_t::IP;

    const exception::Exception ex{"SessionManager", __func__};

    if (ip != IP::v4 && ip != IP::v6)
      ex.throw_ex<std::invalid_argument>("invalid listener protocol.");

    return ip == IP::v4 ? listener_ : listener_v6_;
  }

  /// @brief Get the blacklisted status of a session key
  bool blacklisted(const listener_t::key_t& key) const
  {
    const bool out_bl = blacklist_.find(key) != blacklist_.end();
    const bool listenv4_bl = listener_ && listener_->blacklisted(key);
    const bool listenv6_bl = listener_v6_ && listener_v6_->blacklisted(key);

    return (out_bl || listenv4_bl || listenv6_bl);
  }

 private:
  info_t::shared_ptr info_;
  listener_t::shared_ptr listener_, listener_v6_;
  out_sessions_t out_sessions_;
  listener_t::blacklist_t blacklist_;
  std::mutex out_sessions_mutex_;
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_MANAGER_H_
