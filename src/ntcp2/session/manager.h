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
  tini2p::data::Info* info_;
  std::unique_ptr<SessionListener> listener_, listener_v6_;
  std::vector<std::unique_ptr<Session<Initiator>>> out_sessions_;
  std::mutex out_sessions_mutex_;

 public:
  /// @brief Create a session listener for a given RouterInfo and local endpoints
  /// @param info RouterInfo to receive incoming connections
  /// @param ipv4_ep IPv4 Local ASIO endpoint to listen for connections
  /// @param ipv6_ep IPv6 Local ASIO endpoint to listen for connections
  /// @detail Sessions will be created for both IPv4 and IPv6 routers
  SessionManager(
      tini2p::data::Info* info,
      const boost::asio::ip::tcp::endpoint& ipv4_ep,
      const boost::asio::ip::tcp::endpoint& ipv6_ep)
      : info_(info)
  {
    using listener_t = decltype(listener_)::element_type;

    const exception::Exception ex{"SessionManager", __func__};

    if (!info)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    if (!ipv4_ep.address().is_v4() || !ipv6_ep.address().is_v6())
      ex.throw_ex<std::invalid_argument>("invalid listener endpoints.");

    listener_ = std::make_unique<listener_t>(info_, ipv4_ep);
    listener_v6_ = std::make_unique<listener_t>(info_, ipv6_ep);

    listener_->Start();
    listener_v6_->Start();
  }

  /// @brief Create a session listener for a given RouterInfo and local endpoint
  /// @param info RouterInfo to receive incoming connections
  /// @param ep Local ASIO endpoint to listen for connections
  /// @detail Local endpoint can be either IPv4 or IPv6
  /// @detail Incoming sessions will only be created for either IPv4 or IPv6 routers
  /// @detail Outgoing sessions will be created for both IPv4 and IPv6 routers
  SessionManager(tini2p::data::Info* info, const boost::asio::ip::tcp::endpoint& ep)
      : info_(info)
  {
    using listener_t = decltype(listener_)::element_type;

    if (!info)
      exception::Exception{"SessionManager", __func__}
          .throw_ex<std::invalid_argument>("null RouterInfo.");

    if (ep.address().is_v4())
      {
        listener_ = std::make_unique<listener_t>(info_, ep);
        listener_->Start();
      }
    else
      {
        listener_v6_ = std::make_unique<listener_t>(info_, ep);
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
        }

        if (listener_)
          {
            listener_->Stop();
            listener_.reset(nullptr);
          }

        if (listener_v6_)
          {
            listener_v6_->Stop();
            listener_v6_.reset(nullptr);
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
  decltype(out_sessions_)::value_type::pointer session(tini2p::data::Info* dest)
  {
    using session_t = decltype(out_sessions_)::value_type::element_type;

    const exception::Exception ex{"SessionManager", __func__};

    if (!dest)
      ex.throw_ex<std::invalid_argument>("null RouterInfo.");

    std::lock_guard<std::mutex> l(out_sessions_mutex_);

    // search for existing session to given destination
    const auto it = std::find_if(
        out_sessions_.begin(),
        out_sessions_.end(),
        [dest](const decltype(out_sessions_)::value_type& session) {
          return session->key().key == dest->id_keys().pubkey;
        });

    if (it != out_sessions_.end())
      {
        const auto& dest_key = dest->id_keys().pubkey;

        ex.throw_ex<std::runtime_error>(
            ("session alread exists for key: "
             + crypto::Base64::Encode(dest_key.data(), dest_key.size()))
                .c_str());
      }

    out_sessions_.emplace_back(new session_t(dest, info_));

    return out_sessions_.back().get();
  }

  /// @brief Get a non-const pointer to a session listener
  /// @param ip IP protocol of the listener to retrieve
  /// @throw Invalid argument if ip is invalid protocol
  decltype(listener_)::pointer listener(const meta::ntcp2::session::IP_t ip)
  {
    using tini2p::meta::ntcp2::session::IP_t;

    if (ip != IP_t::v4 && ip != IP_t::v6)
      exception::Exception{"SessionManager", __func__}
          .throw_ex<std::invalid_argument>("invalid listener protocol.");

    return ip == IP_t::v4 ? listener_.get() : listener_v6_.get();
  }

  bool blacklisted(const SessionKey& key) const
  {
    if (const bool ret = listener_ ? listener_->blacklisted(key) : false)
      return ret;

    return listener_v6_ ? listener_v6_->blacklisted(key) : false;
  }
};
}  // namespace ntcp2
}  // namespace tini2p

#endif  // SRC_NTCP2_SESSION_MANAGER_H_
