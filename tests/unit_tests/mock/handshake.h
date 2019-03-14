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

#include <catch2/catch.hpp>

#include "src/ntcp2/role.h"

#include "src/ntcp2/session_request/session_request.h"
#include "src/ntcp2/session_created/session_created.h"
#include "src/ntcp2/session_confirmed/session_confirmed.h"
#include "src/ntcp2/data_phase/data_phase.h"
#include "src/ntcp2/session/session.h"

namespace crypto = tini2p::crypto;
namespace exception = tini2p::exception;
namespace meta = tini2p::meta::ntcp2;

/// @brief Container for performing a valid mock handshake
struct MockHandshake
{
  using Initiator = tini2p::ntcp2::Initiator;
  using Responder = tini2p::ntcp2::Responder;

  using state_t = NoiseHandshakeState;
  using obfse_t = tini2p::crypto::AES;
  using sess_init_t = tini2p::ntcp2::Session<Initiator>;
  using sess_resp_t = tini2p::ntcp2::Session<Responder>;

  using request_msg_t = tini2p::ntcp2::SessionRequestMessage;
  using created_msg_t = tini2p::ntcp2::SessionCreatedMessage;
  using confirmed_msg_t = tini2p::ntcp2::SessionConfirmedMessage;
  using data_msg_t = tini2p::ntcp2::DataPhaseMessage;

  MockHandshake()
      : remote_info(new tini2p::data::Info()),
        local_info(new tini2p::data::Info()),
        sco_message(
            local_info,
            crypto::RandInRange(
                confirmed_msg_t::MinPaddingSize,
                confirmed_msg_t::MaxPaddingSize)),
        srq_message(
            sco_message.payload_size(),
            crypto::RandInRange(
                request_msg_t::MinPaddingSize,
                request_msg_t::MaxPaddingSize)),
        scr_message()
  {
    namespace noise = tini2p::ntcp2::noise;

    const exception::Exception ex{"MockHandshake", __func__};

    noise::init_handshake<Initiator>(&initiator_state, ex);
    noise::init_handshake<Responder>(&responder_state, ex);

    InitializeSessionRequest();
  }

  /// @brief Initialize SessionRequest initiator + responder
  void InitializeSessionRequest()
  {
    const auto& ident_hash = remote_info->identity().hash();

    srq_initiator = std::make_unique<sess_init_t::request_impl_t>(
        initiator_state, ident_hash, remote_info->iv());

    srq_responder = std::make_unique<sess_resp_t::request_impl_t>(
        responder_state, ident_hash, remote_info->iv());
  }

  /// @brief Perform a valid SessionRequest between initiator + responder
  void ValidSessionRequest()
  {
    srq_responder->kdf().generate_keys();
    srq_responder->kdf().get_local_public_key(remote_key);
    srq_responder->kdf().Derive();

    srq_initiator->kdf().generate_keys();
    srq_initiator->kdf().Derive(remote_key);

    srq_initiator->ProcessMessage(srq_message);
    srq_responder->ProcessMessage(srq_message);
  }

  /// @brief After valid SessionRequest, initialize SessionCreated initiator + responder
  /// @detail Roles are switched according to Noise spec
  void InitializeSessionCreated()
  {
    scr_initiator = std::make_unique<sess_resp_t::created_impl_t>(
        responder_state, srq_message, router_hash, iv);

    scr_responder = std::make_unique<sess_init_t::created_impl_t>(
        initiator_state, srq_message, router_hash, iv);
  }

  /// @brief Perform a valid SessionCreated message exchange
  void ValidSessionCreated()
  {
    InitializeSessionCreated();

    scr_initiator->ProcessMessage(scr_message);
    scr_responder->ProcessMessage(scr_message);
  }

  /// @brief After valid SessionCreated, initialize SessionConfirmed initiator + responder
  /// @detail Roles are switched according to Noise spec
  void InitializeSessionConfirmed()
  {
    sco_initiator = std::make_unique<sess_init_t::confirmed_impl_t>(
        initiator_state, scr_message);

    sco_responder = std::make_unique<sess_resp_t::confirmed_impl_t>(
        responder_state, scr_message);
  }

  /// @brief Perform a valid SessionConfirmed message exchange
  void ValidSessionConfirmed()
  {
    InitializeSessionConfirmed();

    sco_initiator->ProcessMessage(sco_message, srq_message.options);
    sco_responder->ProcessMessage(sco_message, srq_message.options);
  }

  /// @brief Initialize a DataPhase exchange after successful SessionConfirmed exchange
  void InitializeDataPhase()
  {
    dp_initiator = std::make_unique<sess_resp_t::data_impl_t>(responder_state);
    dp_responder = std::make_unique<sess_init_t::data_impl_t>(initiator_state);
  }

  state_t* initiator_state;
  state_t* responder_state;

  crypto::X25519::pubkey_t remote_key;
  tini2p::data::Identity::hash_t router_hash;
  obfse_t::iv_t iv;
  tini2p::data::Info::shared_ptr remote_info, local_info;

  // handshake messages, session confirmed must be initialized first to initialize the session request message
  confirmed_msg_t sco_message;
  request_msg_t srq_message;
  created_msg_t scr_message;
  data_msg_t dp_message;

  // handshake message handlers
  std::unique_ptr<sess_init_t::request_impl_t> srq_initiator; 
  std::unique_ptr<sess_resp_t::request_impl_t> srq_responder; 

  // switch roles, see spec
  std::unique_ptr<sess_resp_t::created_impl_t> scr_initiator; 
  std::unique_ptr<sess_init_t::created_impl_t> scr_responder; 

  std::unique_ptr<sess_init_t::confirmed_impl_t> sco_initiator; 
  std::unique_ptr<sess_resp_t::confirmed_impl_t> sco_responder; 

  // switch roles, see spec
  std::unique_ptr<sess_resp_t::data_impl_t> dp_initiator; 
  std::unique_ptr<sess_init_t::data_impl_t> dp_responder; 
};
