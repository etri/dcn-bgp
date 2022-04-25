 /* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
 /**
  * Copyright (c) 2021,  ETRI
  *
  * This file is part of DCN-BGP (Data-Centric Networking - Border Gateway Protocol).
  * See AUTHORS.md for complete list of DCN-BGP authors and contributors.
  *
  * DCN-BGP is free software: you can redistribute it and/or modify it under the terms
  * of the GNU General Public License as published by the Free Software Foundation,
  * either version 3 of the License, or (at your option) any later version.
  *
  * DCN-BGP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
  * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  * PURPOSE.  See the GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License along with
  * DCN-BGP, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
  **/

#include <iostream>
#include <string>

#include <ndn-cxx/security/certificate-fetcher-direct-fetch.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>

#include <ndn-cxx/net/face-uri.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/mgmt/nfd/rib-entry.hpp>
#include <ndn-cxx/mgmt/nfd/status-dataset.hpp>
#include <boost/lexical_cast.hpp>

#include "dcn_master.hpp"
#include "dcn_common.hpp"
#include "command.h"
#include "common.h"
#include "log.h"

#include "bgp_fsm.h"
#include "bgp_packet.h"
#include "bgp_nht.h"

using namespace ndn;
using namespace ndn::security;
//using namespace ndn::security::SigningInfo::SignerType;

namespace dcn {

const std::string DcnMaster::UPDATE_COMPONENT = "UPDATE";
const std::string DcnMaster::UPDATE_NEW_COMPONENT = "UPDATE-NEW";
const std::string DcnMaster::OPEN_COMPONENT = "OPEN";
const std::string DcnMaster::NOTIFICATION_COMPONENT = "NOTIFICATION";
const std::string DcnMaster::KEEPALIVE_COMPONENT = "KEEPALIVE";
const std::string DcnMaster::REFRESH_COMPONENT = "REFRESH";
const std::string DcnMaster::CAPABILITY_COMPONENT = "CAPABILITY";
const std::string DcnMaster::CONNECT_COMPONENT = "CONNECT";
const std::string DcnMaster::DISCONNECT_COMPONENT = "DISCONNECT";
const std::string DcnMaster::DBGP_COMPONENT = "DBGP";

const std::string DcnMaster::MULTICAST_STRATEGY("ndn:/localhost/nfd/strategy/multicast");
const std::string DcnMaster::BEST_ROUTE_V2_STRATEGY("ndn:/localhost/nfd/strategy/best-route");

using ndn::nfd::RibEntry;
using ndn::nfd::Route;

inline int32_t
getNameComponentPosition(const ndn::Name& name, const std::string& searchString)
{
  ndn::name::Component component(searchString);
  size_t nameSize = name.size();
  for (uint32_t i = 0; i < nameSize; i++) {
    if (component == name[i]) {
      return (int32_t)i;
    }
  }
  return -1;
}

static std::unique_ptr<ndn::security::CertificateFetcherDirectFetch>
makeCertificateFetcher(ndn::Face& face)
{
  auto fetcher = std::make_unique<ndn::security::CertificateFetcherDirectFetch>(face);
  fetcher->setSendDirectInterestOnly(true);
  return fetcher;
}

//NDN_LOG_INIT(dcn.name);

DcnMaster::DcnMaster(ndn::Face& face, ndn::KeyChain& keyChain, DCN_CP& confParam)
    : m_face(face)
    , m_confParam(confParam)
    , m_controller(m_face, keyChain)
    , m_faceMonitor(m_face)
    , m_validator(makeCertificateFetcher(m_face))
    , m_faceDatasetController(m_face, keyChain)
    , m_scheduler(face.getIoService())
    , m_sequencingManager(m_confParam.getStateFileDir())
    , m_keyChain(keyChain)
{

    m_faceMonitor.onNotification.connect(std::bind(&DcnMaster::onFaceEventNotification, this, _1));
    m_faceMonitor.start();
    enableIncomingFaceIdIndication();

    m_confParam.setFaceDatasetFetchInterval(3600);

#if 0
    setUpdateInterestFilter(); 
    setStrategies();

    ndn::time::milliseconds syncInterestLifetime(4000);
    /* /localhop/<network>/ibgp/sync/<Version(9)> syncName */
    /* /localhop/<network>/ibgp/UPDATE -->userNode */
    m_psyncLogic = std::make_shared<psync::FullProducer>(80,
                     m_face,
                     m_confParam.getSyncPrefix(),
                     m_confParam.getSyncUserPrefix(),
                     std::bind(&DcnMaster::onPSyncUpdate, this, _1),
                     syncInterestLifetime);
#endif
    initializeFaces(std::bind(&DcnMaster::processFaceDataset, this, _1),
              std::bind(&DcnMaster::onFaceDatasetFetchTimeout, this, _1, _2, 0));

#if 1
     m_scheduler.schedule(
            ndn::time::seconds(RIB_REFRESH_TIME), 
            std::bind(&DcnMaster::sch_red_static, this)
    );
#endif
}

#if 0
void
DcnMaster::setUpdateInterestFilter()
{
    ndn::Name name("localhop");
        name.append(m_confParam.getNetwork());
        name.append("i-dbgp");
        name.append(DcnMaster::UPDATE_COMPONENT);

  zlog_info("Setting interest filter for UpdatePrefix: %s" , name.toUri().c_str() );

  m_face.setInterestFilter(ndn::InterestFilter(name).allowLoopback(false),
                           std::bind(&DcnMaster::processUpdateInterestForIBGP, this, _1, _2),
                           std::bind(&DcnMaster::onRegistrationSuccess, this, _1)),
                           std::bind(&DcnMaster::registrationFailed, this, _1);
                           //m_confParam.getSigningInfo(), ndn::nfd::ROUTE_FLAG_CAPTURE);
}
#endif

void 
DcnMaster::setStrategies()
{
    ndn::Name syncName = m_confParam.getSyncPrefix();
    ndn::nfd::ControlParameters parameters;
    parameters
        .setName(syncName)
        .setStrategy( DcnMaster::MULTICAST_STRATEGY );

    m_controller.start<ndn::nfd::StrategyChoiceSetCommand>(parameters,
            std::bind(&DcnMaster::onSetStrategySuccess, this, _1),
            std::bind(&DcnMaster::onSetStrategyFailure, this, _1,
                parameters));

    ndn::Name ibgpName("localhop");
        ibgpName.append(m_confParam.getNetwork());
        ibgpName.append("i-dbgp");
        ibgpName.append(DcnMaster::UPDATE_COMPONENT);

    ndn::nfd::ControlParameters ibgpparameters;
    ibgpparameters
        .setName(ibgpName)
        .setStrategy( DcnMaster::MULTICAST_STRATEGY );

    m_controller.start<ndn::nfd::StrategyChoiceSetCommand>(ibgpparameters,
            std::bind(&DcnMaster::onSetStrategySuccess, this, _1),
            std::bind(&DcnMaster::onSetStrategyFailure, this, _1,
                ibgpparameters));
}

int DcnMaster::unregister_prefix(const char *prefix, uint64_t nexthop)
{
	zlog_debug( "unregister_prefix %s, nexthop %ld" , prefix, nexthop );
    ndn::nfd::ControlParameters unregisterParams;
    unregisterParams
        .setName(prefix)
        .setFaceId(nexthop)
        .setOrigin(ndn::nfd::ROUTE_ORIGIN_BGP);

    m_controller.start<ndn::nfd::RibUnregisterCommand>(
            unregisterParams,
            [&] (const ndn::nfd::ControlParameters& resp) {
                m_ribTable.erase(resp.getName());
            },
            [=] (const ndn::nfd::ControlResponse& resp) {
            });

    return CMD_SUCCESS;
}

int DcnMaster::remove_network(const char *prefix, uint64_t nexthop)
{
    unregister_prefix(prefix, nexthop);
    return CMD_SUCCESS;
}

using boost::lexical_cast;
using boost::bad_lexical_cast;

uint64_t DcnMaster::register_peer_router(const char*peer_router_name, const char *face_info/*URI or FaceId*/, const struct peer *peer)
{

    ndn::FaceUri faceUri;
    uint64_t faceId =0;

    insertPeer(peer_router_name, peer);

    if( face_info != NULL ){
        try{
            faceId = lexical_cast<uint64_t>(face_info); //case FaceId
            if( exist_dcn_face(faceId) != true ){
                zlog_err( "0Don't Exist Face %s" , face_info );
                erasePeer( peer_router_name );
                return 0; 
            }
        }catch(bad_lexical_cast &){

            std::tie(faceId, faceUri) = get_dcn_face(face_info); // case URI
            if(faceId == 0 ){
                zlog_err( "1Don't Exist Face %s" , face_info );
                erasePeer( peer_router_name );
                return 0;
            }
        }
        register_prefix(peer_router_name, faceId, 0, false);
    }

	return faceId;
}

int DcnMaster::open_peer_connection(struct peer *peer)
{

	ndn::Name name(peer->remote_name);

	zlog_info( "connecting to peer[%s] " ,  peer->remote_name);

	name.append(DBGP_COMPONENT);
	name.append(CONNECT_COMPONENT);
	name.append(m_myRouterPrefix);
	name.appendTimestamp();

	Interest interest(name);

	interest.setCanBePrefix(false);
	interest.setMustBeFresh(true);

	m_face.expressInterest(interest,
			bind(&DcnMaster::onData, this, _1, _2),
			bind(&DcnMaster::onNack, this, _1, _2),
			bind(&DcnMaster::onTimeout, this, _1));

	return CMD_SUCCESS;
}

int DcnMaster::close_peer_connection(struct peer *peer)
{
#if 0
	ndn::Name peerRouter(peer->remote_name);
	uint64_t faceId = findFaceId(peer->remote_name);
        zlog_info( "close connection with peer[%s] router over faceId[%ld]" , peer->remote_name , faceId);

        peerRouter.append(DISCONNECT_COMPONENT);
        peerRouter.appendTimestamp();

        Interest interest(peerRouter);

        interest.setMustBeFresh(true);
        interest.setCanBePrefix(true);

        //interest.setTag(std::make_shared<ndn::lp::NextHopFaceIdTag>(faceId));

        interest.setApplicationParameters((uint8_t *)m_myRouterPrefix.c_str(), m_myRouterPrefix.length());

        m_face.expressInterest(interest,
                        bind(&DcnMaster::onData, this, _1, _2),
                        bind(&DcnMaster::onNack, this, _1, _2),
                        bind(&DcnMaster::onTimeout, this, _1));

#endif
	return CMD_SUCCESS;
}

int
DcnMaster::register_prefix(const char *prefix, uint64_t faceId, uint64_t faceCost, bool net_name)
{

    ndn::time::milliseconds timeout(0);
    ndn::nfd::ControlParameters registerParams;
    registerParams
        .setName(prefix)
        .setFaceId(faceId)
        .setFlags(ndn::nfd::ROUTE_FLAG_CHILD_INHERIT |
                net_name?ndn::nfd::ROUTE_FLAG_NET_NAME:ndn::nfd::ROUTE_FLAGS_NONE)
        .setCost(faceCost)
        .setOrigin(ndn::nfd::ROUTE_ORIGIN_BGP);

    zlog_debug("Registering prefix: %s faceUri %ld" , 
		    registerParams.getName().toUri().c_str(),  registerParams.getFaceId() );

    m_controller.start<ndn::nfd::RibRegisterCommand>(registerParams,
            std::bind(&DcnMaster::onRegistrationSuccess1, this, _1),
            std::bind(&DcnMaster::onRegistrationFailure, this, _1, 
                registerParams, faceId));

    return CMD_SUCCESS;
}


 int
 DcnMaster::add_network(const char *prefix, uint64_t nexthop, uint64_t faceCost)
 {
   zlog_info( "add-network %s nexthop %ld cost %ld" , prefix, nexthop, faceCost);
    return register_prefix(prefix, nexthop, faceCost, true);
 }

void
DcnMaster::onRegistrationSuccess1(const ndn::nfd::ControlParameters& param)
{
  zlog_info( "route-add-accepted %s nexthop %ld origin %d" , param.getName().toUri().c_str()
		  , param.getFaceId() , param.getOrigin() );

  m_ribTable.emplace(param.getName(), param.getFaceId());
}

void
DcnMaster::onRegistrationFailure(const ndn::nfd::ControlResponse& response,
                           const ndn::nfd::ControlParameters& parameters,
                           uint64_t faceId)
{
  zlog_info("Failed in name registration: %s (code: %d)" , response.getText().c_str() 
                 , response.getCode() );
}

void
DcnMaster::onSetStrategySuccess(const ndn::nfd::ControlParameters& commandSuccessResult)
{
    zlog_debug ( "Successfully set strategy choice: %s for Name %s" 
        , commandSuccessResult.getStrategy().toUri().c_str() 
        , commandSuccessResult.getName().toUri().c_str() );
}

void
DcnMaster::onSetStrategyFailure(const ndn::nfd::ControlResponse& response,
                          const ndn::nfd::ControlParameters& parameters)
{
    zlog_debug( "Failed to set strategy choice: %s for Name %s" , 
		    parameters.getStrategy().toUri().c_str(),
        		parameters.getName().toUri().c_str() ); 
}

int 
DcnMaster::send_update_message(const struct peer *peer, uint64_t length, uint8_t *message)
{

    if(peer->sort == BGP_PEER_EBGP and peer->face_id == 0){
        zlog_notice ("send_update_message:: There is no face to %s" ,peer->remote_name );
        return CMD_WARNING;

    }
    zlog_info("send bgp UPDATE message - face[%ld] To %s Type: %s, Len:%ld" 
            ,peer->face_id , peer->remote_name, peer->sort==BGP_PEER_EBGP?"eBGP":"iBGP", length);

    m_sequencingManager.increaseUpdateSeq();
    m_sequencingManager.writeSeqNoToFile();
    uint64_t seqNo = m_sequencingManager.getUpdateSeq();
    uint8_t *update = (uint8_t *)malloc(length);
    memcpy(update, message, length);

    m_updateMessageStorage[seqNo]=update;

    ndn::Name name(peer->remote_name);
    name.append(DcnMaster::DBGP_COMPONENT);
    name.append(DcnMaster::UPDATE_NEW_COMPONENT);
    name.append(m_myRouterPrefix);

    name.appendTimestamp();

    Interest interest(name);
    interest.setCanBePrefix(false);
    interest.setMustBeFresh(true);

    DCN_STATUS_T status{0,0,0};
    status.aux = seqNo;
    interest.setApplicationParameters( std::make_shared<Buffer>(&status, sizeof(DCN_STATUS_T)) );

    m_face.expressInterest(interest,
            bind(&DcnMaster::onData, this, _1, _2),
            bind(&DcnMaster::onNack, this, _1, _2),
            nullptr);

    m_scheduler.schedule(ndn::time::seconds(UPDATE_REFRESH_TIME),
            [this, seqNo] { 
            zlog_debug( "Erase Update Message from m_updateMessageStorage with SeqNo: %ld" , seqNo);
            m_updateMessageStorage.erase(seqNo); 
            });

    return CMD_SUCCESS;
}

void 
DcnMaster::send_bgp_message(const struct peer *peer, uint64_t length, uint8_t *bgp_message)
{
    struct bgp_header *hdr = (struct bgp_header *)bgp_message;

    zlog_info("send_bgp_message - To %s Type: %d, Len:%ld" , peer->remote_name, hdr->type, length);

    ndn::Name name(peer->remote_name);
    name.append(DcnMaster::DBGP_COMPONENT);

    if( hdr->type  == DCN_BGP_MSG_UPDATE ){
        send_update_message(peer, length, bgp_message);
        return; 
    }else if( hdr->type ==  DCN_BGP_MSG_OPEN){
        name.append(DcnMaster::OPEN_COMPONENT);
        auto open = std::make_shared<ndn::Buffer>(bgp_message, length);
        m_openMessageStore[peer->remote_name] = open;
    }else if( hdr->type == DCN_BGP_MSG_NOTIFY){
        name.append(DcnMaster::NOTIFICATION_COMPONENT);
    }else if( hdr->type == DCN_BGP_MSG_KEEPALIVE){
        name.append(DcnMaster::KEEPALIVE_COMPONENT);
    }else if( hdr->type == DCN_BGP_MSG_ROUTE_REFRESH_NEW){
        name.append(DcnMaster::REFRESH_COMPONENT);
    }else if( hdr->type == DCN_BGP_MSG_CAPABILITY){
        name.append(DcnMaster::CAPABILITY_COMPONENT);
    }

    name.append(m_myRouterPrefix);
    name.appendTimestamp();
    zlog_debug( "send_bgp_message - Interst: %s" , name.toUri().c_str() );

    Interest interest(name);
    interest.setCanBePrefix(false);
    interest.setMustBeFresh(true);

    interest.setApplicationParameters(bgp_message, length);

    m_face.expressInterest(interest,
			bind(&DcnMaster::onData, this, _1, _2),
			bind(&DcnMaster::onNack, this, _1, _2),
			bind(&DcnMaster::onTimeout, this, _1));

}

void DcnMaster::onData(const ndn::Interest& interest, const ndn::Data& data)
{

    zlog_info( "Receive data and validation start"  );

    if( data.getSignatureInfo().getSignatureType() == ndn::tlv::DigestSha256 ){
        if(security::verifyDigest(data, DigestAlgorithm::SHA256)) {
            zlog_debug( "verifyDigest with SHA256 is OK %s" , 
			data.getName().getPrefix(3).toUri().c_str());
            onDataValidationSuccess(data);
        }
    }else{
        m_confParam.getValidator().validate(data,
                bind(&DcnMaster::onDataValidationSuccess, this, _1),
                bind(&DcnMaster::onDataValidationFailure, this, _1, _2));
    }

}

void DcnMaster::onDataValidationSuccess(const ndn::Data& data)
{
	zlog_debug( "Validation - Got Data packet with name %s"  , data.getName().toUri().c_str());
	ndn::Name name;

    int32_t dbgp_pos = getNameComponentPosition(data.getName(), DcnMaster::DBGP_COMPONENT);
    ndn::Name neighbor = data.getName().getPrefix(dbgp_pos);
    std::string message_type = data.getName().get(dbgp_pos+1).toUri();
    ndn::Name originRouter = data.getName().getSubName(dbgp_pos+2, data.getName().size() - (dbgp_pos + 4));

	std::map<ndn::Name, uint64_t>::iterator it;

	auto peer = findPeer(neighbor.toUri());
	if( peer != nullptr){
		if( message_type == DcnMaster::CONNECT_COMPONENT){

			auto content = data.getContent();
            DCN_STATUS_T *status = (DCN_STATUS_T*)content.value();
			zlog_debug("CONNECT : %s, Status:%s", 
				neighbor.toUri().c_str(), toErrString(status->code));
            if( status->code == DCN_ERR_NO ){
				dcn_peer_connect_open_success( peer );
            }else
				dcn_peer_connect_open_fail( peer );
		}else if( message_type == DcnMaster::UPDATE_COMPONENT){
			zlog_debug("UPDATE success: %s", neighbor.toUri().c_str());
			auto &block = data.getContent();
			toss_message_to_bgp(neighbor.toUri(), DCN_BGP_MSG_UPDATE, block.value_size(), block.value());
		} else if( message_type == DcnMaster::OPEN_COMPONENT){
			zlog_debug("OPEN success: %s", neighbor.toUri().c_str());

			auto open = data.getContent();
            struct bgp_header *hdr = (struct bgp_header *)open.value();
            if(hdr->type == DCN_BGP_MSG_NO_NEIGHBOR)
			    zlog_debug("recv OPEN with Type: DCN_BGP_MSG_NO_NEIGHBOR");
            else
                dcn_peer_open_data_receive (peer, open.value_size(), open.value());

		}else if( message_type == DcnMaster::KEEPALIVE_COMPONENT){
			auto content = data.getContent();
            struct bgp_header *hdr = (struct bgp_header*)content.value();
			zlog_debug("KEEPALIVE's Content: rcvd");

            if(hdr->type != DCN_BGP_MSG_NO_NEIGHBOR)
			    toss_message_to_bgp(neighbor.toUri(), DCN_BGP_MSG_KEEPALIVE, content.value_size(), content.value());
            else
			    zlog_debug("KEEPALIVE's Content: DCN_BGP_MSG_NO_NEIGHBOR");

		}else if( message_type == DcnMaster::OPEN_COMPONENT){
			auto content = data.getContent();
            DCN_STATUS_T *status = (DCN_STATUS_T*)content.value();
			zlog_debug("OPEN's Content: %s", toErrString(status->code));
		}
    }else{
        zlog_debug("++++++++++++ Can't find Peer Info %s", neighbor.toUri().c_str());
    }
}

void DcnMaster::onDataValidationFailure(const ndn::Data& data, const ValidationError& error)
{
	zlog_err("Validation failed...(%s)" , data.getName().toUri().c_str() );
}

void DcnMaster::onTimeout(const ndn::Interest& interest)
{
	zlog_notice("Time out for Interest %s" , interest.getName().toUri().c_str()) ;
}

void DcnMaster::onNack(const ndn::Interest& interest, const ndn::lp::Nack& nack)
{
	zlog_notice("%s Received NACK" ,  interest.getName().toUri().c_str());//, nack.getReason() << std::endl;

	int32_t pos = getNameComponentPosition(interest.getName(), DcnMaster::CONNECT_COMPONENT);

	if(pos>0){
		ndn::Name originRouter  = interest.getName().getSubName(0, pos);
        auto peer_ptr = findPeer(originRouter.toUri());
        dcn_peer_connect_open_fail(peer_ptr);
		return;
	}
}

void DcnMaster::initializeFaces(const FetchDatasetCallback& onFetchSuccess,
		const FetchDatasetTimeoutCallback& onFetchFailure)
{
	zlog_info( "Initializing Faces..." ) ;

	m_faceDatasetController.fetch<ndn::nfd::FaceDataset>(onFetchSuccess, onFetchFailure);
}

void DcnMaster::enableIncomingFaceIdIndication()
{
  zlog_info( "Enabling incoming face id indication for local face." );

  m_controller.start<ndn::nfd::FaceUpdateCommand>(
    ndn::nfd::ControlParameters()
      .setFlagBit(ndn::nfd::FaceFlagBit::BIT_LOCAL_FIELDS_ENABLED, true),
    std::bind(&DcnMaster::onFaceIdIndicationSuccess, this, _1),
    std::bind(&DcnMaster::onFaceIdIndicationFailure, this, _1));
}

void
DcnMaster::onFaceDatasetFetchTimeout(uint32_t code,
                                const std::string& msg,
                                uint32_t nRetriesSoFar)
{
  zlog_notice( "onFaceDatasetFetchTimeout" );
  // If we have exceeded the maximum attempt count, do not try again.
  if (nRetriesSoFar++ < m_confParam.getFaceDatasetFetchTries()) {
    zlog_notice("Failed to fetch dataset: %s Attempting retry %d" , msg.c_str(), nRetriesSoFar );
    m_faceDatasetController.fetch<ndn::nfd::FaceDataset>(std::bind(&DcnMaster::processFaceDataset,
                                                        this, _1),
                                              std::bind(&DcnMaster::onFaceDatasetFetchTimeout,
                                                        this, _1, _2, nRetriesSoFar));
  }
  else {
    zlog_notice( "Failed to fetch dataset: %s Exceeded limit of %d" ,msg.c_str() , m_confParam.getFaceDatasetFetchTries());
    //<< ", so not trying again this time." << std::endl;
    scheduleDatasetFetch();
  }
}

void
DcnMaster::scheduleDatasetFetch()
{
  m_scheduler.schedule(m_confParam.getFaceDatasetFetchInterval(),
  [this] {
      this->initializeFaces(
        [this] (const std::vector<ndn::nfd::FaceStatus>& faces) {
         this->processFaceDataset(faces);
        },
        [this] (uint32_t code, const std::string& msg) {
         this->onFaceDatasetFetchTimeout(code, msg, 0);
        });
  });
}

bool DcnMaster::get_face_uri(uint64_t faceId, char *buf)
{

	auto it = m_faceUriMap.begin();

    for( ; it !=  m_faceUriMap.end(); it++ ){
        if( it->second == faceId )
		strcpy(buf, it->first.c_str());	
		return true;
	}
	strcpy(buf, "N/A");
	return false;
}

void
DcnMaster::processFaceDataset(const std::vector<ndn::nfd::FaceStatus>& faces)
{
    zlog_debug( "Processing face Dataset" );

    for (const auto& faceStatus : faces) {
        std::string uri;
        if( faceStatus.getRemoteUri().find("ether" ) != std::string::npos )
            uri = faceStatus.getLocalUri();
        else
            uri = faceStatus.getRemoteUri();

        zlog_debug("faceId: %ld , RmoteUri: %s" , faceStatus.getFaceId() , uri.c_str());
        m_faceUriMap[uri] = faceStatus.getFaceId();
    }
}

void
DcnMaster::onFaceIdIndicationSuccess(const ndn::nfd::ControlParameters& cp)
{
  zlog_info("Successfully enabled incoming face id indication for face id %ld" , cp.getFaceId() );
}

void
DcnMaster::registrationFailed(const ndn::Name& name)
{
  zlog_err("ERROR: Failed to register prefix %s in local hub's daemon." , name.toUri().c_str());
}

void
DcnMaster::onRegistrationSuccess(const ndn::Name& name)
{
  zlog_debug("Successfully registered prefix: %s" , name.toUri().c_str() );
}

// # bgp router-name /<network-name>/router/name/prefix
int
DcnMaster::register_router_name(const char *router_name)
{
    ndn::Name name(router_name);
    //name.append(DBGP_COMPONENT);
    zlog_info("DCN-MASTER: setInterestFilter bgp router name: %s" , name.toUri().c_str() );
    m_face.setInterestFilter(name,
        bind(&DcnMaster::onInterest, this, _2),
        std::bind(&DcnMaster::registrationFailed, this, _1)
    );

    m_myRouterPrefix = name.toUri();

    //initializeKey(name);

    return CMD_SUCCESS;
}

int
DcnMaster::unregister_router_name(const char *router_name)
{
  zlog_debug("DCN-MASTER: unregisterint bgp router name: %s" , router_name);
    //m_face.registerPrefix(ndn::Name(routerName),
            //std::bind(&DcnMaster::onRegistrationSuccess, this, _1),
            //std::bind(&DcnMaster::registrationFailed, this, _1));

    ndn::Name bgpInstanceName(router_name);
    bgpInstanceName.append("BGP");

    try {
        m_keyChain.deleteIdentity(m_keyChain.getPib().getIdentity(bgpInstanceName));
    }
    catch (const std::exception& e) {
        //NLSR_LOG_WARN(e.what());
    }
    return CMD_SUCCESS;
}

int 
DcnMaster::add_peer_router_to_ibgp(const char * peer_name)
{
	uint64_t faceId = findFaceId(peer_name);
	if( faceId == 0 ){
    		zlog_err( "Failed to add peer into iBGP: %s" , peer_name );
		return CMD_WARNING;
	}
	zlog_err( "Success to add peer into iBGP: %s" , peer_name );

	register_prefix(m_confParam.getSyncPrefix().toUri().c_str(), faceId, 0, false);
	register_prefix(m_confParam.getSyncUserPrefix().toUri().c_str(), faceId, 0, false);
	
    return CMD_SUCCESS;
}

void
DcnMaster::onFaceIdIndicationFailure(const ndn::nfd::ControlResponse& cr)
{
    zlog_err( "Failed to enable incoming face id indication feature: (code: %d)" ,cr.getCode() );
}

void DcnMaster::onInterest(const ndn::Interest& interest)
{
    // Interest: /<neighbor>/DBGP/<message-type>/<origin>/TimeStamp/params

    ndn::Name interestName(interest.getName());

    ndn::Name neighbor;
    int32_t dbgp_pos = getNameComponentPosition(interestName, DcnMaster::DBGP_COMPONENT);
    neighbor = interestName.getPrefix(dbgp_pos);
    std::string message_type = interestName.get(dbgp_pos+1).toUri();
    ndn::Name originRouter = interestName.getSubName(dbgp_pos+2, interestName.size() - (dbgp_pos + 4));
    zlog_debug("Type: %s, Neighbor: %s, OriginRouter: %s => %s" ,  
            message_type.c_str(), neighbor.toUri().c_str(), originRouter.toUri().c_str(),
            interest.getName().toUri().c_str() );

    DCN_STATUS_T status{0,0,0};

    if( message_type == DcnMaster::UPDATE_COMPONENT ){
        ndn::Block block = interest.getApplicationParameters();
        DCN_STATUS_T *sta = (DCN_STATUS_T *)block.value();
        auto it = m_updateMessageStorage.find(sta->aux);
        ndn::Data data(interest.getName());
        if( it != m_updateMessageStorage.end()){
            struct bgp_header * hdr = (struct bgp_header *)it->second;
            uint16_t len = ntohs(hdr->length);
            data.setContent( it->second, len );
            zlog_debug("Seq: %ld Update's Size: %d" , sta->aux, len);
        }
        data.setFreshnessPeriod(100_ms);
        if( m_confParam.getSignerType() == ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256 )
            m_keyChain.sign( data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256) );
        else{
            auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
            //auto cert = m_keyChain.getPib().getIdentity(ndn::Name(m_confParam.getIdentity())).getDefaultKey().getDefaultCertificate();
            m_keyChain.sign( data, ndn::security::signingByCertificate(cert) );
            //m_keyChain.sign(data, m_signingInfo);
        }
        m_face.put(data);

    }else if( message_type == DcnMaster::UPDATE_NEW_COMPONENT ){
        ndn::Block block = interest.getApplicationParameters();

        ndn::Name name(originRouter);
        name.append(DcnMaster::DBGP_COMPONENT);
        name.append(DcnMaster::UPDATE_COMPONENT);
        name.append(m_myRouterPrefix);
        name.appendTimestamp();

        ndn::Interest updateInterest(name);

        updateInterest.setMustBeFresh(true);
        updateInterest.setCanBePrefix(false);
        updateInterest.setApplicationParameters( std::make_shared<Buffer>(block.value(), block.value_size()) );

        m_face.expressInterest(updateInterest,
                bind(&DcnMaster::onData, this, _1, _2),
                bind(&DcnMaster::onNack, this, _1, _2),
                bind(&DcnMaster::onTimeout, this, _1));

    }else if( message_type == DcnMaster::OPEN_COMPONENT ){

        ndn::Block open = interest.getApplicationParameters();

        ndn::Data data(interest.getName());
        data.setFreshnessPeriod(1_ms);
        
        auto peer = findPeer(originRouter.toUri());
        if(peer){
            dcn_peer_open_interest_receive(peer, open.value_size(), open.value());
            auto it = m_openMessageStore.find(originRouter.toUri());
            if( it != m_openMessageStore.end() ){
                zlog_debug( "Found OPEN Message from m_openMessageStore:%s", originRouter.toUri().c_str());
                auto open = it->second;
                data.setContent( open->data(), open->size() );
            }else{
                zlog_debug( "Not Found OPEN Message with :%s in m_openMessageStore...", originRouter.toUri().c_str());
                struct bgp_header hdr;
                hdr.type = DCN_BGP_MSG_NO_NEIGHBOR;
                data.setContent( (uint8_t *)&hdr, sizeof(struct bgp_header) );
            }
        }else{
            struct bgp_header hdr;
            hdr.type = DCN_BGP_MSG_NO_NEIGHBOR;
            data.setContent( (uint8_t *)&hdr, sizeof(struct bgp_header) );

        }

        if( m_confParam.getSignerType() == ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256 )
            m_keyChain.sign( data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256) );
        else{
            auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
            m_keyChain.sign( data, ndn::security::signingByCertificate(cert) );
            //m_keyChain.sign(data, m_signingInfo);
        }
        m_face.put(data);
    }else if( message_type == DcnMaster::KEEPALIVE_COMPONENT ){

        auto block = interest.getApplicationParameters();
        auto peer = findPeer(originRouter.toUri());
        ndn::Data data(interest.getName());
        if(peer){

            toss_message_to_bgp(originRouter.toUri() , DCN_BGP_MSG_KEEPALIVE, block.value_size(), block.value());
            data.setContent( block.value(), block.value_size() );

        }else{
            struct bgp_header hdr;
            hdr.type = DCN_BGP_MSG_NO_NEIGHBOR;
            data.setContent( (uint8_t *)&hdr, sizeof(struct bgp_header) );
        }

        data.setFreshnessPeriod(1_ms);

        if( m_confParam.getSignerType() == ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256 ){
            auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
            m_keyChain.sign( data, ndn::security::signingByCertificate(cert) );
            //m_keyChain.sign( data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256) );
        }else{
            m_keyChain.sign(data, m_signingInfo);
        }
        m_face.put(data);
    }else if( message_type == DcnMaster::NOTIFICATION_COMPONENT ){
        ndn::Block noti = interest.getApplicationParameters();
        toss_message_to_bgp(originRouter.toUri() , DCN_BGP_MSG_NOTIFY, noti.value_size(), noti.value());

        ndn::Data data(interest.getName());
        data.setFreshnessPeriod(1_ms);
        status.code = DCN_ERR_NO;
        data.setContent( (uint8_t *)&status, sizeof(DCN_STATUS_T) );
        if( m_confParam.getSignerType() == ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256 )
            m_keyChain.sign( data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256) );
        else{
            auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
            m_keyChain.sign( data, ndn::security::signingByCertificate(cert) );
            //m_keyChain.sign(data, m_signingInfo);
        }
        m_face.put(data);
    }else{
        zlog_debug( "Warning +++++ Interest's Name %s from %s" 
                ,interest.getName().toUri().c_str(),  originRouter.toUri().c_str());
    }

}

void
DcnMaster::onFaceEventNotification(const ndn::nfd::FaceEventNotification& faceEventNotification)
{
#if 0
    uint64_t faceId = faceEventNotification.getFaceId();

     std::multimap<uint64_t,std::string>::iterator it = m_namePrefixTable.equal_range(faceId).first;

     std::string uri;

                if( faceEventNotification.getRemoteUri().find("ether") != std::string::npos )
                    uri = faceEventNotification.getLocalUri();
                else
                    uri = faceEventNotification.getRemoteUri();

    switch (faceEventNotification.getKind()) {
        case ndn::nfd::FACE_EVENT_DESTROYED: 
            {
                 for (it=m_namePrefixTable.equal_range(faceId).first; it!=m_namePrefixTable.equal_range(faceId).second; ++it) {
                     std::cout << (*it).first << " => " << (*it).second << '\n';
                     //if( (*it).first == nexthop and (*it).second == prefix )
                     //   m_namePrefixTable.erase(it);
                 }

                 m_faceUriMap.erase( uri );
            }
            break;
        case ndn::nfd::FACE_EVENT_CREATED: 
            {
                // "dev", "ether", "fd", "udp4 or udp6", "tcp4 or tcp6"
                // Find the neighbor in our adjacency list
                try {
                        m_faceUriMap[ uri ] = faceId;

                    for (it=m_namePrefixTable.equal_range(faceId).first; it!=m_namePrefixTable.equal_range(faceId).second; ++it) {
                        std::cout << "face: " << (*it).first << " nexthop => " << (*it).second << '\n';
                        //if( (*it).first == nexthop and (*it).second == prefix )
                        //   m_namePrefixTable.erase(it);
                    }
                }
                catch (const std::exception& e) {
                    zlog_notice("ExceptioN -----> %s",  e.what());
                    return;
                }
                break;
            }
        default:
            break;
    }
#endif
}

int DcnMaster::unregister_peer_router(const char* peer)
{
    erasePeer( peer );
    m_openMessageStore.erase(peer);

#if 0
    ndn::Name peerRouter(peer);
	zlog_info( "unregister peer router - finish connection along peer[%s] router", peer);

	peerRouter.append(DISCONNECT_COMPONENT);
    peerRouter.appendTimestamp();

	Interest interest(peerRouter);

	interest.setMustBeFresh(true);
	interest.setCanBePrefix(false);

	interest.setApplicationParameters((uint8_t *)m_myRouterPrefix.c_str(), m_myRouterPrefix.length());

	m_face.expressInterest(interest,
			bind(&DcnMaster::onData, this, _1, _2),
			bind(&DcnMaster::onNack, this, _1, _2),
			bind(&DcnMaster::onTimeout, this, _1));
#endif
    return CMD_SUCCESS;
}

int DcnMaster::toss_message_to_bgp(std::string origin_router, uint8_t type, size_t length, const uint8_t *message)
{
	zlog_info( "Toss A Message To BGP - originRouter: [%s] router type:%d", origin_router.c_str(), type);
	struct peer *peer = findPeer(origin_router);
	if(peer != nullptr){
		bgp_read_from_dcn(peer, type, length, message);
		return CMD_SUCCESS;
	}
	return CMD_WARNING;
}

uint64_t DcnMaster::get_nexthop_face(const char* nexthop)
{
	zlog_info( "get NextHop Face:%s", nexthop);
    getRouteFromRibDataset(nexthop);
    return CMD_SUCCESS;
}

void DcnMaster::getRouteFromRibDataset(const char *nh)
{
    uint64_t nh_list[1024]={0,};
    uint8_t nh_num=0;
    m_controller.fetch<ndn::nfd::RibDataset>(
            [&] (const std::vector<RibEntry>& dataset) {
            for (const RibEntry& entry : dataset) {
            if( entry.getName().toUri() == nh ){

                for (const ndn::nfd::Route& route : entry.getRoutes()) {
                    nh_list[nh_num++] = route.getFaceId();
                }
            }
            }
            zlog_info( "getRouteFromRibDataset -> nh: %s, nh_num:%d", nh, nh_num);
            for(int i=0;i<=nh_num;i++)
                dcn_bgp_nexthop_update(nh, nh_list, i);

            }, 
            [=] (uint32_t code, const std::string& reason) {
            // failure
            },
            ndn::nfd::CommandOptions()
                .setTimeout(time::duration_cast<time::milliseconds>(4_ms))

                );
}

std::shared_ptr<ndn::security::Certificate> 
DcnMaster::initializeKey(ndn::Name prefix)
{
    zlog_debug(" initializeKey with %s", prefix.toUri().c_str());
    ndn::Name bgpInstanceName(prefix);
    bgpInstanceName.append("BGP");

    try {
        m_keyChain.deleteIdentity(m_keyChain.getPib().getIdentity(bgpInstanceName));
    }
    catch (const std::exception& e) {
        //NLSR_LOG_WARN(e.what());
        zlog_debug("initializeKey Error with %s", e.what());
    }

    ndn::security::Identity bgpInstanceIdentity;
    try {
        bgpInstanceIdentity = m_keyChain.createIdentity(bgpInstanceName);
    }
    catch (const std::exception& e) {
        //NLSR_LOG_ERROR(e.what());
        //NLSR_LOG_ERROR("Unable to create identity, NLSR will run without security!");
        //NLSR_LOG_ERROR("Can be ignored if running in non-production environments.");
        return nullptr;
    }

    auto certificate = std::make_shared<ndn::security::Certificate>();
    auto bgpInstanceKey = bgpInstanceIdentity.getDefaultKey();
    ndn::Name certificateName = bgpInstanceKey.getName();
    certificateName.append("NA");
    certificateName.appendVersion();

    certificate->setName(certificateName);

    // set metainfo
    certificate->setContentType(ndn::tlv::ContentType_Key);
    certificate->setFreshnessPeriod(365_days);

    // set content
    certificate->setContent(bgpInstanceKey.getPublicKey().data(),
            bgpInstanceKey.getPublicKey().size());

    // set signature-info
    ndn::SignatureInfo signatureInfo;
    signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(ndn::time::system_clock::TimePoint(),
                ndn::time::system_clock::now() + 365_days));

    try {
        m_keyChain.sign(*certificate,
                ndn::security::SigningInfo(m_keyChain.getPib().getIdentity(prefix))
                .setSignatureInfo(signatureInfo));
    }
    catch (const std::exception& e) {
        //SR_LOG_ERROR("Router's " << e.what() << ", NLSR is running without security. " <<
         //       "If security is enabled in the configuration, NLSR will not converge.");
    }

    m_signingInfo = ndn::security::SigningInfo(ndn::security::SigningInfo::SIGNER_TYPE_ID,
            bgpInstanceName);

    //loadCertToValidator(*certificate);
    //m_validator.loadAnchor("Authoritative-Certificate", ndn::security::Certificate(*certificate));
    //m_validator.load("/usr/local/etc/dcn-bgpd.conf");
    //m_prefixUpdateValidator.loadAnchor("Authoritative-Certificate", ndn::security::Certificate(cert));

    //m_keyChain.addCertificate(bgpInstanceKey, *certificate);
    return certificate;
}

void DcnMaster::terminate()
{
    zlog_info("DCN-MASTER terminating... m_ribTable.size():%ld", m_ribTable.size());
    for (const auto& it : m_ribTable) {
        zlog_debug("unregister -> prefix: %s / nexthop: %ld", it.first.toUri().c_str(), it.second);
        unregister_prefix(it.first.toUri().c_str(), it.second);
    }

}

int DcnMaster::redistribute_static()
{
    m_redStatic = true;
}

void DcnMaster::sch_red_static()
{
    //zlog_debug("scheduling ... redistributing static");
    std::map<std::string, uint64_t> table;

    m_controller.fetch<ndn::nfd::RibDataset>(
            [&] (const std::vector<RibEntry>& dataset) {

            std::string prefix_list;
            if(m_redStatic){
                for (const RibEntry& entry : dataset) {
                    for (const ndn::nfd::Route& route : entry.getRoutes()) {
                        if( route.getOrigin()==ndn::nfd::ROUTE_ORIGIN_STATIC )
                            if( m_ribStaticTable.find(entry.getName().toUri()) == m_ribStaticTable.end() ){
                                m_ribStaticTable[entry.getName().toUri()] = false;
                            }
                    }
                }

                for (std::map<std::string,bool>::iterator it=m_ribStaticTable.begin(); it!=m_ribStaticTable.end(); ++it){
                    if(it->second==false){
                        zlog_debug( "to be updated: %s" , it->first.c_str() );
                        prefix_list.append(it->first);
                        prefix_list.append(",");
                        it->second = true;
                    }
                }
                if(prefix_list.length() > 0)
                    bgp_redistribute_from_dcn(prefix_list.c_str(), prefix_list.length(), false);
            }else{
                if(m_ribStaticTable.size()>0){
                    for (std::map<std::string,bool>::iterator it=m_ribStaticTable.begin(); it!=m_ribStaticTable.end(); ++it){
                        zlog_debug( "to be deleted: %s" , it->first.c_str() );
                        prefix_list.append(it->first);
                        prefix_list.append(",");
                    }
                    if(prefix_list.length() > 0){
                        bgp_redistribute_from_dcn(prefix_list.c_str(), prefix_list.length(), true);
                    }
                    m_ribStaticTable.clear();
                }
            }

            },
            [=] (uint32_t code, const std::string& reason) {
            // failure
            },
            ndn::nfd::CommandOptions()
            .setTimeout(time::duration_cast<time::milliseconds>(4_ms))

            );

     m_scheduler.schedule(
            ndn::time::seconds(RIB_REFRESH_TIME), 
            std::bind(&DcnMaster::sch_red_static, this)
    );
}

int DcnMaster::no_redistribute_static()
{
    zlog_info("no redistributing static");
    m_redStatic = false;
    return CMD_SUCCESS;
}

//int DcnMaster::update_nexthop(std::list<std::string>& prefixes, std::list<uint64_t>& faces)
int DcnMaster::update_nexthop(const char *prefix, uint64_t face, uint64_t cost)
{
    zlog_info("Update Nexthop ...");

    auto it = m_ribTable.find(prefix);
    if( it != m_ribTable.end() ){
        unregister_prefix(prefix, it->second);
        register_prefix(prefix, face, cost , true);
    }
    return CMD_SUCCESS;
}

}
