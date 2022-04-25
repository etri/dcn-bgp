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

#ifndef __DCN_MASTER_HPP__
#define __DCN_MASTER_HPP__

#include "dcn_conf_parameter.hpp"
#include "seq_mgr.hpp"

#include <PSync/full-producer.hpp>

#include <iostream>
#include <tuple>
#include <functional>
#include <atomic>
#include <vector>
#include <condition_variable>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/certificate-fetcher-direct-fetch.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/signing-info.hpp>
#include <ndn-cxx/net/face-uri.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/mgmt/nfd/face-event-notification.hpp>
#include <ndn-cxx/mgmt/nfd/face-monitor.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/mgmt/dispatcher.hpp>
#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/util/segment-fetcher.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/encoding/nfd-constants.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/mgmt/nfd/control-parameters.hpp>
#include <ndn-cxx/mgmt/nfd/control-response.hpp>
#include <ndn-cxx/mgmt/nfd/status-dataset.hpp>
#include <ndn-cxx/ims/in-memory-storage-persistent.hpp>

#include "filter.h"
#include "bgpd.h"
#include "lib/stream.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/composite_key.hpp>

using namespace ndn::security::v2;

namespace dcn{

	namespace bmi = boost::multi_index;
	using boost::multi_index_container;
	using namespace boost::multi_index;

	struct Peer
	{
		std::string name;
		uint64_t    id;
		struct peer *peer;
        Peer(const std::string _name, const uint64_t _id, const struct peer *_peer)
            : name(_name), id(_id), peer(_peer)
        {}
	};
	struct byId{};
	struct byName{};

    class DcnMaster
    {
	    public:
#if 1
            enum class Type {
                OPEN,
                KEEPALIVE,
                NOTIFICATION,
                UPDATE,
                NEW
            };
#endif
	using PeerContainer =  boost:: multi_index_container< Peer,
		indexed_by<
			hashed_unique< 
				tag<byName>,  member<Peer,std::string, &Peer::name>
			>,
			hashed_non_unique< 
				tag<byId>,  member<Peer,uint64_t, &Peer::id>
			>
		> 
	> ;

            using FetchDatasetCallback = std::function<void(const std::vector<ndn::nfd::FaceStatus>&)>;
            using FetchDatasetTimeoutCallback = std::function<void(uint32_t, const std::string&)>;
            DcnMaster(ndn::Face& face, ndn::KeyChain& keyChain, DCN_CP &confParam);
            ndn::util::signal::Signal<DcnMaster, const ndn::Data&> afterSegmentValidatedSignal;

	    private:
            void onTimeout(const ndn::Interest& interest);
            void onNack(const ndn::Interest& interest, const ndn::lp::Nack& nack);
            void onData(const ndn::Interest& interest, const ndn::Data& data);
            //void onSyncUpdateData(const ndn::Interest& interest, const ndn::Data& data);
            void onDataValidationSuccess(const ndn::Data& data);
            void onDataValidationFailure(const ndn::Data& data, const ValidationError& error);

            void enableIncomingFaceIdIndication();
            void onFaceIdIndicationSuccess(const ndn::nfd::ControlParameters& cp);
            void onFaceIdIndicationFailure(const ndn::nfd::ControlResponse& cr);
            void onFaceEventNotification(const ndn::nfd::FaceEventNotification& faceEventNotification);
            void scheduleDatasetFetch();
            void onFaceDatasetFetchTimeout( uint32_t code, const std::string& msg, uint32_t nRetriesSoFar );
            void processFaceDataset(const std::vector<ndn::nfd::FaceStatus>& faces);
            void initializeFaces(const FetchDatasetCallback& onFetchSuccess,
                      const FetchDatasetTimeoutCallback& onFetchFailure);

            void registrationFailed(const ndn::Name& name);
            void onRegistrationSuccess(const ndn::Name& name);

            void onRegistrationSuccess1(const ndn::nfd::ControlParameters& );
            void onRegistrationFailure(const ndn::nfd::ControlResponse& ,
                const ndn::nfd::ControlParameters& , uint64_t );

            //void onPSyncUpdate(const std::vector<psync::MissingDataInfo>& updates); 
            void onInterest(const ndn::Interest& interest);
            //void setUpdateInterestFilter();
            //void processUpdateInterestForIBGP(const ndn::Name& name, const ndn::Interest& interest);

            void onBgpKeyInterest(const ndn::Name& name,const ndn::Interest& interest);
            void setStrategies();
            void onSetStrategySuccess(const ndn::nfd::ControlParameters& commandSuccessResult);
            void onSetStrategyFailure(const ndn::nfd::ControlResponse& response,
                          const ndn::nfd::ControlParameters& parameters);

            //void afterFetchUpdate(const ndn::ConstBufferPtr& bufferPtr, const ndn::Name& interestName, uint64_t);
            //void onFetchUpdateError(uint32_t errorCode, const std::string& msg,
             //       const ndn::Name& interestName, uint32_t retransmitNo,
              //      const ndn::time::steady_clock::TimePoint& deadline,
               //     ndn::Name lsaName, uint64_t seqNo);


	    bool exist_dcn_face(uint64_t faceId)
	    {
		    std::map<std::string, uint64_t>::iterator it;
		    for (it=m_faceUriMap.begin(); it!=m_faceUriMap.end(); ++it)
			    if(faceId == it->second)
				    return true;

		    return false;
	    }

	    std::tuple<uint64_t, ndn::FaceUri> get_dcn_face(const char*uri_str)
	    {
            auto it = m_faceUriMap.find(std::string(uri_str));
            if( it != m_faceUriMap.end() )
				    return std::make_tuple(it->second, ndn::FaceUri(it->first));

		    return std::make_tuple(0, ndn::FaceUri(uri_str));
	    }

            static const std::string MULTICAST_STRATEGY;
            static const std::string BEST_ROUTE_V2_STRATEGY;

            void
            expressUpdateSyncInterest(const ndn::Name& interestName, uint32_t timeoutCount,
                ndn::time::steady_clock::TimePoint deadline = ndn::time::steady_clock::TimePoint::min());

	    void getRouteFromRibDataset(const char*);
	    void sch_red_static();
            int add_peer_router_to_ibgp(const char *);
            int remove_peer_router_from_ibgp(const char *);
            int send_update_message(const struct peer *, uint64_t , uint8_t *);
        public:
            /* BGP ---> DCN  APIs*/
            int add_network(const char* prefix, uint64_t nexthop, uint64_t cost);
            int remove_network(const char* prefix, uint64_t nexthop);
            int register_router_name(const char*);
            int unregister_router_name(const char*);
            void send_bgp_message(const struct peer * , uint64_t , uint8_t *);
            uint64_t register_peer_router(const char*, const char *, const struct peer *);
            uint64_t get_nexthop_face(const char*);
            int unregister_peer_router(const char*);
	    int open_peer_connection(struct peer *);
	    int close_peer_connection(struct peer *);
	    bool get_face_uri(uint64_t, char *);
        int redistribute_static();
        int no_redistribute_static();
        //int update_nexthop(std::list<std::string>&, std::list<uint64_t>&);
        int update_nexthop(const char *, uint64_t, uint64_t);
            /* END */
            
            /* DCN ---> BGP */

            /* EDN */
        void terminate();
        private:

            //uint64_t publish_update_for_ibgp(uint16_t length, uint8_t *message, uint64_t);
            int toss_message_to_bgp( std::string, uint8_t, size_t, const uint8_t *);
            int register_prefix(const char *prefix, uint64_t nexthop, uint64_t faceCost, bool);
            int unregister_prefix(const char *prefix, uint64_t nexthop);

            void emitSegmentValidatedSignal(const ndn::Data& data)
            {
                afterSegmentValidatedSignal(data);
            }


	    uint64_t findFaceId(const char * peer) //const
	    {
		auto &peers_index = m_peers.get<byName>();	
		auto it = peers_index.find(peer);
		return it != peers_index.end() ? it->id : 0;
	    }
            void insertPeer(const char *name, const struct peer *_peer)
            {
                m_peers.insert({name, 0, _peer});
            }

            void insertPeer(const char *name, uint64_t faceId, const struct peer *_peer)
            {
                m_peers.insert({name, faceId, _peer});
            }
	    struct peer * findPeer(std::string name)
	    {
		auto &peers_index = m_peers.get<byName>();
		auto it = peers_index.find(name);
		return it != peers_index.end() ? it->peer : nullptr;
	    }

        void erasePeer(std::string name)
         {
         auto &peers_index = m_peers.get<byName>();
         peers_index.erase(name);
         }

	    struct peer * findPeer(uint64_t id)
	    {
		auto &peers_index = m_peers.get<byId>();
		auto it = peers_index.find(id);
		return it != peers_index.end() ? it->peer : nullptr;
	    }

        std::shared_ptr<ndn::security::Certificate> initializeKey(ndn::Name);
        private:
            ndn::Face& m_face; 
            DCN_CP& m_confParam;

            ndn::nfd::Controller m_controller;
            ndn::nfd::FaceMonitor m_faceMonitor;
            ndn::security::ValidatorConfig m_validator;
            ndn::security::SigningInfo m_signingInfo;
            ndn::nfd::Controller m_faceDatasetController;
            ndn::Scheduler m_scheduler;
            bool m_redStatic=false;

            static const std::string UPDATE_COMPONENT;
            static const std::string UPDATE_NEW_COMPONENT;
            static const std::string OPEN_COMPONENT;
            static const std::string KEEPALIVE_COMPONENT;
            static const std::string NOTIFICATION_COMPONENT;
            static const std::string REFRESH_COMPONENT;
            static const std::string CAPABILITY_COMPONENT;
            static const std::string CONNECT_COMPONENT;
            static const std::string DISCONNECT_COMPONENT;
            static const std::string DBGP_COMPONENT;

            std::map<std::string, std::shared_ptr<ndn::Buffer>> m_openMessageStore;
            std::map<std::string, uint64_t> m_faceUriMap;
            std::map<ndn::Name, uint64_t> m_ribTable;
            std::map<std::string, bool> m_ribStaticTable;
	    
	    PeerContainer m_peers;

            std::string m_myRouterPrefix;
            std::map<uint64_t, uint8_t *> m_updateMessageStorage; //iBGP and eBGP 모두 사용
            SeqMgr m_sequencingManager;
            ndn::KeyChain& m_keyChain;
    };

}

#endif
