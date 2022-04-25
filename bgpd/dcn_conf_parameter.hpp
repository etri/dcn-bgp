
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2020,  The University of Memphis,
 *                           Regents of the University of California,
 *                           Arizona Board of Regents.
 *
 * This file is part of NLSR (Named-data Link State Routing).
 * See AUTHORS.md for complete list of NLSR authors and contributors.
 *
 * NLSR is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NLSR is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NLSR, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#ifndef DCN_CONF_PARAMETER_HPP
#define DCN_CONF_PARAMETER_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/certificate-fetcher-direct-fetch.hpp>
#include <ndn-cxx/security/signing-info.hpp>

namespace dcn {

class DCN_CP
{
public:
  DCN_CP(ndn::Face& face, ndn::KeyChain& keyChain,
                const std::string& confFileName = "dbgpd.conf");

  const std::string&
  getConfFileName()
  {
    return m_confFileName;
  }

  void
  setISP(const ndn::Name& ispName);

  const ndn::Name&
  getISP() const
  {
    return m_ispName;
  }

    void
  setNetwork(const ndn::Name& networkName);

  const ndn::Name&
  getNetwork() const
  {
    return m_network;
  }


  void
  setRouterName(const ndn::Name& routerName)
  {
    m_routerName = routerName;
  }

  const ndn::Name&
  getRouterName() const
  {
    return m_routerName;
  }

  void
  setAS(const ndn::Name& asName)
  {
    m_asName = asName;
  }

  const ndn::Name&
  getAS() const
  {
    return m_asName;
  }

  void
  buildRouterAndSyncUserPrefix()
  {
    m_routerPrefix = m_ispName;
    m_routerPrefix.append(m_asName);
    m_routerPrefix.append(m_routerName);
  }

  const ndn::Name&
  getRouterPrefix() const
  {
    return m_routerPrefix;
  }

  const ndn::Name&
  getSyncUserPrefix() const
  {
    return m_syncUserPrefix;
  }

  const ndn::Name&
  getSyncPrefix() const
  {
    return m_syncPrefix;
  }


  void
  setFaceDatasetFetchTries(uint32_t count)
  {
    m_faceDatasetFetchTries = count;
  }

  uint32_t
  getFaceDatasetFetchTries() const
  {
    return m_faceDatasetFetchTries;
  }

  void
  setFaceDatasetFetchInterval(uint32_t interval)
  {
    m_faceDatasetFetchInterval = ndn::time::seconds(interval);
  }

  const ndn::time::seconds
  getFaceDatasetFetchInterval() const
  {
    return m_faceDatasetFetchInterval;
  }

  void
  setInterestRetryNumber(uint32_t irn)
  {
    m_interestRetryNumber = irn;
  }

  uint32_t
  getInterestRetryNumber() const
  {
    return m_interestRetryNumber;
  }

  void
  setStateFileDir(const std::string& ssfd)
  {
    m_stateFileDir = ssfd;
  }

  const std::string&
  getStateFileDir() const
  {
    return m_stateFileDir;
  }

  ndn::security::ValidatorConfig&
  getValidator()
  {
    return m_validator;
  }

  ndn::security::ValidatorConfig&
  getPrefixUpdateValidator()
  {
    return m_prefixUpdateValidator;
  }

  const ndn::security::SigningInfo&
  getSigningInfo() const
  {
    return m_signingInfo;
  }

  void
  addCertPath(const std::string& certPath)
  {
    m_certs.insert(certPath);
  }

  const std::unordered_set<std::string>&
  getIdCerts() const
  {
    return m_certs;
  }

  const ndn::KeyChain&
  getKeyChain() const
  {
    return m_keyChain;
  }

  void setSignerType(ndn::security::SigningInfo::SignerType type)
  {
	  m_signerType = type;
  }

  ndn::security::SigningInfo::SignerType getSignerType()
  {
	return m_signerType;
  }
  std::shared_ptr<ndn::security::Certificate>
  initializeKey();

  void
  loadCertToValidator(const ndn::security::Certificate& cert);

  void
  writeLog();

private:
    std::string m_stateFileDir;
    ndn::security::SigningInfo::SignerType m_signerType;
  ndn::Name m_routerName;
  ndn::Name m_asName;
  ndn::Name m_ispName;
  ndn::Name m_network;
  ndn::Name m_updatePrefix;
  std::string m_confFileName;
  ndn::Name m_routerPrefix;
  ndn::Name m_syncUserPrefix;
  ndn::Name m_syncPrefix;
  uint32_t m_faceDatasetFetchTries;
  ndn::time::seconds m_faceDatasetFetchInterval;
  uint32_t m_interestRetryNumber;

  static const uint64_t SYNC_VERSION;

  ndn::security::ValidatorConfig m_validator;
  ndn::security::ValidatorConfig m_prefixUpdateValidator;
  ndn::security::SigningInfo m_signingInfo;
  std::unordered_set<std::string> m_certs;
  ndn::KeyChain& m_keyChain;
};

} 

#endif
