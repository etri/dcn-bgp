
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
#include "dcn_conf_parameter.hpp"

namespace dcn {

// To be changed when breaking changes are made to sync
const uint64_t DCN_CP::SYNC_VERSION = 9;

static std::unique_ptr<ndn::security::CertificateFetcherDirectFetch>
makeCertificateFetcher(ndn::Face& face)
{
  auto fetcher = std::make_unique<ndn::security::CertificateFetcherDirectFetch>(face);
  fetcher->setSendDirectInterestOnly(true);
  return fetcher;
}

DCN_CP::DCN_CP(ndn::Face& face, ndn::KeyChain& keyChain,
                             const std::string& confFileName)
  : m_confFileName(confFileName)
  , m_validator(makeCertificateFetcher(face))
  , m_prefixUpdateValidator(std::make_unique<ndn::security::CertificateFetcherDirectFetch>(face))
  , m_keyChain(keyChain)
  ,m_signerType(ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256)
{
}

void
DCN_CP::setNetwork(const ndn::Name& networkName)
{
    m_network = networkName;
    m_syncPrefix.append("localhop");
    m_syncPrefix.append(m_network);
    m_syncPrefix.append("i-dbgp");
    m_syncPrefix.append("sync");
    m_syncPrefix.appendVersion(DCN_CP::SYNC_VERSION);

    m_syncUserPrefix.append("localhop");
    m_syncUserPrefix.append(m_network);
    m_syncUserPrefix.append("i-dbgp");
    m_syncUserPrefix.append("UPDATE");
}

void
DCN_CP::writeLog()
{
}

void
DCN_CP::setISP(const ndn::Name& ispName)
{
  m_ispName = ispName;

}

void
DCN_CP::loadCertToValidator(const ndn::security::Certificate& cert)
{
  m_validator.loadAnchor("Authoritative-Certificate", ndn::security::Certificate(cert));
  m_prefixUpdateValidator.loadAnchor("Authoritative-Certificate", ndn::security::Certificate(cert));
}

std::shared_ptr<ndn::security::Certificate>
DCN_CP::initializeKey()
{

  ndn::Name nlsrInstanceName(m_routerPrefix);
  nlsrInstanceName.append("bgp");

  try {
    m_keyChain.deleteIdentity(m_keyChain.getPib().getIdentity(nlsrInstanceName));
  }
  catch (const std::exception& e) {
    //NLSR_LOG_WARN(e.what());
  }

  ndn::security::Identity nlsrInstanceIdentity;
  try {
    nlsrInstanceIdentity = m_keyChain.createIdentity(nlsrInstanceName);
  }
  catch (const std::exception& e) {
    return nullptr;
  }
  auto certificate = std::make_shared<ndn::security::Certificate>();
  auto nlsrInstanceKey = nlsrInstanceIdentity.getDefaultKey();
  ndn::Name certificateName = nlsrInstanceKey.getName();
  certificateName.append("NA");
  certificateName.appendVersion();

  certificate->setName(certificateName);

  certificate->setContentType(ndn::tlv::ContentType_Key);

  certificate->setContent(nlsrInstanceKey.getPublicKey().data(),
                          nlsrInstanceKey.getPublicKey().size());

  ndn::SignatureInfo signatureInfo;

  try {
    m_keyChain.sign(*certificate,
                    ndn::security::SigningInfo(m_keyChain.getPib().getIdentity(m_routerPrefix))
                                               .setSignatureInfo(signatureInfo));
  }
  catch (const std::exception& e) {

  }

  m_signingInfo = ndn::security::SigningInfo(ndn::security::SigningInfo::SIGNER_TYPE_ID,
                                             nlsrInstanceName);

  loadCertToValidator(*certificate);

  return certificate;
}

} 
