
#include "certificate-store.hpp"
#include "dcn_conf_parameter.hpp"

#include <ndn-cxx/util/io.hpp>

namespace dcn {
namespace security {


CertificateStore::CertificateStore(ndn::Face& face, ConfParameter& confParam, DcnMaster& dcn)
  : m_face(face)
  , m_confParam(confParam)
  , m_dcnMaster(dcn)
  , m_validator(m_confParam.getValidator())
  , m_afterSegmentValidatedConnection(m_dcnMaster.afterSegmentValidatedSignal.connect(
                                      std::bind(&CertificateStore::afterFetcherSignalEmitted,
                                                this, _1)))
{
  for (const auto& x: confParam.getIdCerts()) {
    auto idCert = ndn::io::load<ndn::security::Certificate>(x);
    insert(*idCert);
  }

  registerKeyPrefixes();
}

void
CertificateStore::insert(const ndn::security::Certificate& certificate)
{
  m_certificates[certificate.getKeyName()] = certificate;
  std::cout << "Certificate inserted successfully" << std::endl;
}

const ndn::security::Certificate*
CertificateStore::find(const ndn::Name& keyName) const
{
  auto it = m_certificates.find(keyName);
  return it != m_certificates.end() ? &it->second : nullptr;
}

void
CertificateStore::clear()
{
  m_certificates.clear();
}

void
CertificateStore::setInterestFilter(const ndn::Name& prefix, bool loopback)
{
  m_face.setInterestFilter(ndn::InterestFilter(prefix).allowLoopback(loopback),
                           std::bind(&CertificateStore::onKeyInterest, this, _1, _2),
                           std::bind(&CertificateStore::onKeyPrefixRegSuccess, this, _1),
                           std::bind(&CertificateStore::registrationFailed, this, _1),
                           m_confParam.getSigningInfo(), ndn::nfd::ROUTE_FLAG_CAPTURE);
}

void
CertificateStore::registerKeyPrefixes()
{
  std::vector<ndn::Name> prefixes;

  // Router's NLSR certificate
  ndn::Name nlsrKeyPrefix = m_confParam.getRouterPrefix();
  nlsrKeyPrefix.append("nlsr");
  nlsrKeyPrefix.append(ndn::security::Certificate::KEY_COMPONENT);
  prefixes.push_back(nlsrKeyPrefix);

  // Router's certificate
  ndn::Name routerKeyPrefix = m_confParam.getRouterPrefix();
  routerKeyPrefix.append(ndn::security::Certificate::KEY_COMPONENT);
  prefixes.push_back(routerKeyPrefix);

  // Router's operator's certificate
  ndn::Name operatorKeyPrefix = m_confParam.getNetwork();
  //MODORI
  //operatorKeyPrefix.append(m_confParam.getSiteName());
  operatorKeyPrefix.append(std::string("%C1.Operator"));
  prefixes.push_back(operatorKeyPrefix);

  // Router's site's certificate
  ndn::Name siteKeyPrefix = m_confParam.getNetwork();
  //MODORI
  //siteKeyPrefix.append(m_confParam.getSiteName());
  siteKeyPrefix.append(ndn::security::Certificate::KEY_COMPONENT);
  prefixes.push_back(siteKeyPrefix);

  // Start listening for interest of this router's NLSR certificate,
  // router's certificate and site's certificate
  for (const auto& i : prefixes) {
    setInterestFilter(i);
  }
}

void
CertificateStore::onKeyInterest(const ndn::Name& name, const ndn::Interest& interest)
{
  std::cout << "Got interest for certificate. Interest: " << interest.getName() << std::endl;

  const auto* cert = find(interest.getName());

  if (!cert) {
    std::cout << "Certificate is not found for: " << interest << std::endl;
    return;
  }
  m_face.put(*cert);
}

void
CertificateStore::onKeyPrefixRegSuccess(const ndn::Name& name)
{
  //NLSR_LOG_DEBUG("KEY prefix: " << name << " registration is successful");
}

void
CertificateStore::registrationFailed(const ndn::Name& name)
{
  //NLSR_LOG_ERROR("Failed to register prefix " << name);
  //NDN_THROW(std::runtime_error("Prefix registration failed"));
}

void
CertificateStore::publishCertFromCache(const ndn::Name& keyName)
{
  const auto* cert = m_validator.getUnverifiedCertCache().find(keyName);

  if (cert) {
    insert(*cert);
    //NLSR_LOG_TRACE(*cert);
    ndn::Name certName = ndn::security::extractKeyNameFromCertName(cert->getName());
    //NLSR_LOG_TRACE("Setting interest filter for: " << certName);

    setInterestFilter(certName);

    const ndn::Name& keyLocatorName = cert->getSignatureInfo().getKeyLocator().getName();
    if (cert->getKeyName() != keyLocatorName) {
      publishCertFromCache(keyLocatorName);
    }
  }
  else {
    // Happens for root cert
    //NLSR_LOG_TRACE("Cert for " << keyName << " was not found in the Validator's cache. ");
  }
}

void
CertificateStore::afterFetcherSignalEmitted(const ndn::Data& lsaSegment)
{
  const auto keyName = lsaSegment.getSignatureInfo().getKeyLocator().getName();
  if (!find(keyName)) {
    //NLSR_LOG_TRACE("Publishing certificate for: " << keyName);
    publishCertFromCache(keyName);
  }
  else {
    //NLSR_LOG_TRACE("Certificate is already in the store: " << keyName);
  }
}

} // namespace security
} // namespace nlsr
