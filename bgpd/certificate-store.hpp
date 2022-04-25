
#ifndef _CERTIFICATE_STORE_HPP
#define _CERTIFICATE_STORE_HPP

#include "dcn_master.hpp"

#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/validator-config.hpp>

namespace dcn {
class DCN_CP;
namespace security {

/*! \brief Store certificates for names
 *
 * Stores certificates that this router claims to be authoritative
 * for. That is, this stores only the certificates that we will reply
 * to KEY interests with, e.g. when other routers are verifying data
 * we have sent.
 */
class CertificateStore
{

public:
  CertificateStore(ndn::Face& face, DCN_CP& confParam, DcnMaster& dcn);

  void
  insert(const ndn::security::Certificate& certificate);

  /*! \brief Find a certificate
   *
   * Find a certificate that NLSR has. First it checks against the
   * certificates this NLSR claims to be authoritative for, usually
   * something like this specific router's certificate, and then
   * checks the cache of certificates it has already fetched. If none
   * can be found, it will return an null pointer.
 */
  const ndn::security::Certificate*
  find(const ndn::Name& keyName) const;

  /*! \brief Retrieves the chain of certificates from Validator's cache and
   *   store them in Nlsr's own CertificateStore.
   * \param keyName Name of the first key in the certificate chain.
  */
  void
  publishCertFromCache(const ndn::Name& keyName);

  void
  afterFetcherSignalEmitted(const ndn::Data& lsaSegment);

private:
  void
  clear();

  void
  setInterestFilter(const ndn::Name& prefix, const bool loopback = false);

  void
  registerKeyPrefixes();

  void
  onKeyInterest(const ndn::Name& name, const ndn::Interest& interest);

  void
  onKeyPrefixRegSuccess(const ndn::Name& name);

  void
  registrationFailed(const ndn::Name& name);

private:
  typedef std::map<ndn::Name, ndn::security::Certificate> CertMap;
  CertMap m_certificates;
  ndn::Face& m_face;
  DCN_CP& m_confParam;
  DcnMaster& m_dcnMaster;
  ndn::security::ValidatorConfig& m_validator;
  ndn::util::signal::ScopedConnection m_afterSegmentValidatedConnection;
};

} 
}

#endif 
