
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

#include <iostream>
#include <fstream>

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/net/face-uri.hpp>

#include "dcn_conf_file.hpp"

namespace dcn{

template <class T>
class ConfigurationVariable
{
public:
  typedef std::function<void(T)> DCN_CP;

  ConfigurationVariable(const std::string& key, const DCN_CP& setter)
    : m_key(key)
    , m_setterCallback(setter)
    , m_minValue(0)
    , m_maxValue(0)
    , m_shouldCheckRange(false)
    , m_isRequired(true)
  {
  }

  bool
  parseFromConfigSection(const ConfigSection& section)
  {
    try {
      T value = section.get<T>(m_key);

      if (!isValidValue(value)) {
        return false;
      }

      m_setterCallback(value);
      return true;
    }
    catch (const std::exception& ex) {

      if (m_isRequired) {
        std::cerr << ex.what() << std::endl;
        std::cerr << "Missing required configuration variable" << std::endl;
        return false;
      }
      else {
        m_setterCallback(m_defaultValue);
        return true;
      }
    }

    return false;
  }

  void
  setMinAndMaxValue(T min, T max)
  {
    m_minValue = min;
    m_maxValue = max;
    m_shouldCheckRange = true;
  }

  void
  setOptional(T defaultValue)
  {
    m_isRequired = false;
    m_defaultValue = defaultValue;
  }

private:
  void
  printOutOfRangeError(T value)
  {
    std::cerr << "Invalid value for " << m_key << ": "
              << value << ". "
              << "Valid values: "
              << m_minValue << " - "
              << m_maxValue << std::endl;
  }

  bool
  isValidValue(T value)
  {
    if (!m_shouldCheckRange) {
      return true;
    }
    else if (value < m_minValue || value > m_maxValue)
    {
      printOutOfRangeError(value);
      return false;
    }

    return true;
  }

private:
  const std::string m_key;
  const DCN_CP m_setterCallback;
  T m_defaultValue;

  T m_minValue;
  T m_maxValue;

  bool m_shouldCheckRange;
  bool m_isRequired;
};

ConfFileProcessor::ConfFileProcessor(DCN_CP& confParam)
  : m_confFileName(confParam.getConfFileName())
  , m_confParam(confParam)
{
}

bool
ConfFileProcessor::processConfFile()
{
  bool ret = true;
  std::ifstream inputFile;
  inputFile.open(m_confFileName.c_str());
  if (!inputFile.is_open()) {
    std::string msg = "Failed to read configuration file: ";
    msg += m_confFileName;
    std::cerr << msg << std::endl;
    return false;
  }
  ret = load(inputFile);
  inputFile.close();

  if (ret) {
    m_confParam.buildRouterAndSyncUserPrefix();
    m_confParam.writeLog();
  }

  return ret;
}

bool
ConfFileProcessor::load(std::istream& input)
{
  ConfigSection pt;
  try {
    boost::property_tree::read_info(input, pt);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    std::stringstream msg;
    std::cerr << "Failed to parse configuration file " << std::endl;
    std::cerr << m_confFileName << std::endl;
    return false;
  }

  for (const auto& tn : pt) {
    if (!processSection(tn.first, tn.second)) {
      return false;
    }
  }
  return true;
}

bool
ConfFileProcessor::processSection(const std::string& sectionName, const ConfigSection& section)
{
  bool ret = true;
  if (sectionName == "general")
  {
    ret = processConfSectionGeneral(section);
  }
  else if (sectionName == "security")
  {
    ret = processConfSectionSecurity(section);
  }
  else
  {
    std::cerr << "Wrong configuration section: " << sectionName << std::endl;
  }
  return ret;
}

bool
ConfFileProcessor::processConfSectionGeneral(const ConfigSection& section)
{
    std::string network = section.get<std::string>("network");
    ndn::Name networkName(network);
    if (!networkName.empty()) {
      m_confParam.setNetwork(networkName);
    }
    else {
      std::cerr << " Network can not be null or empty or in bad URI format :(!" << std::endl;
      return false;
    }

    std::string syncProtocol = section.get<std::string>("sync-protocol", "psync");
    //m_confParam.setSyncProtocol(SYNC_PROTOCOL_PSYNC);

    std::string stateDir = section.get<std::string>("state-dir");
    m_confParam.setStateFileDir(stateDir);

  return true;
}

bool
ConfFileProcessor::processConfSectionSecurity(const ConfigSection& section)
{
  ConfigSection::const_iterator it = section.begin();

  if (it == section.end() || it->first != "validator") {
    std::cerr << "Error: Expect validator section!" << std::endl;
    return false;
  }

  m_confParam.getValidator().load(it->second, m_confFileName);

  it++;
  if (it != section.end() && it->first == "signer-type") {

      std::string type = it->second.data();

      if( type == "SHA256" )
        m_confParam.setSignerType(ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256);
  }
    std::cout << "Security - SignerType:" << m_confParam.getSignerType() << std::endl;

  return true;
}

}
