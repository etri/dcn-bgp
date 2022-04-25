
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

#ifndef DCN_CONF_FILE_HPP
#define DCN_CONF_FILE_HPP

#include "dcn_conf_parameter.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/filesystem.hpp>

namespace dcn {

namespace bf = boost::filesystem;
using ConfigSection = boost::property_tree::ptree;

class ConfFileProcessor
{
public:
  ConfFileProcessor(DCN_CP& confParam);

  bool
  processConfFile();

private:
  bool
  load(std::istream& input);

  bool
  processSection(const std::string& sectionName, const ConfigSection& section);

  bool
  processConfSectionGeneral(const ConfigSection& section);

  bool
  processConfSectionNeighbors(const ConfigSection& section);

  bool
  processConfSectionHyperbolic(const ConfigSection& section);

  bool
  processConfSectionFib(const ConfigSection& section);

  bool
  processConfSectionAdvertising(const ConfigSection& section);

  bool
  processConfSectionSecurity(const ConfigSection& section);

private:
  std::string m_confFileName;
  DCN_CP& m_confParam;
};

} // namespace bgp
#endif // CONF_FILE_PROCESSOR_HPP
