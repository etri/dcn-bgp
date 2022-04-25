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
#include "seq_mgr.hpp"

#include <string>
#include <fstream>
#include <pwd.h>
#include <cstdlib>
#include <unistd.h>
#include <sstream>

#include "log.h"

namespace dcn {


SeqMgr::SeqMgr(const std::string& filePath)
{
  setSeqFileDirectory(filePath);
  initiateSeqNoFromFile();
}

void
SeqMgr::writeSeqNoToFile() const
{
  writeLog();
  //zlog_info( "writeSeqNoToFile: %s" , m_seqFileNameWithPath.c_str() );
  std::ofstream outputFile(m_seqFileNameWithPath.c_str());
  std::ostringstream os;
  os << "UpdateSeq " << std::to_string(m_updateSeq) ;
  outputFile << os.str();
  outputFile.close();
}

void
SeqMgr::initiateSeqNoFromFile()
{
  zlog_info( "Seq File Name: %s" , m_seqFileNameWithPath.c_str() );
  std::ifstream inputFile(m_seqFileNameWithPath.c_str());

  std::string seqType;
  // Good checks that file is not (bad or eof or fail)
  if (inputFile.good()) {
    inputFile >> seqType >> m_updateSeq;

    inputFile.close();

    // Increment by 10 in case last run of NLSR was not able to write to file
    // before crashing
    m_updateSeq += 10;

  }
  writeLog();
}

void
SeqMgr::setSeqFileDirectory(const std::string& filePath)
{
  m_seqFileNameWithPath = filePath;

  if (m_seqFileNameWithPath.empty()) {
    std::string homeDirPath(getpwuid(getuid())->pw_dir);
    if (homeDirPath.empty()) {
      homeDirPath = getenv("HOME");
    }
    m_seqFileNameWithPath = homeDirPath;
  }
  m_seqFileNameWithPath = m_seqFileNameWithPath + "/nlsrSeqNo.txt";
}

void
SeqMgr::writeLog() const
{
  //zlog_debug( "writeLog - UPDATE Seq No: %d" , m_updateSeq);
}

} 
