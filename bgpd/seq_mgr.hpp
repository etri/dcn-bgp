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

#ifndef _SEQ_MGR_HPP
#define _SEQ_MGR_HPP

#include <list>
#include <string>
#include <iostream>

namespace dcn {

class SeqMgr
{
public:
  SeqMgr(const std::string& filePath);

  void
  setUpdateSeq(uint64_t seqNo)
  {
        m_updateSeq = seqNo;
  }

  uint64_t
  getUpdateSeq()
  {
        return m_updateSeq;
  }

  void
  increaseUpdateSeq()
  {
    m_updateSeq++;
  }

  void
  writeSeqNoToFile() const;

  void
  initiateSeqNoFromFile();

private:
  void
  setSeqFileDirectory(const std::string& filePath);

  void
  writeLog() const;

private:
  uint64_t m_updateSeq = 0;
  std::string m_seqFileNameWithPath;

};

} 
#endif 
