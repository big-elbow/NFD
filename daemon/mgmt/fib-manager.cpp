/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2025,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "fib-manager.hpp"

#include "common/logger.hpp"
#include "fw/face-table.hpp"
#include "table/fib.hpp"

#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/mgmt/nfd/fib-entry.hpp>

#include <boost/range/adaptor/transformed.hpp>

namespace nfd {

NFD_LOG_INIT(FibManager);

FibManager::FibManager(Fib& fib, const FaceTable& faceTable,
                       Dispatcher& dispatcher, CommandAuthenticator& authenticator)
  : ManagerBase("fib", dispatcher, authenticator)
  , m_fib(fib)
  , m_faceTable(faceTable)
{
  registerCommandHandler<ndn::nfd::FibAddNextHopCommand>([this] (auto&&, auto&&... args) {
    addNextHop(std::forward<decltype(args)>(args)...);
  });
  registerCommandHandler<ndn::nfd::FibRemoveNextHopCommand>([this] (auto&&, auto&&... args) {
    removeNextHop(std::forward<decltype(args)>(args)...);
  });
  registerStatusDatasetHandler("list", [this] (auto&&, auto&&, auto&&... args) {
    listEntries(std::forward<decltype(args)>(args)...);
  });
}

void
FibManager::addNextHop(const Interest& interest, ControlParameters parameters,
                       const CommandContinuation& done)
{
  setFaceForSelfRegistration(interest, parameters);
  const Name& prefix = parameters.getName();
  FaceId faceId = parameters.getFaceId();
  uint64_t cost = parameters.getCost();

  if (prefix.size() > Fib::getMaxDepth()) {
    NFD_LOG_DEBUG("add-nexthop(" << prefix << ',' << faceId << ',' << cost <<
                  ") -> FAIL prefix-too-long");
    return done(ControlResponse(414, "FIB entry prefix cannot exceed " +
                                std::to_string(Fib::getMaxDepth()) + " components"));
  }

  Face* face = m_faceTable.get(faceId);
  if (face == nullptr) {
    NFD_LOG_DEBUG("add-nexthop(" << prefix << ',' << faceId << ',' << cost <<
                  ") -> FAIL unknown-faceid");
    return done(ControlResponse(410, "Face not found"));
  }

  fib::Entry* entry = m_fib.insert(prefix).first;
  m_fib.addOrUpdateNextHop(*entry, *face, cost);

  NFD_LOG_TRACE("add-nexthop(" << prefix << ',' << faceId << ',' << cost << ") -> OK");
  return done(ControlResponse(200, "OK").setBody(parameters.wireEncode()));
}

void
FibManager::removeNextHop(const Interest& interest, ControlParameters parameters,
                          const CommandContinuation& done)
{
  setFaceForSelfRegistration(interest, parameters);
  const Name& prefix = parameters.getName();
  FaceId faceId = parameters.getFaceId();

  done(ControlResponse(200, "OK").setBody(parameters.wireEncode()));

  Face* face = m_faceTable.get(faceId);
  if (face == nullptr) {
    NFD_LOG_TRACE("remove-nexthop(" << prefix << ',' << faceId << ") -> OK no-face");
    return;
  }

  fib::Entry* entry = m_fib.findExactMatch(parameters.getName());
  if (entry == nullptr) {
    NFD_LOG_TRACE("remove-nexthop(" << prefix << ',' << faceId << ") -> OK no-entry");
    return;
  }

  auto status = m_fib.removeNextHop(*entry, *face);
  switch (status) {
    case Fib::RemoveNextHopResult::NO_SUCH_NEXTHOP:
      NFD_LOG_TRACE("remove-nexthop(" << prefix << ',' << faceId << ") -> OK no-nexthop");
      break;
    case Fib::RemoveNextHopResult::FIB_ENTRY_REMOVED:
      NFD_LOG_TRACE("remove-nexthop(" << prefix << ',' << faceId << ") -> OK entry-erased");
      break;
    case Fib::RemoveNextHopResult::NEXTHOP_REMOVED:
      NFD_LOG_TRACE("remove-nexthop(" << prefix << ',' << faceId << ") -> OK nexthop-removed");
      break;
  }
}

void
FibManager::listEntries(ndn::mgmt::StatusDatasetContext& context)
{
  for (const auto& entry : m_fib) {
    const auto& nexthops = entry.getNextHops() |
                           boost::adaptors::transformed([] (const fib::NextHop& nh) {
                             return ndn::nfd::NextHopRecord()
                                 .setFaceId(nh.getFace().getId())
                                 .setCost(nh.getCost());
                           });
    context.append(ndn::nfd::FibEntry()
                   .setPrefix(entry.getPrefix())
                   .setNextHopRecords(std::begin(nexthops), std::end(nexthops))
                   .wireEncode());
  }
  context.end();
}

void
FibManager::setFaceForSelfRegistration(const Interest& request, ControlParameters& parameters)
{
  bool isSelfRegistration = parameters.getFaceId() == face::INVALID_FACEID;
  if (isSelfRegistration) {
    auto incomingFaceIdTag = request.getTag<lp::IncomingFaceIdTag>();
    // NDNLPv2 says "application MUST be prepared to receive a packet without IncomingFaceId field",
    // but it's fine to assert IncomingFaceId is available, because InternalFace lives inside NFD
    // and is initialized synchronously with IncomingFaceId field enabled.
    BOOST_ASSERT(incomingFaceIdTag != nullptr);
    parameters.setFaceId(*incomingFaceIdTag);
  }
}

} // namespace nfd
