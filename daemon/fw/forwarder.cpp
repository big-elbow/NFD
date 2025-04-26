/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2024,  Regents of the University of California,
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

#include "forwarder.hpp"

#include "algorithm.hpp"
#include "best-route-strategy.hpp"
#include "scope-prefix.hpp"
#include "strategy.hpp"
#include "common/global.hpp"
#include "common/logger.hpp"
#include "table/cleanup.hpp"

#include <ndn-cxx/lp/pit-token.hpp>
#include <ndn-cxx/lp/tags.hpp>

namespace nfd {

NFD_LOG_INIT(Forwarder);

const std::string CFG_FORWARDER = "forwarder";

static Name
getDefaultStrategyName()
{
  return fw::BestRouteStrategy::getStrategyName();
}

Forwarder::Forwarder(FaceTable& faceTable)
  : m_faceTable(faceTable)
  , m_unsolicitedDataPolicy(make_unique<fw::DefaultUnsolicitedDataPolicy>())
  , m_fib(m_nameTree)
  , m_pit(m_nameTree)
  , m_measurements(m_nameTree)
  , m_strategyChoice(*this)
{
  m_faceTable.afterAdd.connect([this] (const Face& face) {
    face.afterReceiveInterest.connect(
      [this, &face] (const Interest& interest, const EndpointId& endpointId) {
        this->onIncomingInterest(interest, FaceEndpoint(const_cast<Face&>(face), endpointId));
      });
    face.afterReceiveData.connect(
      [this, &face] (const Data& data, const EndpointId& endpointId) {
        this->onIncomingData(data, FaceEndpoint(const_cast<Face&>(face), endpointId));
      });
    face.afterReceiveNack.connect(
      [this, &face] (const lp::Nack& nack, const EndpointId& endpointId) {
        this->onIncomingNack(nack, FaceEndpoint(const_cast<Face&>(face), endpointId));
      });
    face.onDroppedInterest.connect(
      [this, &face] (const Interest& interest) {
        this->onDroppedInterest(interest, const_cast<Face&>(face));
      });
  });

  m_faceTable.beforeRemove.connect([this] (const Face& face) {
    cleanupOnFaceRemoval(m_nameTree, m_fib, m_pit, face);
  });

  m_fib.afterNewNextHop.connect([this] (const Name& prefix, const fib::NextHop& nextHop) {
    this->onNewNextHop(prefix, nextHop);
  });

  m_strategyChoice.setDefaultStrategy(getDefaultStrategyName());
}

void
Forwarder::onIncomingInterest(const Interest& interest, const FaceEndpoint& ingress)
{
  interest.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInInterests;

  // ensure the received Interest has a Nonce
  auto nonce = interest.getNonce();
  auto hopLimit = interest.getHopLimit();

  // drop if HopLimit zero, decrement otherwise (if present)
  if (hopLimit) {
    NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName()
                  << " nonce=" << nonce << " hop-limit=" << static_cast<unsigned>(*hopLimit));
    if (*hopLimit == 0) {
      ++ingress.face.getCounters().nInHopLimitZero;
      // drop
      return;
    }
    const_cast<Interest&>(interest).setHopLimit(*hopLimit - 1);
  }
  else {
    NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName()
                  << " nonce=" << nonce);
  }

  // /localhost scope control
  bool isViolatingLocalhost = ingress.face.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(interest.getName());
  //isPrefixOf() 是一个函数，判断左边的名字是不是右边名字的前缀。
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName()
                  << " nonce=" << nonce << " violates /localhost");
    // drop
    return;
  }

  // detect duplicate Nonce with Dead Nonce List
  //DNL 是用来记录最近见过的 Interest Nonce，用来检测是否有循环 Interest。
  bool hasDuplicateNonceInDnl = m_deadNonceList.has(interest.getName(), nonce);
  if (hasDuplicateNonceInDnl) {
    // go to Interest loop pipeline
    this->onInterestLoop(interest, ingress);
    return;
  }

   //如果 Interest 已经到了目标区域，就把它原来携带的转发提示去掉，因为它已经不需要再“被引导”了，直接找生产者就好。
  /*Producer Region 就是发布者所在的网络区域，例如：某个特定的子网、某个自治系统（AS）或者是某个明确标记为“生产者”的节点集合
  * 这些“区域”信息是在 NFD 里通过一个叫 NetworkRegionTable 的组件维护的。
  * 可能的判断方法包括：匹配 Forwarding Hint 的前缀和本地配置的 region name；根据 router 的标识符（ID）是否属于指定区域，
  * 利用手动配置或动态学习得出的“我在哪个区域”信息*/

   // strip forwarding hint if Interest has reached producer region
  if (!interest.getForwardingHint().empty() &&
      m_networkRegionTable.isInProducerRegion(interest.getForwardingHint())) {
    NFD_LOG_DEBUG("onIncomingInterest in=" << ingress << " interest=" << interest.getName()
                  << " nonce=" << nonce << " reaching-producer-region");
    const_cast<Interest&>(interest).setForwardingHint({});
  }

  
  //下一步是使用 Interst 包中指定的名称和选择器查找现有的或创建新的PIT条目。至此，PIT条目成为对该传入 Interest 进行后续处理的管道的处理对象。请注意，NFD在执行 ContentStore 查找之前创建了PIT条目。
  //由于 ContentStore 可能明显大于PIT，所以查询 ContentStore 的代价是高于查询 PIT 的，在下面即将讨论的一些情况下，是可以跳过CS查找，所以在查询 ContentStore 之前查询PIT或创建相应的表项是有助于减小查询开销的。

  
  // PIT insert
  shared_ptr<pit::Entry> pitEntry = m_pit.insert(interest).first;
  
  //m_pit：表示的是 PIT（Pending Interest Table），也就是NDN 转发器中的挂起请求表，用来记录哪些 Interest 已经被收到但还没回应。
  //调用 m_pit 的 insert() 方法，把一个新的 Interest 插入进 PIT 表中，尝试把一个新的 Interest 插入 PIT，如果已经存在相同的条目，则返回现有的。
  //.first：说明 insert() 方法的返回值是一个 pair，所以 .first 拿到的是这个 Interest 对应的 PIT Entry，不管它是新创建的还是已有的。
  //shared_ptr<pit::Entry> pitEntry定义一个智能指针变量 pitEntry，指向这个 PIT 表项。
  
  /*在 C++ 中，pair 是一个 模板类，用于存储两个相关的值，可以是不同类型的值。它的定义是这样的：
  * template <typename T1, typename T2>
  * struct pair {
      T1 first;
      T2 second;
     };
     
  * pair 就是一个 由两个元素组成的容器。你可以通过 first 和 second 成员访问这两个元素。
  * 假设你有一个 pair<int, std::string>，表示一个数字和一个字符串的组合：
   std::pair<int, std::string> myPair = std::make_pair(1, "hello");
   std::cout << "First: " << myPair.first << ", Second: " << myPair.second << std::endl;
  * 输出：
    First: 1, Second: hello
  */

  
  /*在进一步处理传入 Interest 之前，查询 PIT 中对应表项的 in-records （ 这边查询的是同一个 PIT entry 的 in-record 列表 ）。
  * 如果在不同 Face 的记录中找到匹配项（ 即找到一个 in-record 记录，它的 Nonce 和传入 Interest 的 Nonce 是一样的，但是是从不同的 Face传入的 ）*/
  
  // detect duplicate Nonce in PIT entry
  int dnw = fw::findDuplicateNonce(*pitEntry, nonce, ingress.face);
  bool hasDuplicateNonceInPit = dnw != fw::DUPLICATE_NONCE_NONE;
  //请注意，如果在同一个 p2p Face 收到相同 Nonce 的同名 Interest，则该 Interest 被视为合法重发，因为在这种情况下不存在持续循环的风险
  if (ingress.face.getLinkType() == ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    // for p2p face: duplicate Nonce from same incoming face is not loop
    hasDuplicateNonceInPit = hasDuplicateNonceInPit && !(dnw & fw::DUPLICATE_NONCE_IN_SAME);
    //dnw & fw::DUPLICATE_NONCE_IN_SAME：检查是否是来自同一面（即同一入站 Face）
  }
  if (hasDuplicateNonceInPit) {
    // go to Interest loop pipeline
    this->onInterestLoop(interest, ingress);
    return;
  }
 /*
 // 下面是 fw::findDuplicateNonce 的实现
int
findDuplicateNonce(const pit::Entry& pitEntry, uint32_t nonce, const Face& face)
{
  int dnw = DUPLICATE_NONCE_NONE;

  for (const pit::InRecord& inRecord : pitEntry.getInRecords()) {
    if (inRecord.getLastNonce() == nonce) {
      if (&inRecord.getFace() == &face) {
      //这行代码在做的是对比两个指针，检查它们是否指向同一个 Face 对象。
        dnw |= DUPLICATE_NONCE_IN_SAME;
        //  |= 是 按位或赋值（bitwise OR assignment） 运算符，也就是说，把 dnw 当前已有的值，和 DUPLICATE_NONCE_IN_SAME 做按位“或”运算（|），然后把结果重新赋给 dnw
        //因为 dnw 是用来记录 多种检测到的“重复 Nonce”类型的，而 dnw 需要同时记录多个信息，所以每种情况用不同的位来表示
      }
      //如果之前 dnw 为空（0），那现在 dnw = DUPLICATE_NONCE_IN_SAME；如果之前 dnw 已经有别的标志，比如 DUPLICATE_NONCE_OUT_OTHER，那加上这个后，dnw 同时有了两个标志。
      else {
        dnw |= DUPLICATE_NONCE_IN_OTHER;
      }
    }
  }
  for (const pit::OutRecord& outRecord : pitEntry.getOutRecords()) {
    if (outRecord.getLastNonce() == nonce) {
      if (&outRecord.getFace() == &face) {
        dnw |= DUPLICATE_NONCE_OUT_SAME;//同一个 Face 上发出和收到了一样的 Nonce 的 Interest，可能是自己发出去又自己收回来了（异常情况，要注意）
      }
      else {
        dnw |= DUPLICATE_NONCE_OUT_OTHER;//发到别的 Face 出去的 Interest，又从其他 Face 收到了同样的 Nonce，很可能是 Interest 在网络里绕了一圈又回来了（真的可能是 Interest 循环了）
      }
    }
  }
  return dnw;
}
  */

  
  // is pending?
  if (!pitEntry->hasInRecords()) {
    m_cs.find(interest,
              [=] (const Interest& i, const Data& d) { onContentStoreHit(i, ingress, pitEntry, d); },
              [=] (const Interest& i) { onContentStoreMiss(i, ingress, pitEntry); });
    //lambda[=]
  }
  else {
    this->onContentStoreMiss(interest, ingress, pitEntry);
  }
}

/*如果 Interest 是非未决的（ not pending ），则去 ContentStore 查询是否有对应的匹配项（Cs::find，第3.3.1节）。
* 否则，不需要进行CS查找，直接传递给 ContentStore miss 管道处理，因为未决的 Interest 意味着先前查询过 ContentStore ，且在 ContentStore 中未能命中 。
* 对于非未决的 Interest ，根据CS是否匹配，选择将 Interest 传递给 ContentStore miss 管道（第4.2.4节）还是 ContentStore hit 管道（第4.2.3节）处理。*/


void
Forwarder::onInterestLoop(const Interest& interest, const FaceEndpoint& ingress)
{
  // if multi-access or ad hoc face, drop
  if (ingress.face.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onInterestLoop in=" << ingress << " interest=" << interest.getName()
                  << " nonce=" << interest.getNonce() << " drop");
    return;
  }

  NFD_LOG_DEBUG("onInterestLoop in=" << ingress << " interest=" << interest.getName()
                << " nonce=" << interest.getNonce());

  // 这行是重点：
  //leave loop handling up to the strategy (e.g., whether to reply with a Nack)
  m_strategyChoice.findEffectiveStrategy(interest.getName()).onInterestLoop(interest, ingress);
  
  /* m_strategyChoice.findEffectiveStrategy(interest.getName())
  * 找出对应这个 Interest name 的有效转发策略（Strategy）。
   .onInterestLoop(interest, ingress)
   调用这个策略的 onInterestLoop() 方法，让策略决定怎么处理这个 Loop Interest！*/
  
 /*NFD_LOG_DEBUG("onInterestLoop in=" << ingress << " interest=" << interest.getName()
              << " send-Nack-duplicate");

  // send Nack with reason=DUPLICATE
  // note: Don't enter outgoing Nack pipeline because it needs an in-record.
  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::DUPLICATE);
  ingress.face.sendNack(nack, ingress.endpoint);*/
}

void
Forwarder::onContentStoreMiss(const Interest& interest, const FaceEndpoint& ingress,
                              const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName() << " nonce=" << interest.getNonce());
  ++m_counters.nCsMisses;

  // attach HopLimit if configured and not present in Interest
  if (m_config.defaultHopLimit > 0 && !interest.getHopLimit()) {
    const_cast<Interest&>(interest).setHopLimit(m_config.defaultHopLimit);
  }

  // insert in-record
  pitEntry->insertOrUpdateInRecord(ingress.face, interest);

  // set PIT expiry timer to the time that the last PIT in-record expires
  auto lastExpiring = std::max_element(pitEntry->in_begin(), pitEntry->in_end(),
                                       [] (const auto& a, const auto& b) {
                                         return a.getExpiry() < b.getExpiry();
                                       });
  auto lastExpiryFromNow = lastExpiring->getExpiry() - time::steady_clock::now();
  this->setExpiryTimer(pitEntry, time::duration_cast<time::milliseconds>(lastExpiryFromNow));

  // has NextHopFaceId?
  auto nextHopTag = interest.getTag<lp::NextHopFaceIdTag>();
  if (nextHopTag != nullptr) {
    // chosen NextHop face exists?
    Face* nextHopFace = m_faceTable.get(*nextHopTag);
    if (nextHopFace != nullptr) {
      NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName()
                    << " nonce=" << interest.getNonce() << " nexthop-faceid=" << nextHopFace->getId());
      // go to outgoing Interest pipeline
      // scope control is unnecessary, because privileged app explicitly wants to forward
      this->onOutgoingInterest(interest, *nextHopFace, pitEntry);
    }
    return;
  }

  // dispatch to strategy: after receive Interest
  m_strategyChoice.findEffectiveStrategy(*pitEntry)
    .afterReceiveInterest(interest, FaceEndpoint(ingress.face), pitEntry);
}

void
Forwarder::onContentStoreHit(const Interest& interest, const FaceEndpoint& ingress,
                             const shared_ptr<pit::Entry>& pitEntry, const Data& data)
{
  NFD_LOG_DEBUG("onContentStoreHit interest=" << interest.getName() << " nonce=" << interest.getNonce());
  ++m_counters.nCsHits;

  data.setTag(make_shared<lp::IncomingFaceIdTag>(face::FACEID_CONTENT_STORE));
  data.setTag(interest.getTag<lp::PitToken>());
  // FIXME Should we lookup PIT for other Interests that also match the data?

  pitEntry->isSatisfied = true;
  pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

  // set PIT expiry timer to now
  this->setExpiryTimer(pitEntry, 0_ms);

  // dispatch to strategy: after Content Store hit
  m_strategyChoice.findEffectiveStrategy(*pitEntry).afterContentStoreHit(data, ingress, pitEntry);
}

pit::OutRecord*
Forwarder::onOutgoingInterest(const Interest& interest, Face& egress,
                              const shared_ptr<pit::Entry>& pitEntry)
{
  // drop if HopLimit == 0 but sending on non-local face
  if (interest.getHopLimit() == 0 && egress.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL) {
    NFD_LOG_DEBUG("onOutgoingInterest out=" << egress.getId() << " interest=" << interest.getName()
                  << " nonce=" << interest.getNonce() << " non-local hop-limit=0");
    ++egress.getCounters().nOutHopLimitZero;
    return nullptr;
  }

  NFD_LOG_DEBUG("onOutgoingInterest out=" << egress.getId() << " interest=" << interest.getName()
                << " nonce=" << interest.getNonce());

  // insert out-record
  auto it = pitEntry->insertOrUpdateOutRecord(egress, interest);
  BOOST_ASSERT(it != pitEntry->out_end());

  // send Interest
  egress.sendInterest(interest);
  ++m_counters.nOutInterests;

  return &*it;
}

void
Forwarder::onInterestFinalize(const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onInterestFinalize interest=" << pitEntry->getName()
                << (pitEntry->isSatisfied ? " satisfied" : " unsatisfied"));

  // Dead Nonce List insert if necessary
  this->insertDeadNonceList(*pitEntry, nullptr);

  // Increment satisfied/unsatisfied Interests counter
  if (pitEntry->isSatisfied) {
    ++m_counters.nSatisfiedInterests;
  }
  else {
    ++m_counters.nUnsatisfiedInterests;
  }

  // PIT delete
  pitEntry->expiryTimer.cancel();
  m_pit.erase(pitEntry.get());
}

void
Forwarder::onIncomingData(const Data& data, const FaceEndpoint& ingress)
{
  data.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInData;
  NFD_LOG_DEBUG("onIncomingData in=" << ingress << " data=" << data.getName());

  // /localhost scope control
  bool isViolatingLocalhost = ingress.face.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingData in=" << ingress << " data=" << data.getName() << " violates /localhost");
    // drop
    return;
  }

  // PIT match
  pit::DataMatchResult pitMatches = m_pit.findAllDataMatches(data);
  if (pitMatches.size() == 0) {
    // go to Data unsolicited pipeline
    this->onDataUnsolicited(data, ingress);
    return;
  }

  // CS insert
  m_cs.insert(data);

  // when only one PIT entry is matched, trigger strategy: after receive Data
  if (pitMatches.size() == 1) {
    auto& pitEntry = pitMatches.front();

    NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

    // set PIT expiry timer to now
    this->setExpiryTimer(pitEntry, 0_ms);

    // trigger strategy: after receive Data
    m_strategyChoice.findEffectiveStrategy(*pitEntry).afterReceiveData(data, ingress, pitEntry);

    // mark PIT satisfied
    pitEntry->isSatisfied = true;
    pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

    // Dead Nonce List insert if necessary (for out-record of ingress face)
    this->insertDeadNonceList(*pitEntry, &ingress.face);

    // delete PIT entry's out-record
    pitEntry->deleteOutRecord(ingress.face);
  }
  // when more than one PIT entry is matched, trigger strategy: before satisfy Interest,
  // and send Data to all matched out faces
  else {
    std::set<Face*> pendingDownstreams;
    auto now = time::steady_clock::now();

    for (const auto& pitEntry : pitMatches) {
      NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

      // remember pending downstreams
      for (const pit::InRecord& inRecord : pitEntry->getInRecords()) {
        if (inRecord.getExpiry() > now) {
          pendingDownstreams.insert(&inRecord.getFace());
        }
      }

      // set PIT expiry timer to now
      this->setExpiryTimer(pitEntry, 0_ms);

      // invoke PIT satisfy callback
      m_strategyChoice.findEffectiveStrategy(*pitEntry).beforeSatisfyInterest(data, ingress, pitEntry);

      // mark PIT satisfied
      pitEntry->isSatisfied = true;
      pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

      // Dead Nonce List insert if necessary (for out-record of ingress face)
      this->insertDeadNonceList(*pitEntry, &ingress.face);

      // clear PIT entry's in and out records
      pitEntry->clearInRecords();
      pitEntry->deleteOutRecord(ingress.face);
    }

    for (Face* pendingDownstream : pendingDownstreams) {
      if (pendingDownstream->getId() == ingress.face.getId() &&
          pendingDownstream->getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) {
        continue;
      }
      // go to outgoing Data pipeline
      this->onOutgoingData(data, *pendingDownstream);
    }
  }
}

void
Forwarder::onDataUnsolicited(const Data& data, const FaceEndpoint& ingress)
{
  ++m_counters.nUnsolicitedData;

  // accept to cache?
  auto decision = m_unsolicitedDataPolicy->decide(ingress.face, data);
  NFD_LOG_DEBUG("onDataUnsolicited in=" << ingress << " data=" << data.getName()
                << " decision=" << decision);
  if (decision == fw::UnsolicitedDataDecision::CACHE) {
    // CS insert
    m_cs.insert(data, true);
  }
}

bool
Forwarder::onOutgoingData(const Data& data, Face& egress)
{
  if (egress.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingData out=(invalid) data=" << data.getName());
    return false;
  }

  // /localhost scope control
  bool isViolatingLocalhost = egress.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onOutgoingData out=" << egress.getId() << " data=" << data.getName()
                  << " violates /localhost");
    // drop
    return false;
  }

  NFD_LOG_DEBUG("onOutgoingData out=" << egress.getId() << " data=" << data.getName());

  // send Data
  egress.sendData(data);
  ++m_counters.nOutData;

  return true;
}

void
Forwarder::onIncomingNack(const lp::Nack& nack, const FaceEndpoint& ingress)
{
  nack.setTag(make_shared<lp::IncomingFaceIdTag>(ingress.face.getId()));
  ++m_counters.nInNacks;

  // if multi-access or ad hoc face, drop
  if (ingress.face.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " link-type=" << ingress.face.getLinkType());
    return;
  }

  // PIT match
  shared_ptr<pit::Entry> pitEntry = m_pit.find(nack.getInterest());
  // if no PIT entry found, drop
  if (pitEntry == nullptr) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " no-pit-entry");
    return;
  }

  // has out-record?
  auto outRecord = pitEntry->findOutRecord(ingress.face);
  // if no out-record found, drop
  if (outRecord == pitEntry->out_end()) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " no-out-record");
    return;
  }

  // if out-record has different Nonce, drop
  if (nack.getInterest().getNonce() != outRecord->getLastNonce()) {
    NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                  << "~" << nack.getReason() << " nonce-mismatch " << nack.getInterest().getNonce()
                  << "!=" << outRecord->getLastNonce());
    return;
  }

  NFD_LOG_DEBUG("onIncomingNack in=" << ingress << " nack=" << nack.getInterest().getName()
                << "~" << nack.getReason());

  // record Nack on out-record
  outRecord->setIncomingNack(nack);

  // set PIT expiry timer to now when all out-record receive Nack
  if (!fw::hasPendingOutRecords(*pitEntry)) {
    this->setExpiryTimer(pitEntry, 0_ms);
  }

  // trigger strategy: after receive Nack
  m_strategyChoice.findEffectiveStrategy(*pitEntry).afterReceiveNack(nack, ingress, pitEntry);
}

bool
Forwarder::onOutgoingNack(const lp::NackHeader& nack, Face& egress,
                          const shared_ptr<pit::Entry>& pitEntry)
{
  if (egress.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingNack out=(invalid)" << " nack=" << pitEntry->getName()
                 << "~" << nack.getReason());
    return false;
  }

  // has in-record?
  auto inRecord = pitEntry->findInRecord(egress);

  // if no in-record found, drop
  if (inRecord == pitEntry->in_end()) {
    NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId() << " nack=" << pitEntry->getName()
                  << "~" << nack.getReason() << " no-in-record");
    return false;
  }

  // if multi-access or ad hoc face, drop
  if (egress.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId() << " nack=" << pitEntry->getName()
                  << "~" << nack.getReason() << " link-type=" << egress.getLinkType());
    return false;
  }

  NFD_LOG_DEBUG("onOutgoingNack out=" << egress.getId() << " nack=" << pitEntry->getName()
                << "~" << nack.getReason());

  // create Nack packet with the Interest from in-record
  lp::Nack nackPkt(inRecord->getInterest());
  nackPkt.setHeader(nack);

  // erase in-record
  pitEntry->deleteInRecord(inRecord);

  // send Nack on face
  egress.sendNack(nackPkt);
  ++m_counters.nOutNacks;

  return true;
}

void
Forwarder::onDroppedInterest(const Interest& interest, Face& egress)
{
  m_strategyChoice.findEffectiveStrategy(interest.getName()).onDroppedInterest(interest, egress);
}

void
Forwarder::onNewNextHop(const Name& prefix, const fib::NextHop& nextHop)
{
  const auto affectedEntries = this->getNameTree().partialEnumerate(prefix,
    [&] (const name_tree::Entry& nte) -> std::pair<bool, bool> {
      // we ignore an NTE and skip visiting its descendants if that NTE has an
      // associated FIB entry (1st condition), since in that case the new nexthop
      // won't affect any PIT entries anywhere in that subtree, *unless* this is
      // the initial NTE from which the enumeration started (2nd condition), which
      // must always be considered
      if (nte.getFibEntry() != nullptr && nte.getName().size() > prefix.size()) {
        return {false, false};
      }
      return {nte.hasPitEntries(), true};
    });

  for (const auto& nte : affectedEntries) {
    for (const auto& pitEntry : nte.getPitEntries()) {
      m_strategyChoice.findEffectiveStrategy(*pitEntry).afterNewNextHop(nextHop, pitEntry);
    }
  }
}

void
Forwarder::setExpiryTimer(const shared_ptr<pit::Entry>& pitEntry, time::milliseconds duration)
{
  BOOST_ASSERT(pitEntry);
  duration = std::max(duration, 0_ms);

  pitEntry->expiryTimer.cancel();
  pitEntry->expiryTimer = getScheduler().schedule(duration, [=] { onInterestFinalize(pitEntry); });
}

void
Forwarder::insertDeadNonceList(pit::Entry& pitEntry, const Face* upstream)
{
  // need Dead Nonce List insert?
  bool needDnl = true;
  if (pitEntry.isSatisfied) {
    BOOST_ASSERT(pitEntry.dataFreshnessPeriod >= 0_ms);
    needDnl = pitEntry.getInterest().getMustBeFresh() &&
              pitEntry.dataFreshnessPeriod < m_deadNonceList.getLifetime();
  }

  if (!needDnl) {
    return;
  }

  // Dead Nonce List insert
  if (upstream == nullptr) {
    // insert all outgoing Nonces
    std::for_each(pitEntry.out_begin(), pitEntry.out_end(), [&] (const auto& outRecord) {
      m_deadNonceList.add(pitEntry.getName(), outRecord.getLastNonce());
    });
  }
  else {
    // insert outgoing Nonce of a specific face
    auto outRecord = pitEntry.findOutRecord(*upstream);
    if (outRecord != pitEntry.out_end()) {
      m_deadNonceList.add(pitEntry.getName(), outRecord->getLastNonce());
    }
  }
}

void
Forwarder::setConfigFile(ConfigFile& configFile)
{
  configFile.addSectionHandler(CFG_FORWARDER, [this] (auto&&... args) {
    processConfig(std::forward<decltype(args)>(args)...);
  });
}

void
Forwarder::processConfig(const ConfigSection& configSection, bool isDryRun, const std::string&)
{
  Config config;

  for (const auto& pair : configSection) {
    const std::string& key = pair.first;
    if (key == "default_hop_limit") {
      config.defaultHopLimit = ConfigFile::parseNumber<uint8_t>(pair, CFG_FORWARDER);
    }
    else {
      NDN_THROW(ConfigFile::Error("Unrecognized option " + CFG_FORWARDER + "." + key));
    }
  }

  if (!isDryRun) {
    m_config = config;
  }
}

} // namespace nfd
