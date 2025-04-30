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

#include "strategy.hpp"
#include "forwarder.hpp"
#include "common/logger.hpp"

#include <ndn-cxx/lp/pit-token.hpp>

#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <unordered_set>

namespace nfd::fw {

NFD_LOG_INIT(Strategy);

Strategy::Registry&
Strategy::getRegistry()
{
  static Registry registry;
  return registry;
}

Strategy::Registry::const_iterator
Strategy::find(const Name& instanceName)
{
  const Registry& registry = getRegistry();
  ParsedInstanceName parsed = parseInstanceName(instanceName);

  if (parsed.version) {
    // specified version: find exact or next higher version

    auto found = registry.lower_bound(parsed.strategyName);
    if (found != registry.end()) {
      if (parsed.strategyName.getPrefix(-1).isPrefixOf(found->first)) {
        NFD_LOG_TRACE("find " << instanceName << " versioned found=" << found->first);
        return found;
      }
    }

    NFD_LOG_TRACE("find " << instanceName << " versioned not-found");
    return registry.end();
  }

  // no version specified: find highest version

  if (!parsed.strategyName.empty()) { // Name().getSuccessor() would be invalid
    auto found = registry.lower_bound(parsed.strategyName.getSuccessor());
    if (found != registry.begin()) {
      --found;
      if (parsed.strategyName.isPrefixOf(found->first)) {
        NFD_LOG_TRACE("find " << instanceName << " unversioned found=" << found->first);
        return found;
      }
    }
  }

  NFD_LOG_TRACE("find " << instanceName << " unversioned not-found");
  return registry.end();
}

bool
Strategy::canCreate(const Name& instanceName)
{
  return Strategy::find(instanceName) != getRegistry().end();
}

unique_ptr<Strategy>
Strategy::create(const Name& instanceName, Forwarder& forwarder)
{
  auto found = Strategy::find(instanceName);
  if (found == getRegistry().end()) {
    NFD_LOG_DEBUG("create " << instanceName << " not-found");
    return nullptr;
  }

  unique_ptr<Strategy> instance = found->second(forwarder, instanceName);
  NFD_LOG_DEBUG("create " << instanceName << " found=" << found->first
                << " created=" << instance->getInstanceName());
  BOOST_ASSERT(!instance->getInstanceName().empty());
  return instance;
}

bool
Strategy::areSameType(const Name& instanceNameA, const Name& instanceNameB)
{
  return Strategy::find(instanceNameA) == Strategy::find(instanceNameB);
}

std::set<Name>
Strategy::listRegistered()
{
  std::set<Name> strategyNames;
  boost::copy(getRegistry() | boost::adaptors::map_keys,
              std::inserter(strategyNames, strategyNames.end()));
  return strategyNames;
}

Strategy::ParsedInstanceName
Strategy::parseInstanceName(const Name& input)
{
  for (ssize_t i = input.size() - 1; i > 0; --i) {
    if (input[i].isVersion()) {
      return {input.getPrefix(i + 1), input[i].toVersion(), input.getSubName(i + 1)};
    }
  }
  return {input, std::nullopt, PartialName()};
}

Name
Strategy::makeInstanceName(const Name& input, const Name& strategyName)
{
  BOOST_ASSERT(strategyName.at(-1).isVersion());

  bool hasVersion = std::any_of(input.rbegin(), input.rend(),
                                [] (const auto& comp) { return comp.isVersion(); });
  return hasVersion ? input : Name(input).append(strategyName.at(-1));
}

StrategyParameters
Strategy::parseParameters(const PartialName& params)
{
  StrategyParameters parsed;

  for (const auto& component : params) {
    auto sep = std::find(component.value_begin(), component.value_end(), '~');
    if (sep == component.value_end()) {
      NDN_THROW(std::invalid_argument("Strategy parameters format is (<parameter>~<value>)*"));
    }

    std::string p(component.value_begin(), sep);
    std::advance(sep, 1);
    std::string v(sep, component.value_end());
    if (p.empty() || v.empty()) {
      NDN_THROW(std::invalid_argument("Strategy parameter name and value cannot be empty"));
    }
    parsed[std::move(p)] = std::move(v);
  }

  return parsed;
}

Strategy::Strategy(Forwarder& forwarder)
  : afterAddFace(forwarder.m_faceTable.afterAdd)
  , beforeRemoveFace(forwarder.m_faceTable.beforeRemove)
  , m_forwarder(forwarder)
  , m_measurements(m_forwarder.getMeasurements(), m_forwarder.getStrategyChoice(), *this)
{
}

Strategy::~Strategy() = default;

void
Strategy::onInterestLoop(const Interest& interest, const FaceEndpoint& ingress)
{
  NFD_LOG_DEBUG("onInterestLoop in=" << ingress << " name=" << interest.getName());

  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::DUPLICATE);
  this->sendNack(nack, ingress.face);
}

void
Strategy::afterContentStoreHit(const Data& data, const FaceEndpoint& ingress,
                               const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("afterContentStoreHit pitEntry=" << pitEntry->getName()
                << " in=" << ingress << " data=" << data.getName());

  this->sendData(data, ingress.face, pitEntry);
}

void
Strategy::beforeSatisfyInterest(const Data& data, const FaceEndpoint& ingress,
                                const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("beforeSatisfyInterest pitEntry=" << pitEntry->getName()
                << " in=" << ingress << " data=" << data.getName());
}


/* 此触发器声明为 Strategy::afterReceiveData 方法。当传入的数据恰好满足一个PIT条目时，将调用此触发器，并为该策略提供对数据转发的完全控制权。
 * 调用此触发器时，已验证数据满足PIT条目，并且PIT条目到期计时器设置为立即触发。*/
void
Strategy::afterReceiveData(const Data& data, const FaceEndpoint& ingress,
                           const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("afterReceiveData pitEntry=" << pitEntry->getName()
                << " in=" << ingress << " data=" << data.getName());

  this->beforeSatisfyInterest(data, ingress, pitEntry);
  this->sendDataToAll(data, pitEntry, ingress.face);
}


void
Strategy::afterReceiveNack(const lp::Nack&, const FaceEndpoint& ingress,
                           const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("afterReceiveNack in=" << ingress << " pitEntry=" << pitEntry->getName());
}

void
Strategy::onDroppedInterest(const Interest& interest, Face& egress)
{
  NFD_LOG_DEBUG("onDroppedInterest out=" << egress.getId() << " name=" << interest.getName());
}

void
Strategy::afterNewNextHop(const fib::NextHop& nextHop, const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("afterNewNextHop pitEntry=" << pitEntry->getName()
                << " nexthop=" << nextHop.getFace().getId());
}

pit::OutRecord*
Strategy::sendInterest(const Interest& interest, Face& egress, const shared_ptr<pit::Entry>& pitEntry)
{
  if (interest.getTag<lp::PitToken>() != nullptr) {
    Interest interest2 = interest; // make a copy to preserve tag on original packet
    interest2.removeTag<lp::PitToken>();
    return m_forwarder.onOutgoingInterest(interest2, egress, pitEntry);
  }
  return m_forwarder.onOutgoingInterest(interest, egress, pitEntry);
}

//此操作将删除PIT条目的记录中的内容，并进入 Outgoing Data 管道
bool
Strategy::sendData(const Data& data, Face& egress, const shared_ptr<pit::Entry>& pitEntry)
{
  //使用 BOOST_ASSERT 断言，确保 Data 满足 PIT 条目中的 Interest
  //matchesData(data) 检查 Data 是否满足 Interest（例如，名称匹配、签名验证等）
  BOOST_ASSERT(pitEntry->getInterest().matchesData(data));

  //如果找到匹配的 In-Record，返回指向该记录的迭代器。
  //如果未找到，返回 pitEntry->in_end()（表示结束的迭代器）
  auto inRecord = pitEntry->findInRecord(egress);
  if (inRecord != pitEntry->in_end()) {
    auto pitToken = inRecord->getInterest().getTag<lp::PitToken>();//从 In-Record 中的 Interest 获取 lp::PitToken 标签

    // delete the PIT entry's in-record based on egress,
    // since the Data is sent to the face from which the Interest was received
    pitEntry->deleteInRecord(inRecord);//从 PIT 条目中删除与 egress 关联的 In-Record

    if (pitToken != nullptr) {
      //复制确保每个下游 Face 可以接收独立的 Data（可能携带不同的 PitToken
      Data data2 = data; // make a copy so each downstream can get a different PIT token
      //将从 In-Record 获取的 PitToken 设置到 Data 副本上
      data2.setTag(pitToken);
      return m_forwarder.onOutgoingData(data2, egress);
    }
  }
  return m_forwarder.onOutgoingData(data, egress);
}

/* 在许多情况下，该策略可能希望将 Data 发送到每个下游。Strategy::sendDataToAll 方法是用于此目的的帮助程序，它接受PIT条目，Data 和 传入 Data 的 Face 。
 * 请注意，Strategy::sendDataToAll 会将数据发送到每个待处理的下游，除非待处理的下游 Face 与数据的传入 Face 相同，并且该 Face 不是临时的。*/
void
Strategy::sendDataToAll(const Data& data, const shared_ptr<pit::Entry>& pitEntry, const Face& inFace)
{
  //定义一个 std::set 容器 pendingDownstreams，存储指向下游 Face 的指针（Face*）
  /* std::set 确保 Face 指针的唯一性（避免重复发送）。
   * 提供有序存储（按指针值排序），虽然在本例中排序非必需。*/
  std::set<Face*> pendingDownstreams;
  auto now = time::steady_clock::now();

  // remember pending downstreams
  for (const auto& inRecord : pitEntry->getInRecords()) {
    if (inRecord.getExpiry() > now) {
      if (inRecord.getFace().getId() == inFace.getId() &&
          inRecord.getFace().getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) {
        continue;
      }
      pendingDownstreams.emplace(&inRecord.getFace());//emplace 直接构造并插入指针，确保高效且唯一
    }
  }

  for (const auto& pendingDownstream : pendingDownstreams) {
    this->sendData(data, *pendingDownstream, pitEntry);
  }
}

/*在许多情况下，该策略可能希望将 Nacks 发送到每个下游（同样的对每个要发送的下游 Face 都有匹配的 in-record ）。 
 * Strategy::sendNacks 方法是用于此目的的辅助方法，它接受PIT条目和 NackHeader 。调用此帮助程序方法等效于为每个下游调用 send Nack 操作。*/
void
Strategy::sendNacks(const lp::NackHeader& header, const shared_ptr<pit::Entry>& pitEntry,
                    std::initializer_list<const Face*> exceptFaces)
{
  // populate downstreams with all downstreams faces
  std::unordered_set<Face*> downstreams;
  /*遍历 In-Records，将每个 In-Record 转换为对应的 Face 指针。
   * 转换函数：[] (const auto& inR) { return &inR.getFace(); } 获取 In-Record 的 Face 指针。
   * std::inserter(downstreams, downstreams.end())：一个插入迭代器，将转换结果插入 downstreams。
   * 确保 Face 指针唯一（std::unordered_set 自动去重）*/
  std::transform(pitEntry->in_begin(), pitEntry->in_end(),
                 std::inserter(downstreams, downstreams.end()),
                 [] (const auto& inR) { return &inR.getFace(); });

  // remove excluded faces 从 downstreams 中移除 exceptFaces 中指定的 Face
  for (auto exceptFace : exceptFaces) {
    downstreams.erase(const_cast<Face*>(exceptFace));
  }

  // send Nacks
  for (auto downstream : downstreams) {
    this->sendNack(header, *downstream, pitEntry);
  }
  // warning: don't loop on pitEntry->getInRecords(), because in-record is deleted when sending Nack
  //提醒开发者不要直接遍历 pitEntry->getInRecords() 来发送 Nack
}

//Strategy::lookupFib 考虑 forwarding hint 来实现FIB查找过程
const fib::Entry&
Strategy::lookupFib(const pit::Entry& pitEntry) const
{
  const Fib& fib = m_forwarder.getFib();//从转发器（m_forwarder）中获取 FIB 的引用

  const Interest& interest = pitEntry.getInterest();//从 PIT 条目（pitEntry）中提取 Interest（兴趣包）对象的引用
  
  // has forwarding hint?
  if (interest.getForwardingHint().empty()) {
    // FIB lookup with Interest name
    const fib::Entry& fibEntry = fib.findLongestPrefixMatch(pitEntry);
    NFD_LOG_TRACE("lookupFib noForwardingHint found=" << fibEntry.getPrefix());
    return fibEntry;
  }

  // 此时存在转发提示表示兴趣尚未到达生产者区域，因为在进入生产者区域时，应该在传入的 Incoming Interest 管道中删除转发提示
  // 有 Forwarding Hint 的情况：初始化
  const auto& fh = interest.getForwardingHint();
  // Forwarding hint should have been stripped by incoming Interest pipeline when reaching producer region
  BOOST_ASSERT(!m_forwarder.getNetworkRegionTable().isInProducerRegion(fh));
  //BOOST_ASSERT(expression);
  //expression：一个返回布尔值的表达式（true 或 false）
  /*如果 expression 为 true，什么也不做，程序继续运行。
    如果 expression 为 false，在调试模式下：
    程序终止。
    输出错误信息（通常包括文件名、行号和失败的表达式）。
    在发布模式下，BOOST_ASSERT 通常被禁用（不执行检查），以提高性能。*/

  //Forwarding Hint 是 Interest 中的一个字段，包含一组名称（delegations），用于提示转发器如何在 FIB 中查找转发路径
  const fib::Entry* fibEntry = nullptr;
  for (const auto& delegation : fh) {
    fibEntry = &fib.findLongestPrefixMatch(delegation);
    if (fibEntry->hasNextHops()) {
      if (fibEntry->getPrefix().empty()) {
        //空前缀（ndn:/）：表示默认路由，通常在消费者区域
        // in consumer region, return the default route
        NFD_LOG_TRACE("lookupFib inConsumerRegion found=" << fibEntry->getPrefix());
      }
      else {
        // in default-free zone, use the first delegation that finds a FIB entry
        NFD_LOG_TRACE("lookupFib delegation=" << delegation << " found=" << fibEntry->getPrefix());
      }
      return *fibEntry;
    }
    //通过 BOOST_ASSERT 断言该条目是默认条目（ndn:/），因为只有默认条目允许没有下一跳
    BOOST_ASSERT(fibEntry->getPrefix().empty()); // only ndn:/ FIB entry can have zero nexthop
  }
  BOOST_ASSERT(fibEntry != nullptr && fibEntry->getPrefix().empty());//如果 Forwarding Hint 中的所有 delegation 都没有找到带有 nexthop 的 FIB 条目，则返回默认条目
  return *fibEntry; // only occurs if no delegation finds a FIB nexthop
  //确保 fibEntry 不为空且其前缀为空，返回默认条目引用
}

} // namespace nfd::fw
