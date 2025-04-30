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

#ifndef NFD_DAEMON_FW_STRATEGY_HPP
#define NFD_DAEMON_FW_STRATEGY_HPP

#include "forwarder.hpp"
#include "table/measurements-accessor.hpp"

#include <boost/lexical_cast/try_lexical_convert.hpp>

#include <functional>
#include <map>
#include <set>

namespace nfd::fw {

class StrategyParameters;

/**
 * \brief Base class of all forwarding strategies.
 */
class Strategy : noncopyable
{
public: // registry
  /**
   * \brief Register a strategy type.
   * \tparam S subclass of Strategy
   * \param strategyName strategy program name, must contain version
   * \note It is permitted to register the same strategy type under multiple names,
   *       which is useful in tests and for creating aliases.
   */
  template<typename S>
  static void
  registerType(const Name& strategyName = S::getStrategyName())
  {
    BOOST_ASSERT(strategyName.size() > 1);
    BOOST_ASSERT(strategyName.at(-1).isVersion());
    auto r = getRegistry().insert_or_assign(strategyName, [] (auto&&... args) {
      return make_unique<S>(std::forward<decltype(args)>(args)...);
    });
    BOOST_VERIFY(r.second);
  }

  /**
   * \brief Returns whether a strategy instance can be created from \p instanceName.
   * \param instanceName strategy instance name, may contain version and parameters
   * \note This function finds a strategy type using the same rules as create(),
   *       but does not attempt to construct an instance.
   */
  static bool
  canCreate(const Name& instanceName);

  /**
   * \brief Returns a strategy instance created from \p instanceName.
   * \retval nullptr if `canCreate(instanceName) == false`
   * \throw std::invalid_argument strategy type constructor does not accept the
   *                              specified version or parameters
   */
  static unique_ptr<Strategy>
  create(const Name& instanceName, Forwarder& forwarder);

  /**
   * \brief Returns whether two names will instantiate the same strategy type.
   */
  static bool
  areSameType(const Name& instanceNameA, const Name& instanceNameB);

  /**
   * \brief Returns all registered versioned strategy names.
   */
  [[nodiscard]] static std::set<Name>
  listRegistered();

public: // constructor, destructor, strategy info
  /** \brief Construct a strategy instance.
   *  \param forwarder a reference to the forwarder, used to enable actions and accessors.
   *  \note Strategy subclass constructor must not retain a reference to \p forwarder.
   */
  explicit
  Strategy(Forwarder& forwarder);

  virtual
  ~Strategy();

#ifdef DOXYGEN
  /**
   * \brief Returns the strategy's program name.
   *
   * The strategy name is defined by the strategy program.
   * It must end with a version component.
   */
  static const Name&
  getStrategyName();
#endif

  /**
   * \brief Returns the strategy's instance name.
   *
   * The instance name is assigned during instantiation.
   * It contains a version component and may have extra parameter components.
   */
  const Name&
  getInstanceName() const noexcept
  {
    return m_name;
  }

public: // triggers
  /**
   * \brief Trigger after an Interest is received.
   *
   *  当NFD收到一个 Interest ，会传递给 Incoming Interest 管道处理，经过必要的检查之后如果这个 Interest 还需要被转发，
   *  则 Incoming Interest 管道会触发 Interest 所关联策略的 Strategy::afterReceiveInterest 触发器
   * （以收到的 Interest、入口 Face 和对应的PIT条目作为参数）
   * 
   * The Interest:
   *  - has not exceeded HopLimit
   *  - does not violate Scope / Interest 不违反 /localhost scope 限制
   *  - has not looped / 不是循环的（ loop ）
   *  - cannot be satisfied by ContentStore / Interest 没有命中缓存
   *  - is under a namespace managed by this strategy / Interest 位于此策略管理的名称空间下
   *
   * The PIT entry is set to expire after InterestLifetime has elapsed at each downstream.
   *
   * The strategy should decide whether and where to forward this Interest.
   *  - If the strategy decides to forward this Interest,
   *    invoke sendInterest() for each upstream, either now or shortly after via a scheduler event,
   *    but before the PIT entry expires.
   *    Optionally, the strategy can invoke setExpiryTimer() to adjust how long it would wait for a response.
   * 如果策略决定转发此Interest， 对于每个上游，立即或稍后通过调度事件调用sendInterest()，但需在PIT条目过期之前。
   * 可选地，策略可调用setExpiryTimer()调整等待响应的时间。
   *  - If the strategy has already forwarded this Interest previously and decides to continue
   *    waiting, do nothing.
   *    Optionally, the strategy can invoke setExpiryTimer() to adjust how long it would wait for a response.
   * 如果策略之前已转发此Interest并决定继续等待，则不执行任何操作。 可选地，策略可调用setExpiryTimer()调整等待响应的时间。
   *  - If the strategy concludes that this Interest cannot be satisfied,
   *    invoke rejectPendingInterest() to erase the PIT entry.
   * 如果策略认为此Interest无法满足， 调用rejectPendingInterest()删除PIT条目
   *
   * 当本触发器被触发后，策略应决定是否以及在何处转发此 Interest 。大多数策略都需要读取FIB条目来做出此决定，这可以通过调用 Strategy::lookupFib 访问器函数来获得。
   * 如果该策略决定转发此 Interest ，则应至少调用一次 send interest 操作；如果该策略得出结论认为不能转发此 Interest ，
   * 则应调用 Strategy::setExpiryTimer 操作并将该定时器设置为立即过期 ^8，以便相关PIT条目最终可以被移除。
   * ^8 警告 ：尽管允许策略通过计时器延迟调用 send interest 操作，但在特殊情况下这种转发可能永远不会发生。
   * 例如，如果在等待此类计时器的过程中，NFD管理员在兴趣的名称空间上更新策略，则该计时器事件将被取消，并且新策略可能直到PIT条目中的所有记录都到期后才决定转发该兴趣。
   *
   * \warning The strategy must not retain a copy of the \p pitEntry shared_ptr after this function
   *          returns, otherwise undefined behavior may occur. However, the strategy is allowed to
   *          construct and keep a weak_ptr to \p pitEntry.
   * 策略在此函数返回后不得保留\p pitEntry shared_ptr的副本，否则可能导致未定义行为。但策略可构造并保留指向\p pitEntry的weak_ptr
   */
  //此方法是纯虚拟方法，因此必须被子类覆盖
  virtual void
  afterReceiveInterest(const Interest& interest, const FaceEndpoint& ingress,
                       const shared_ptr<pit::Entry>& pitEntry) = 0;

  /**
   * \brief Trigger after an Interest loop is detected.
   *
   * The Interest:
   *  - has not exceeded HopLimit
   *  - does not violate Scope
   *  - has looped /Interest 
   *  - is under a namespace managed by this strategy 
   *
   * In the base class, this method sends a Nack with reason DUPLICATE to \p ingress.
   */
  virtual void
  onInterestLoop(const Interest& interest, const FaceEndpoint& ingress);

  /**
   * \brief Trigger after a matching Data is found in the Content Store.
   *
   * In the base class, this method sends \p data to \p ingress.
   *
   * \warning The strategy must not retain a copy of the \p pitEntry shared_ptr after this function
   *          returns, otherwise undefined behavior may occur. However, the strategy is allowed to
   *          construct and keep a weak_ptr to \p pitEntry.
   */
  virtual void
  afterContentStoreHit(const Data& data, const FaceEndpoint& ingress,
                       const shared_ptr<pit::Entry>& pitEntry);

/**
 * \brief 在 PIT 条目被满足之前触发
 *
 * 单 PIT 匹配：afterReceiveData 被调用，策略完全控制 Data 转发。
 * 多 PIT 匹配：beforeSatisfyInterest 被调用，策略只能收集信息，不能控制转发。
 *
 * 当一个传入的 Data 满足多个 PIT 条目时，会调用此触发器。
 * 策略可以在此收集测量信息，但无法控制 Data 的转发。
 * 如果传入的 Data 只满足一个 PIT 条目，则会调用 afterReceiveData()，并将 Data 转发的完全控制权交给策略。
 * 如果策略未重写 afterReceiveData()，其默认实现会调用 beforeSatisfyInterest()。
 *
 * 通常，PIT 条目在接收到第一个匹配的 Data 后会被删除。
 * 如果策略希望从额外的上游节点收集响应，它应在此函数中调用 setExpiryTimer() 来延长 PIT 条目的生命周期。
 * 如果在延长的 PIT 条目生命周期内，从另一个上游节点收到 Data，此触发器会再次被调用。
 * 此时，策略必须再次调用 setExpiryTimer() 以继续收集更多响应。
 *
 * 在基类中，此方法不执行任何操作。
 *
 * \warning 策略在函数返回后不得保留 \p pitEntry shared_ptr 的副本，否则可能导致未定义行为。
 *          但是，策略可以构造并保留对 \p pitEntry 的 weak_ptr。
 */
  virtual void
  beforeSatisfyInterest(const Data& data, const FaceEndpoint& ingress,
                        const shared_ptr<pit::Entry>& pitEntry);

/**
 * \brief 在接收到 Data 后触发
 *
 * 当一个传入的 Data 恰好满足一个 PIT 条目时，会调用此触发器，并将 Data 转发的完全控制权交给策略。
 * 补：（“恰好满足一个 PIT 条目”意味着 Data 与一个 Interest 完全匹配，没有多个 PIT 条目同时匹配的情况。）
 *
 * 调用此触发器时的条件：
 *  - Data 已被验证能够满足 PIT 条目。
 *  - PIT 条目的过期计时器已被设置为当前时间（now）。
 *
 * 在此函数内部：
 *  - 策略应通过 sendData() 或 sendDataToAll() 将 Data 返回给下游节点。
 *  - 策略可以修改 Data，只要它仍然满足 PIT 条目，例如添加或移除拥塞标记。
 *  - 策略可以通过 setExpiryTimer() 延长 PIT 条目的生命周期来延迟 Data 转发，并在 PIT 条目被删除前稍后转发 Data。
 *  - 策略可以收集关于上游的测量数据。
 *  - 策略可以通过在每次接收到 Data 时使用 setExpiryTimer() 延长 PIT 条目生命周期，以从额外的上游节点收集响应。
 *    注意：每个下游节点只能返回一个 Data。
 *
 * 在基类中，此方法会调用 beforeSatisfyInterest()，然后通过 sendDataToAll() 将 Data 返回给所有下游 Face。
 *
 * \warning 策略在函数返回后不得保留 \p pitEntry shared_ptr 的副本，否则可能导致未定义行为。
 *          但是，策略可以构造并保留对 \p pitEntry 的 weak_ptr。
 */
  virtual void
  afterReceiveData(const Data& data, const FaceEndpoint& ingress,
                   const shared_ptr<pit::Entry>& pitEntry);

  /**
 * \brief 在接收到 Nack 后触发
 *
 * 当接收到一个响应已转发 Interest 的传入 Nack（否定确认）时，会调用此触发器。
 * Nack 已被确认为对最后转发到该上游的 Interest 的响应，即 PIT 的 Out-Record 存在且具有匹配的 Nonce。
 * NackHeader（Nack 头部信息）已被记录在 PIT 的 Out-Record 中。
 * PIT条目位于此策略管理的名称空间下^9
 * ^9:注意：Nack 对应的 Interest 不一定是由同一个策略转发的。
 * 如果在转发 Interest 后更改了有效策略，然后收到了对应的 Nack ，则会触发新的有效策略，而不是先前转发 Interest 的策略。
 *
 * 如果 PIT 条目尚未被满足（即未收到匹配的 Data），其过期计时器保持不变。
 * 否则，PIT 条目通常会在此函数返回后立即过期。
 *
 * 如果策略希望从额外的上游节点收集响应，它应在此函数中调用 setExpiryTimer() 来延长 PIT 条目的生命周期。
 * 如果在延长的 PIT 条目生命周期内，从另一个上游节点收到 Nack，此触发器会再次被调用。
 * 此时，策略必须再次调用 setExpiryTimer() 以继续收集更多响应。
 *
 * 在基类中，此方法不执行任何操作。
 *
 * \warning 策略在函数返回后不得保留 \p pitEntry shared_ptr 的副本，否则可能导致未定义行为。
 *          但是，策略可以构造并保留对 \p pitEntry 的 weak_ptr。
 */

/*当 After Receive Nack Trigger 被触发后，该策略通常可以执行以下操作之一：
    通过调用 send Interest 操作将其转发到相同或不同的上游来重试兴趣（ Retry the Interest ）。大多数策略都需要一个FIB条目来找出潜在的上游，这可以通过调用 Strategy::lookupFib 访问器函数获得；
    通过调用 send Nack 操作将 Nack 反回到下游，放弃对该 Interest 的重传尝试；
    不对这个 Nack 做任何处理。如果 Nack 对应的 Interest 转发给了多个上游，且某些（但不是全部）上游回复了 Nack ，则该策略可能要等待来自更多上游的 Data 或 Nack 。
    在这种情况下，该策略无需将 Nack 记录在其自己的 StrategyInfo 中，因为 NackHeader 已经存储在PIT out-record 的 Nacked 字段中了。*/
  virtual void
  afterReceiveNack(const lp::Nack& nack, const FaceEndpoint& ingress,
                   const shared_ptr<pit::Entry>& pitEntry);

  /**
   * \brief Trigger after an Interest is dropped (e.g., for exceeding allowed retransmissions).
   *
   * In the base class, this method does nothing.
   */
  virtual void
  onDroppedInterest(const Interest& interest, Face& egress);

  /**
   * \brief Trigger after a new nexthop is added.
   *
   * The strategy should decide whether to send the buffered Interests to the new nexthop.
   *
   * In the base class, this method does nothing.
   */
  virtual void
  afterNewNextHop(const fib::NextHop& nextHop, const shared_ptr<pit::Entry>& pitEntry);

protected: // actions
//操作（ Action ）是转发策略（ forwarding strategy ）做出的决策。操作（ Action ）被实现为 nfd::fw::Strategy 类的非虚拟保护方法。
  /**
   * \brief Send an Interest packet.
   * \param interest the Interest packet
   * \param egress face through which to send out the Interest
   * \param pitEntry the PIT entry
   * \return A pointer to the out-record created or nullptr if the Interest was dropped
   */
 //该操作将启动 Outgoing Interest 管道处理流程
  NFD_VIRTUAL_WITH_TESTS pit::OutRecord*
  sendInterest(const Interest& interest, Face& egress, const shared_ptr<pit::Entry>& pitEntry);
 /* 调用本操作的策略负责检查的转发是否不违反基于命名空间的范围控制[10]。通常，该策略应使用在PIT in-records 中找到的传入 Interest 之一来调用此操作。 
  * 只要兴趣仍然与PIT条目相匹配，就可以制作一个兴趣的副本并修改其指导字段（通常指的是，修改 LpHeaderField ）。
  /**
   * \brief Send a Data packet.
   * \param data the Data packet
   * \param egress face through which to send out the Data
   * \param pitEntry the PIT entry
   * \return Whether the Data was sent (true) or dropped (false)
   */
  NFD_VIRTUAL_WITH_TESTS bool
  sendData(const Data& data, Face& egress, const shared_ptr<pit::Entry>& pitEntry);

  /**
   * \brief Send a Data packet to all matched and qualified faces.
   *
   * A matched face qualifies if it is ad-hoc OR it is NOT \p inFace.
   *
   * \param data the Data packet
   * \param pitEntry the PIT entry
   * \param inFace face on which the Data arrived
   */
  NFD_VIRTUAL_WITH_TESTS void
  sendDataToAll(const Data& data, const shared_ptr<pit::Entry>& pitEntry, const Face& inFace);

  /**
   * \brief Schedule the PIT entry for immediate deletion.
   *
   * This helper function sets the PIT entry expiry time to zero.
   * The strategy should invoke this function when it concludes that the Interest cannot
   * be forwarded and it does not want to wait for responses from existing upstream nodes.
   */
  NFD_VIRTUAL_WITH_TESTS void
  rejectPendingInterest(const shared_ptr<pit::Entry>& pitEntry)
  {
    this->setExpiryTimer(pitEntry, 0_ms);
  }

  /**
   * \brief Send a Nack packet.
   *
   * The egress face must have a PIT in-record, otherwise this method has no effect.
   *
   * \param header the Nack header
   * \param egress face through which to send out the Nack
   * \param pitEntry the PIT entry
   * \return Whether the Nack was sent (true) or dropped (false)
   */
/*此操将启动 Outgoing Nack 管道（第4.4.2节）处理流程。PIT条目中应存在一个下游 Face 的 in-record ，
 * 并且通过从该 in-record 中获取最后一个传入的 Interest 并添加指定的 NackHeader ，将构造一个 Nack 包。
 * 如果对应的PIT表项中缺少符合条件的 in-record ，则此操作无效。*/
  NFD_VIRTUAL_WITH_TESTS bool
  sendNack(const lp::NackHeader& header, Face& egress, const shared_ptr<pit::Entry>& pitEntry)
  {
    return m_forwarder.onOutgoingNack(header, egress, pitEntry);
  }

  /**
   * \brief Send a Nack packet without going through the outgoing Nack pipeline.
   *
   * \param nack the Nack packet
   * \param egress face through which to send out the Nack
   * \return Whether the Nack was sent (true) or dropped (false)
   */
  NFD_VIRTUAL_WITH_TESTS bool
  sendNack(const lp::Nack& nack, Face& egress)
  {
    egress.sendNack(nack);
    ++m_forwarder.m_counters.nOutNacks;
    return true;
  }

  /**
   * \brief Send Nack to every face that has an in-record, except those in \p exceptFaces
   * \param header the Nack header
   * \param pitEntry the PIT entry
   * \param exceptFaces list of faces that should be excluded from sending Nacks
   * \note This is not an action, but a helper that invokes the sendNack() action.
   */
  void
  sendNacks(const lp::NackHeader& header, const shared_ptr<pit::Entry>& pitEntry,
            std::initializer_list<const Face*> exceptFaces = {});

  /**
   * \brief Schedule the PIT entry to be erased after \p duration.
   */
  void
  setExpiryTimer(const shared_ptr<pit::Entry>& pitEntry, time::milliseconds duration)
  {
    m_forwarder.setExpiryTimer(pitEntry, duration);
  }

protected: // accessors
  /**
   * \brief Performs a FIB lookup, considering Link object if present.
   */
  const fib::Entry&
  lookupFib(const pit::Entry& pitEntry) const;

  MeasurementsAccessor&
  getMeasurements() noexcept
  {
    return m_measurements;
  }

  Face*
  getFace(FaceId id) const noexcept
  {
    return getFaceTable().get(id);
  }

  const FaceTable&
  getFaceTable() const noexcept
  {
    return m_forwarder.m_faceTable;
  }

protected: // instance name
  struct ParsedInstanceName
  {
    Name strategyName; ///< Strategy name without parameters
    std::optional<uint64_t> version; ///< The strategy version number, if present
    PartialName parameters; ///< Parameter components, may be empty
  };

  /** \brief Parse a strategy instance name
   *  \param input strategy instance name, may contain version and parameters
   *  \throw std::invalid_argument input format is unacceptable
   */
  static ParsedInstanceName
  parseInstanceName(const Name& input);

  /** \brief Construct a strategy instance name
   *  \param input strategy instance name, may contain version and parameters
   *  \param strategyName strategy name with version but without parameters;
   *                      typically this should be \p getStrategyName()
   *
   *  If \p input contains a version component, return \p input unchanged.
   *  Otherwise, return \p input plus the version component taken from \p strategyName.
   *  This allows a strategy instance to be constructed with an unversioned name,
   *  but its final instance name should contain the version.
   */
  static Name
  makeInstanceName(const Name& input, const Name& strategyName);

  /** \brief Set strategy instance name
   *  \note This must be called by strategy subclass constructor.
   */
  void
  setInstanceName(const Name& name) noexcept
  {
    m_name = name;
  }

NFD_PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  /**
   * \brief Parse strategy parameters encoded in a strategy instance name
   * \param params encoded parameters, typically obtained from a call to parseInstanceName()
   * \throw std::invalid_argument the encoding format is invalid or unsupported by this implementation
   */
  static StrategyParameters
  parseParameters(const PartialName& params);

private: // registry
  using CreateFunc = std::function<unique_ptr<Strategy>(Forwarder&, const Name& /*strategyName*/)>;
  using Registry = std::map<Name, CreateFunc>; // indexed by strategy name

  static Registry&
  getRegistry();

  static Registry::const_iterator
  find(const Name& instanceName);

protected: // accessors
  signal::Signal<FaceTable, Face>& afterAddFace;
  signal::Signal<FaceTable, Face>& beforeRemoveFace;

private: // instance fields
  Name m_name;
  Forwarder& m_forwarder;
  MeasurementsAccessor m_measurements;
};

class StrategyParameters : public std::map<std::string, std::string>
{
public:
  // Note: only arithmetic types are supported by getOrDefault() for now

  template<typename T>
  std::enable_if_t<std::is_signed_v<T>, T>
  getOrDefault(const key_type& key, const T& defaultVal) const
  {
    auto it = find(key);
    if (it == end()) {
      return defaultVal;
    }

    T val{};
    if (!boost::conversion::try_lexical_convert(it->second, val)) {
      NDN_THROW(std::invalid_argument(key + " value is malformed"));
    }
    return val;
  }

  template<typename T>
  std::enable_if_t<std::is_unsigned_v<T>, T>
  getOrDefault(const key_type& key, const T& defaultVal) const
  {
    auto it = find(key);
    if (it == end()) {
      return defaultVal;
    }

    if (it->second.find('-') != std::string::npos) {
      NDN_THROW(std::invalid_argument(key + " cannot be negative"));
    }

    T val{};
    if (!boost::conversion::try_lexical_convert(it->second, val)) {
      NDN_THROW(std::invalid_argument(key + " value is malformed"));
    }
    return val;
  }
};

} // namespace nfd::fw

/**
 * \brief Registers a forwarding strategy.
 *
 * This macro should appear once in the `.cpp` of each strategy.
 */
#define NFD_REGISTER_STRATEGY(S)                       \
static class NfdAuto ## S ## StrategyRegistrationClass \
{                                                      \
public:                                                \
  NfdAuto ## S ## StrategyRegistrationClass()          \
  {                                                    \
    ::nfd::fw::Strategy::registerType<S>();            \
  }                                                    \
} g_nfdAuto ## S ## StrategyRegistrationVariable

/// Logs the reception of \p interest on \p ingress, followed by \p msg, at DEBUG level.
#define NFD_LOG_INTEREST_FROM(interest, ingress, msg)  \
  NFD_LOG_DEBUG("interest=" << (interest).getName() << \
                " nonce=" << (interest).getNonce() <<  \
                " from=" << (ingress) <<               \
                ' ' << msg)

/// Logs the reception of \p data on \p ingress, followed by \p msg, at DEBUG level.
#define NFD_LOG_DATA_FROM(data, ingress, msg)          \
  NFD_LOG_DEBUG("data=" << (data).getName() <<         \
                " from=" << (ingress) <<               \
                ' ' << msg)

/// Logs the reception of \p nack on \p ingress, followed by \p msg, at DEBUG level.
#define NFD_LOG_NACK_FROM(nack, ingress, msg)                   \
  NFD_LOG_DEBUG("nack=" << (nack).getInterest().getName() <<    \
                " nonce=" << (nack).getInterest().getNonce() << \
                " reason=" << (nack).getReason() <<             \
                " from=" << (ingress) <<                        \
                ' ' << msg)

#endif // NFD_DAEMON_FW_STRATEGY_HPP
