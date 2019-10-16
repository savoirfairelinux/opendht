#include "callbacks.h"

namespace dht {


GetCallbackSimple
bindGetCb(const GetCallbackRaw& raw_cb, void* user_data)
{
    if (not raw_cb) return {};
    return [=](const std::shared_ptr<Value>& value) {
        return raw_cb(value, user_data);
    };
}

GetCallback
bindGetCb(const GetCallbackSimple& cb)
{
    if (not cb) return {};
    return [=](const std::vector<std::shared_ptr<Value>>& values) {
        for (const auto& v : values)
            if (not cb(v))
                return false;
        return true;
    };
}

ValueCallback
bindValueCb(const ValueCallbackRaw& raw_cb, void* user_data)
{
    if (not raw_cb) return {};
    return [=](const std::vector<std::shared_ptr<Value>>& values, bool expired) {
        for (const auto& v : values)
            if (not raw_cb(v, expired, user_data))
                return false;
        return true;
    };
}

ShutdownCallback
bindShutdownCb(const ShutdownCallbackRaw& shutdown_cb_raw, void* user_data)
{
    return [=]() { shutdown_cb_raw(user_data); };
}

DoneCallback
bindDoneCb(DoneCallbackSimple donecb)
{
    if (not donecb) return {};
    using namespace std::placeholders;
    return std::bind(donecb, _1);
}

DoneCallback
bindDoneCb(const DoneCallbackRaw& raw_cb, void* user_data)
{
    if (not raw_cb) return {};
    return [=](bool success, const std::vector<std::shared_ptr<Node>>& nodes) {
        raw_cb(success, (std::vector<std::shared_ptr<Node>>*)&nodes, user_data);
    };
}

DoneCallbackSimple
bindDoneCbSimple(const DoneCallbackSimpleRaw& raw_cb, void* user_data) {
    if (not raw_cb) return {};
    return [=](bool success) {
        raw_cb(success, user_data);
    };
}

std::string
NodeStats::toString() const
{
    std::stringstream ss;
    ss << "Known nodes: " << good_nodes << " good, " << dubious_nodes << " dubious, " << incoming_nodes << " incoming." << std::endl;
    if (table_depth > 1) {
        ss << "Routing table depth: " << table_depth << std::endl;
        ss << "Network size estimation: " << getNetworkSizeEstimation() << " nodes" << std::endl;
    }
    return ss.str();
}

#ifdef OPENDHT_JSONCPP
/**
 * Build a json object from a NodeStats
 */
Json::Value
NodeStats::toJson() const
{
    Json::Value val;
    val["good"] = static_cast<Json::LargestUInt>(good_nodes);
    val["dubious"] = static_cast<Json::LargestUInt>(dubious_nodes);
    val["incoming"] = static_cast<Json::LargestUInt>(incoming_nodes);
    if (table_depth > 1) {
        val["table_depth"] = static_cast<Json::LargestUInt>(table_depth);
        val["network_size_estimation"] = static_cast<Json::LargestUInt>(getNetworkSizeEstimation());
    }
    return val;
}

NodeStats::NodeStats(const Json::Value& val)
{
    if (val.isMember("good"))
        good_nodes = static_cast<unsigned>(val["good"].asLargestUInt());
    if (val.isMember("dubious"))
        dubious_nodes = static_cast<unsigned>(val["dubious"].asLargestUInt());
    if (val.isMember("incoming"))
        incoming_nodes = static_cast<unsigned>(val["incoming"].asLargestUInt());
    if (val.isMember("table_depth"))
        table_depth = static_cast<unsigned>(val["table_depth"].asLargestUInt());
}

/**
 * Build a json object from a NodeStats
 */
Json::Value
NodeInfo::toJson() const
{
    Json::Value val;
    if (id)
        val["id"] = id.toString();
    val["node_id"] = node_id.toString();
    val["ipv4"] = ipv4.toJson();
    val["ipv6"] = ipv6.toJson();
    return val;
}

NodeInfo::NodeInfo(const Json::Value& v)
{
    if (v.isMember("id"))
        id = InfoHash(v["id"].asString());
    node_id = InfoHash(v["node_id"].asString());
    ipv4 = NodeStats(v["ipv4"]);
    ipv6 = NodeStats(v["ipv6"]);
}

#endif


}
