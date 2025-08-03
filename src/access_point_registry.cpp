#include <access_point_registry.hpp>


namespace whiff {

void AccessPointRegistry::add_entry(const BeaconInfo& info) 
{
    _ssid_to_bssid.insert_or_assign(info.ssid, info.bssid);
}

std::optional<std::string> AccessPointRegistry::get_bssid(const std::string& ssid) const 
{
    auto it = _ssid_to_bssid.find(ssid);
    if (it != _ssid_to_bssid.end()) {
        return it->second;
    }
    return std::nullopt;
}

const std::unordered_map<std::string, std::string>& AccessPointRegistry::get_entries() const
{
    return _ssid_to_bssid;
}

}