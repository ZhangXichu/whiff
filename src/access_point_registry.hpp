#pragma once

#include <unordered_map>
#include <string>
#include <cstdint>
#include <beacon_filter.hpp>

namespace whiff {

class AccessPointRegistry {

public:
void add_entry(const BeaconFilter::BeaconInfo& info);
std::optional<std::string> get_bssid(const std::string& ssid) const;

private:
std::unordered_map<std::string, std::string> _ssid_to_bssid;

};

}