#pragma once

#include <unordered_map>
#include <string>
#include <cstdint>
#include <optional>
#include <packet_data.hpp>

namespace whiff {

class AccessPointRegistry {

public:
void add_entry(const BeaconInfo& info);
std::optional<std::string> get_bssid(const std::string& ssid) const;

private:
std::unordered_map<std::string, std::string> _ssid_to_bssid;

};

}