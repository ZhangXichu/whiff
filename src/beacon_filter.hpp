#pragma once

#include <packet_filter.hpp>

#include <cstdint>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <access_point_registry.hpp>

namespace whiff {

class BeaconFilter : public PacketFilter {

public:   
BeaconFilter(AccessPointRegistry& registry,
              std::mutex& mutex,
              std::condition_variable& cv,
              std::string& target_ssid);

bool match(const u_char* packet, uint32_t len) const override;
std::optional<BeaconInfo> parse(const u_char* packet, uint32_t len) const;

private:
AccessPointRegistry& _registry;
std::mutex& _mutex;
std::condition_variable& _cv;
std::string& _target_ssid;

static inline bool is_mgmt(uint16_t fc)   { return ((fc >> 2) & 0x3) == 0; }
static inline uint8_t subtype(uint16_t fc){ return (fc >> 4) & 0xF; }
static inline uint16_t le16(const u_char* p) { return p[0] | (p[1] << 8); }

};

}