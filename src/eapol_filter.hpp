#pragma once

#include <array>
#include <packet_filter.hpp>


namespace whiff {

class EapolFilter : public PacketFilter {

public:
explicit EapolFilter(const std::string& bssid);
bool match(const u_char* packet, uint32_t len) const override;

private:
std::array<uint8_t, 6> _bssid;

};


}