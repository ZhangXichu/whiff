#pragma once

#include <packet_filter.hpp>

namespace whiff {

class BeaconFilter : public PacketFilter {

public:    
bool match(const u_char* packet, uint32_t len) const override;

private:
inline bool is_mgmt(uint16_t fc)   { return ((fc >> 2) & 0x3) == 0; }
inline uint8_t subtype(uint16_t fc){ return (fc >> 4) & 0xF; }
inline uint16_t le16(const u_char* p) { return p[0] | (p[1] << 8); }

};

}