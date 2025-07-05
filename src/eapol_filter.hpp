#pragma once

#include <packet_filter.hpp>


namespace whiff {

class EapolFilter : public PacketFilter {

public:
bool match(const u_char* packet, uint32_t len) const override;

};


}