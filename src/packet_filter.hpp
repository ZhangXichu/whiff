#include <iostream>
#include <cstring>
#include <cstdint>

namespace whiff {

class PacketFilter {

public:

virtual bool match(const u_char* packet, uint32_t len) const = 0;


};

}