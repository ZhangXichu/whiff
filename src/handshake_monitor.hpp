#include <iostream>
#include <cstring>
#include <cstdint>

namespace whiff {

class HandshakeMonitor {


public:

bool is_eapol_packet(const u_char* packet, uint32_t len);


private:


};

}