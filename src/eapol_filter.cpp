#include <eapol_filter.hpp>

namespace whiff {

bool EapolFilter::match(const u_char* packet, uint32_t len) const
{
    if (len < 36) return false;

    // Radiotap header length
    uint16_t radiotap_len = packet[2] | (packet[3] << 8);
    if (len <= radiotap_len + 24) return false;

    const u_char* payload = packet + radiotap_len;

    // Frame control field (first 2 bytes)
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xf;

    // Only handle Data frames
    if (type != 2) return false;

    // Check if Address4 is present (ToDS + FromDS both set)
    bool has_addr4 = (fc & 0x0300) == 0x0300;
    size_t hdr_len = 24 + (has_addr4 ? 6 : 0);

    // Add QoS control field if needed
    if (subtype & 0x08) {
        hdr_len += 2;
    }

    // Add HT control field if present (not handled here yet)
    if (len <= radiotap_len + hdr_len + 8) return false;

    const u_char* llc = payload + hdr_len;

    // Check for LLC/SNAP
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
        uint16_t ethertype = (llc[6] << 8) | llc[7];

        std::cout << "[debug] Packet len=" << len
          << ", radiotap=" << radiotap_len
          << ", 802.11 hdr=" << hdr_len
          << ", llc[0-2]=" << std::hex << (int)llc[0] << " " << (int)llc[1] << " " << (int)llc[2]
          << ", ethertype=" << std::hex << ethertype << "\n";

        return ethertype == 0x888E;
    }

    return false;
}

    
}