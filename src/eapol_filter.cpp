#include <eapol_filter.hpp>

namespace whiff {

EapolFilter::EapolFilter(const std::string& bssid) {
    unsigned int bytes[6];
    std::sscanf(bssid.c_str(), "%x:%x:%x:%x:%x:%x",
                &bytes[0], &bytes[1], &bytes[2],
                &bytes[3], &bytes[4], &bytes[5]);
    for (int i = 0; i < 6; ++i) {
        _bssid[i] = static_cast<uint8_t>(bytes[i]);
    }
}

bool EapolFilter::match(const u_char* packet, uint32_t len) const  // TODO: check BSSID (derive from SSID -> need to get beacon, implement beacon filter first)
{
    if (len < 36) return false;

    std::cout << "length: " << std::dec << len << std::endl;

    // Radiotap header length
    uint16_t radiotap_len = packet[2] | (packet[3] << 8);

    std::cout << "radiotap_len: " << radiotap_len << std::endl;
    
    if (len <= radiotap_len + 24) return false;

    const u_char* payload = packet + radiotap_len;

    // Frame control field (first 2 bytes)
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xf;

    std::cout << "type: " << static_cast<int>(type) << std::endl;
    std::cout << "subtype: " << static_cast<int>(subtype) << std::endl;

    // Only handle Data frames
    if (type != 2) return false;

    bool to_ds   = fc & 0x0100;
    bool from_ds = fc & 0x0200;

    // Check if Address4 is present (ToDS + FromDS both set)
    bool has_addr4 = (fc & 0x0300) == 0x0300;
    size_t hdr_len = 24 + (has_addr4 ? 6 : 0);

    std::cout << "hdr_len: " << hdr_len << std::endl;
    std::cout << "has_addr4=" << std::boolalpha << has_addr4 << std::endl;

    // Add QoS control field if needed
    if (subtype & 0x08) {
        hdr_len += 2;
    }

    // Add HT control field if present (not handled here yet)
    if (len <= radiotap_len + hdr_len + 8) return false;

    const u_char* addr1 = payload + 4;
    const u_char* addr2 = payload + 10;
    const u_char* addr3 = payload + 16;

    auto format_mac = [](const uint8_t* mac) {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return std::string(buf);
    };

    std::cout << "[debug] ToDS=" << to_ds << ", FromDS=" << from_ds << "\n";
    std::cout << "        Addr1 (dst)  = " << format_mac(addr1) << "\n";
    std::cout << "        Addr2 (src)  = " << format_mac(addr2) << "\n";
    std::cout << "        Addr3 (BSSID?) = " << format_mac(addr3) << "\n";

    // Determine BSSID location
    const u_char* bssid_ptr = nullptr;
    if (!to_ds && !from_ds) {  // management, control or DTL frames
        bssid_ptr = addr3;
    } else if (to_ds && !from_ds) { // client to DS
        bssid_ptr = addr1; // addr2
    } else if (!to_ds && from_ds) {  // DS to client
        bssid_ptr = addr2; 
    } else {  // wireless mesh or bridge 
        return false;
    }

    // Debug print
    std::cout << "[debug] Comparing BSSID\n";
    std::cout << "        expected = " << format_mac(_bssid.data()) << "\n";
    std::cout << "        in frame = " << format_mac(bssid_ptr) << "\n";

    // Compare BSSID
    if (!std::equal(_bssid.begin(), _bssid.end(), bssid_ptr)) {
        return false;
    }

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