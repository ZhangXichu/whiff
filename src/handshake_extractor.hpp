#pragma once

#include <pcap.h>
#include <vector>
#include <cstdint>
#include <string>

namespace whiff {

struct EapolPacket 
{
    struct timeval timestamp;
    std::vector<uint8_t> raw_data;
};

class HandshakeExtractor {

public:
    explicit HandshakeExtractor(const std::string& pcap_file);
    ~HandshakeExtractor();

    bool extract_handshake();
    const std::vector<EapolPacket>& get_eapol_packets() const;

private:
    std::string _pcap_file;
    std::vector<EapolPacket> _eapol_packets;

    static bool is_eapol_packet(const u_char* packet, uint32_t len);

};


}