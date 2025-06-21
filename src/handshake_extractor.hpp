#pragma once

#include <pcap.h>
#include <string>
#include <optional>
#include <packet_data.hpp>

namespace whiff {



class HandshakeExtractor {

public:
    explicit HandshakeExtractor(const std::string& pcap_file);
    ~HandshakeExtractor();

    bool extract_handshake();
    const std::vector<EapolPacket>& get_eapol_packets() const;
    Eapol parse_packet(const EapolPacket& pkt);
    std::optional<HandshakeData> prepare_handshake_info();

private:
    std::string _pcap_file;
    std::vector<EapolPacket> _eapol_packets;

    static bool is_eapol_packet(const u_char* packet, uint32_t len);
    std::string to_hex(const uint8_t* data, size_t len);

};


}