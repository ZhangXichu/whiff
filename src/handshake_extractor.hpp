#pragma once

#include <pcap.h>
#include <vector>
#include <cstdint>
#include <string>
#include <array>

namespace whiff {

struct EapolPacket 
{
    struct timeval timestamp;
    std::vector<uint8_t> raw_data;
};


struct KeyDescriptor {
    uint8_t descriptor_type;
    uint16_t key_info;
    uint16_t key_length;
    std::array<uint8_t, 8> replay_counter;
    std::array<uint8_t, 32> nonce;
    std::array<uint8_t, 16> key_iv;
    std::array<uint8_t, 8> key_rsc;
    std::array<uint8_t, 16> mic;
    uint16_t key_data_length;
    std::vector<uint8_t> key_data;
};


struct Eapol {
    timeval timestamp;
    std::vector<uint8_t> raw_frame;
    std::array<uint8_t, 6> src_mac{};  // Source MAC address
    std::array<uint8_t, 6> dst_mac{};  // Destination MAC address
    bool has_mic = false;
    bool is_from_ap = false;
    KeyDescriptor key_descriptor;
};


class HandshakeExtractor {

public:
    explicit HandshakeExtractor(const std::string& pcap_file);
    ~HandshakeExtractor();

    bool extract_handshake();
    const std::vector<EapolPacket>& get_eapol_packets() const;
    Eapol parse_packet(const EapolPacket& pkt);

private:
    std::string _pcap_file;
    std::vector<EapolPacket> _eapol_packets;

    static bool is_eapol_packet(const u_char* packet, uint32_t len);

};


}