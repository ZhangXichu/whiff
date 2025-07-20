#pragma once

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <sys/time.h>

namespace whiff {

struct BeaconInfo {
  std::string ssid;
  std::string bssid;
};

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
    std::vector<uint8_t> eapol_payload;
    std::vector<uint8_t> eapol_payload_zeroed;
    std::array<uint8_t, 6> src_mac{};  // Source MAC address
    std::array<uint8_t, 6> dst_mac{};  // Destination MAC address
    std::array<uint8_t, 6> bssid{};
    bool has_mic = false;
    bool is_from_ap = false;
    KeyDescriptor key_descriptor;
};


struct HandshakeData {
    std::array<uint8_t, 6> ap_mac;
    std::array<uint8_t, 6> client_mac;
    std::array<uint8_t, 32> anonce;
    std::array<uint8_t, 32> snonce;
    std::array<uint8_t, 16> mic;
    std::vector<uint8_t> eapol_frame;
    uint8_t message_pair = 0x00;
    std::string ssid;
};

}