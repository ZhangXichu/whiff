#pragma once

#include <pcap.h>
#include <string>
#include <optional>
#include <packet_data.hpp>
#include <utils.hpp>
#include <packet_filter.hpp>

namespace whiff {

class HandshakeExtractor {

public:
    HandshakeExtractor(const std::string& pcap_file);
    ~HandshakeExtractor();

    bool extract_handshake();
    const std::vector<EapolPacket>& get_eapol_packets() const;
    Eapol parse_packet(const EapolPacket& pkt);
    std::optional<HandshakeData> prepare_handshake_info();

private:
    using ReplayCounter = uint64_t;

    struct HandshakeBins {
        std::vector<Eapol> m1s;
        std::vector<Eapol> m2s;
        std::vector<Eapol> m3s;
        std::vector<Eapol> m4s;
    };

    std::string _pcap_file;
    std::vector<EapolPacket> _eapol_packets;
};


}