#pragma once

#include <packet_data.hpp>
#include <utils.hpp>

namespace whiff {

class Hc22000Exporter {
public:
    static std::string generate_line(const HandshakeData& h, const std::string& ssid);
    static void export_to_file(const std::vector<HandshakeData>& handshakes,
                               const std::string& ssid,
                               const std::string& filepath);
    static void export_to_file(const HandshakeData& handshakes,
                               const std::string& ssid,
                               const std::string& filepath);
};

}