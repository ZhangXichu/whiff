#include <hc22000_exporter.hpp>
#include <fstream>
#include <cctype>
#include <algorithm>
#include <iostream>

namespace whiff {

namespace {
bool requires_hex_encoding(const std::string& ssid) {
    return std::any_of(ssid.begin(), ssid.end(), [](char c) {
        return static_cast<unsigned char>(c) < 0x20 || c == '*' || c == ' ' || c > 0x7E;
    });
}
}

std::string Hc22000Exporter::generate_line(const HandshakeData& h, const std::string& ssid) {
    using whiff::utils::to_hex;

    std::string encoded_ssid;
    if (requires_hex_encoding(ssid)) {
        encoded_ssid = to_hex(reinterpret_cast<const uint8_t*>(ssid.data()), ssid.size());
    } else {
        encoded_ssid = ssid;
    }

    std::string line = "WPA*02*";
    line += to_hex(h.mic.data(), 16) + "*";
    line += to_hex(h.ap_mac.data(), 6) + "*";
    line += to_hex(h.client_mac.data(), 6) + "*";
    line += encoded_ssid + "*";
    line += to_hex(h.anonce.data(), 32) + "*";
    line += to_hex(h.eapol_frame.data(), h.eapol_frame.size()) + "*";
    line += "00";

    std::cout << "[*] Exported line:\n" << line << "\n";

    return line;
}

void Hc22000Exporter::export_to_file(const HandshakeData& handshake,
                                     const std::string& ssid,
                                     const std::string& filepath) {
    std::ofstream ofs(filepath);
    if (!ofs) {
        throw std::runtime_error("Cannot open output file: " + filepath);
    }

    ofs << generate_line(handshake, ssid);
}

// overload for future use
void Hc22000Exporter::export_to_file(const std::vector<HandshakeData>& handshakes,
                                     const std::string& ssid,
                                     const std::string& filepath) {
    std::ofstream ofs(filepath);
    if (!ofs) throw std::runtime_error("Cannot open output file: " + filepath);

    for (const auto& h : handshakes) {
        ofs << generate_line(h, ssid) << "\n";
    }
}

}