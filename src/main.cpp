#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <packet_handler.hpp>
#include <signal_handler.hpp>
#include <handshake_extractor.hpp>
#include <hc22000_exporter.hpp>
#include <eapol_filter.hpp>
#include <beacon_filter.hpp>


int main(int argc, char* argv[])
{
    using namespace whiff;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }

    const char* dev = argv[1];
    const char* output_file = (argc >= 3) ? argv[2] : "/home/xichuz/workspace/whiff/beacon.pcap";

    std::unique_ptr<whiff::BeaconFilter> filter = std::make_unique<whiff::BeaconFilter>();

    whiff::PacketHandler pkt_handler(filter.get());

    whiff::SignalHandler::set_callback([&]() { pkt_handler.stop(); });
    whiff::SignalHandler::setup();

    pkt_handler.capture(dev, output_file);

    std::cout << "[*] Finished capture.\n";

    // std::unique_ptr<whiff::EapolFilter> filter = std::make_unique<whiff::EapolFilter>();

    // whiff::HandshakeExtractor extractor("/home/xichuz/workspace/whiff/packets/dump5.pcap");
    // if (extractor.extract_handshake()) {
    //     std::cout << "[*] EAPOL handshake(s) found: " << extractor.get_eapol_packets().size() << "\n";
    // } else {
    //     std::cout << "[-] No EAPOL packets found.\n";
    //     return 0;
    // }

    // for (const auto& pkt : extractor.get_eapol_packets()) {
    //     extractor.parse_packet(pkt);
    // }

    // auto data = extractor.prepare_handshake_info();

    // whiff::Hc22000Exporter hc_exporter;

    // std::string ssid = "realme 8";
    // std::string filepath = "/home/xichuz/workspace/whiff/out";
    // if (data.has_value()) {
    //     whiff::Hc22000Exporter::export_to_file(data.value(), ssid, filepath);
    // }

    return 0;
}