#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include "packet_handler.hpp"
#include "signal_handler.hpp"
#include "pcap_reader.hpp"
#include <handshake_extractor.hpp>


int main(int argc, char* argv[])
{
    // if (argc < 2) {
    //     std::cerr << "Usage: " << argv[0] << " <interface>\n";
    //     return 1;
    // }

    // const char* dev = argv[1];
    // const char* output_file = (argc >= 3) ? argv[2] : "/home/xichuz/workspace/whiff/dump.pcap";

    // whiff::PacketHandler pkt_handler;

    // whiff::SignalHandler::set_callback([&]() { pkt_handler.stop(); });
    // whiff::SignalHandler::setup();

    // pkt_handler.capture(dev, output_file);

    // std::cout << "[*] Finished capture.\n";

    // whiff::PcapReader pcap_reader("/home/xichuz/workspace/whiff/dump.pcap");

    // pcap_reader.read_all();

    whiff::HandshakeExtractor extractor("/home/xichuz/workspace/whiff/dump.pcap");
    if (extractor.extract_handshake()) {
        std::cout << "[*] EAPOL handshake(s) found: " << extractor.get_eapol_packets().size() << "\n";
    } else {
        std::cout << "[-] No EAPOL packets found.\n";
    }

    return 0;
}