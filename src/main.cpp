#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include "packet_handler.hpp"
#include "signal_handler.hpp"


int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }

    const char* dev = argv[1];
    const char* output_file = (argc >= 3) ? argv[2] : "handshakee.pcap";

    whiff::PacketHandler pkt_handler;

    whiff::SignalHandler::set_callback([&]() { pkt_handler.stop(); });
    whiff::SignalHandler::setup();

    pkt_handler.capture(dev, output_file);

    std::cout << "[*] Finished capture.\n";

    return 0;
}