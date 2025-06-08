#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include "packet_handler.hpp"


int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }

    const char* dev = argv[1];
    const char* output_file = (argc >= 3) ? argv[2] : "handshakee.pcap";

    whiff::PacketHandler pkt_handler;

    pkt_handler.capture(dev, output_file);

    return 0;
}