#include "packet_handler.hpp"

namespace whiff {

PacketHandler::~PacketHandler()
{
    if (_dumper) {
        pcap_dump_close(_dumper);
        _dumper = nullptr;
    }
    if (_handle) {
        pcap_close(_handle);
        _handle = nullptr;
    }
}

void PacketHandler::pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* ctx = reinterpret_cast<CaptureContext*>(user);

    std::cout << "[*] Packet length: " << header->len << "\n";
    pcap_dump((u_char*)ctx->dumper, header, packet);
}

void PacketHandler::capture(const std::string& iface, const std::string& output_file)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    _handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!_handle) {
        std::cerr << "[-] pcap_open_live failed: " << errbuf << "\n";
        return;
    }

    _dumper = pcap_dump_open(_handle, output_file.c_str());
    if (!_dumper) {
        std::cerr << "[-] pcap_dump_open failed: " << pcap_geterr(_handle) << "\n";
        pcap_close(_handle);
        _handle = nullptr;
        return;
    }

    std::cout << "[+] Capturing packets on " << iface << ", saving to: " << output_file << "\n";

    CaptureContext ctx{ _dumper };
    pcap_loop(_handle, 0, pcap_callback, reinterpret_cast<u_char*>(&ctx));
}

}