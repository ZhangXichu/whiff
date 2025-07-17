#include "packet_handler.hpp"

namespace whiff {

PacketHandler::PacketHandler(PacketFilter* filter)
 :_filter(filter) {}

void PacketHandler::stop()
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

PacketHandler::~PacketHandler()
{
    std::cout << "dtor called" << std::endl;
    stop();
}

void PacketHandler::pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* ctx = reinterpret_cast<CaptureContext*>(user);

    if (ctx->filter && ctx->filter->match(packet, header->len)) {  // TODO: check ssid
        pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), header, packet);

        ctx->on_match(header, packet);
    }
}

void PacketHandler::capture(const std::string& iface, const std::string& output_file, PacketCallback on_match)
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

    CaptureContext ctx{ _dumper, _filter, on_match};
    pcap_loop(_handle, 0, pcap_callback, reinterpret_cast<u_char*>(&ctx));
}

void PacketHandler::set_filter(PacketFilter* new_filter) { // TODO: maybe remove this
    _filter = new_filter;
}

}