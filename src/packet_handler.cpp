#include "packet_handler.hpp"

#include <loguru.hpp>

namespace whiff {

PacketHandler::PacketHandler(PacketFilter* filter)
 :_filter(filter) {}

void PacketHandler::stop()
{
    if (_handle) {
        pcap_breakloop(_handle);
    }
}

PacketHandler::~PacketHandler()
{
    LOG_F(1, "PacketHandler destructor called");
    stop();
}

void PacketHandler::pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {

// TODO: check here if _target_bssid is set
// if so break the loop

    LOG_F(1, "pcap_callback called.");

    auto* ctx = reinterpret_cast<CaptureContext*>(user);

    if (ctx->filter && ctx->filter->match(packet, header->len)) {  // TODO: check ssid
        pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), header, packet);
    }
}

void PacketHandler::capture(const std::string& iface, const std::string& output_file)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    _handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!_handle) {
        LOG_F(ERROR, "pcap_open_live failed: %s", errbuf);
        return;
    }

    _dumper = pcap_dump_open(_handle, output_file.c_str());
    if (!_dumper) 
    {
        LOG_F(ERROR, "pcap_dump_open failed: %s", pcap_geterr(_handle));
        pcap_close(_handle);
        _handle = nullptr;
        return;
    }

    LOG_F(INFO, "Starting packet capture on interface: %s, saving to %s", iface.c_str(), output_file.c_str());

    CaptureContext ctx{ _dumper, _filter};
    pcap_loop(_handle, 0, pcap_callback, reinterpret_cast<u_char*>(&ctx));

    if (_dumper) {
        pcap_dump_close(_dumper);
        _dumper = nullptr;
    }

    if (_handle) {
        pcap_close(_handle);
        _handle = nullptr;
    }
}

void PacketHandler::set_filter(PacketFilter* new_filter) { // TODO: maybe remove this
    _filter = new_filter;
}

}