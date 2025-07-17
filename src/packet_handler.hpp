#pragma once

#include <pcap.h>
#include <string>
#include <iostream>
#include <memory>
#include <queue>
#include <functional>
#include <packet_handler.hpp>
#include <packet_filter.hpp>

namespace whiff {

class PacketHandler {

public:

using PacketCallback = std::function<void(const struct pcap_pkthdr*, const u_char*)>;

PacketHandler(PacketFilter* filter);
~PacketHandler();

void capture(const std::string& iface, const std::string& output_file, PacketCallback on_match);
void stop();
void set_filter(PacketFilter* new_filter);

private:
struct CaptureContext {
    pcap_dumper_t* dumper;
    PacketFilter*  filter;
    PacketCallback on_match;
};


pcap_t* _handle = nullptr;
pcap_dumper_t* _dumper = nullptr;
PacketFilter* _filter;

static void pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

};


}