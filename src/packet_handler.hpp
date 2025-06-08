#pragma once

#include <pcap.h>
#include <string>
#include <iostream>
#include <packet_handler.hpp>

namespace whiff {

struct CaptureContext 
{
    pcap_dumper_t* dumper;
};

class PacketHandler {

public:

~PacketHandler();

void capture(const std::string& iface, const std::string& output_file);

private:

pcap_t* _handle = nullptr;
pcap_dumper_t* _dumper = nullptr;

static void pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

};

}