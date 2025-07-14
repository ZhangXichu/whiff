#pragma once

#include <memory>
#include <packet_handler.hpp>
#include <beacon_filter.hpp>
#include <handshake_extractor.hpp>
#include <hc22000_exporter.hpp>
#include <access_point_registry.hpp>

namespace whiff {

class Whiff {

public:
static Whiff from_args(int argc, char** argv);
void run();

private:
enum class Mode {
    Capture,
    Dump,
    DumpAll,
    Export
};
Mode _mode;
std::string _outfile;
std::string _interface;
AccessPointRegistry _registry;
std::unique_ptr<PacketHandler> _pkt_handler;

};


}