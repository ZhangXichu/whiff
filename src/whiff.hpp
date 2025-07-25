#pragma once

#include <memory>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <packet_handler.hpp>
#include <beacon_filter.hpp>
#include <eapol_filter.hpp>
#include <handshake_extractor.hpp>
#include <hc22000_exporter.hpp>
#include <access_point_registry.hpp>

namespace whiff {

class Whiff {

public:
static std::unique_ptr<Whiff> from_args(int argc, char** argv);
void run();

private:
enum class Mode {
    Capture,
    Dump,
    DumpAll,
    Export
};
std::atomic<bool> _abort = false;
Mode _mode;
std::mutex _mutex;
std::condition_variable _cv;
std::string _outfile;
std::string _interface;
AccessPointRegistry _registry;
std::optional<std::string> _target_bssid;
std::unique_ptr<PacketHandler> _pkt_handler;
std::unique_ptr<BeaconFilter> _beacon_filter;
std::unique_ptr<EapolFilter> _eapol_filter;

};


}