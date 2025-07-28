#include <whiff.hpp>

#include <thread>
#include <chrono>
#include <signal_handler.hpp>
#include <loguru.hpp>

namespace whiff {

std::unique_ptr<Whiff> Whiff::from_args(int argc, char** argv) {
    if (argc < 2) {
        throw std::runtime_error("Usage:\n"
            "  ./whiff --capture <interface> <output.pcap>\n"
            "  ./whiff --export <interface> <output.pcap>\n");
    }

    auto app = std::make_unique<Whiff>();  // TODO: make order of flags independent (use map)
    std::string flag = argv[1];

    if (flag == "--capture") {
        if (argc < 4) throw std::runtime_error("Missing args for --capture");
        app->_mode = Mode::Capture;
        app->_interface = argv[2];
        app->_outfile = argv[3];

    } 
    else if (flag == "--export") {
        if (argc < 4) throw std::runtime_error("Missing args for --export");
        app->_mode = Mode::Export;
        app->_interface = argv[2];
        app->_outfile = argv[3];
    } else {
        throw std::runtime_error("Unknown mode flag: " + flag);
    }

    return app;
}


void Whiff::run() {

    switch (_mode) {
        case Mode::Capture: {

            std::string target_ssid = "realme 8"; // TODO: make this part of command line arguement
            _target_bssid = std::nullopt;
            
            _beacon_filter = std::make_unique<BeaconFilter>(_registry, _mutex, _cv, target_ssid, _target_bssid);
            _pkt_handler  = std::make_unique<PacketHandler>(_beacon_filter.get());

            std::thread monitor([&]() {
                std::unique_lock<std::mutex> lock(_mutex);
                _cv.wait(lock, [&]() { 
                    LOG_F(INFO, "target_bssid has value: %s", _target_bssid.has_value() ? "true" : "false");
                    return _target_bssid.has_value() || _abort.load(); 
                });
                LOG_F(1, "calling pcap_breakloop");
                _pkt_handler->stop();
            });

            SignalHandler::set_callback([&]() {
                 _pkt_handler->stop();

                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    _abort.store(true);
                    _cv.notify_one();
                }

                 if (monitor.joinable())
                     monitor.join(); 
            });
            SignalHandler::setup();

            _pkt_handler->capture(_interface.c_str(), _outfile.c_str());

            if (monitor.joinable())
                monitor.join();

            std::this_thread::sleep_for(std::chrono::seconds(2)); 

            _pkt_handler.reset();  

            if (_target_bssid) {
                LOG_F(INFO, "[*] Starting EAPOL capture for BSSID: %s", _target_bssid->c_str());

                _eapol_filter = std::make_unique<EapolFilter>(*_target_bssid);
                _pkt_handler = std::make_unique<PacketHandler>(_eapol_filter.get());

                _pkt_handler->capture(_interface.c_str(), _outfile.c_str());

                LOG_F(INFO, "[*] Exporting EAPOL packets to %s", _outfile.c_str());
            } else {
                LOG_F(WARNING, "No target SSID detected. EAPOL capture skipped.");
            }

            LOG_F(INFO, "[*] Finished capture.\n");
            break;
        }

        case Mode::Export: {
            HandshakeExtractor extractor("/home/xichuz/workspace/whiff/eapol.pcap"); // TODO : set this using cli

            if (extractor.extract_handshake()) {
                LOG_F(INFO, "[*] EAPOL handshake(s) found: %zu",
                          extractor.get_eapol_packets().size());
            } else {
                LOG_F(ERROR, "No EAPOL packets found.");
                return;
            }

            for (const auto& pkt : extractor.get_eapol_packets()) {
                extractor.parse_packet(pkt);
            }

            auto data = extractor.prepare_handshake_info();
            if (!data.has_value()) {
                LOG_F(ERROR, "Could not prepare handshake data.");
                return;
            }

            Hc22000Exporter::export_to_file(data.value(), "realme 8", _outfile); // TODO: set target ssid using cli
            LOG_F(INFO, "[*] Exported handshake to %s", _outfile.c_str());
            break;
        }
    }
}

}