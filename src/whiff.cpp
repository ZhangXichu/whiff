#include <whiff.hpp>

#include <thread>
#include <chrono>
#include <signal_handler.hpp>
#include <loguru.hpp>
#include <constants.hpp>

namespace whiff {

std::unique_ptr<Whiff> Whiff::from_args(int argc, char** argv) {
    if (argc < 3) {
        throw std::runtime_error(
            "Usage:\n"
            "  ./whiff --capture <interface> --output <file.pcap> [--ssid <name>]\n"
            "  ./whiff --export <interface> --input <file.pcap> --output <file.22000> [--ssid <name>]\n"
            "  ./whiff --list <interface>\n"
        );
    }

    std::string mode_flag;
    std::string interface;
    std::unordered_map<std::string, std::string> options;

    auto app = std::make_unique<Whiff>();
    std::string flag = argv[1];

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == flags::capture_mode || arg == flags::export_mode || arg == flags::list) {
            if (!mode_flag.empty()) {
                throw std::runtime_error("Specify only one mode: --capture, --export or --list");
            }
            mode_flag = arg;

            // Interface must follow
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing interface after " + arg);
            }
            interface = argv[++i];
        } else if (arg == flags::output || arg == flags::input || arg == flags::ssid) {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value after " + arg);
            }
            options[arg] = argv[++i];
        } else {
            throw std::runtime_error("Unknown argument: " + arg);
        }
    }

    if (mode_flag.empty()) {
        throw std::runtime_error("You must specify one mode: --capture or --export");
    }

    app->_interface = interface;

    if (mode_flag == flags::capture_mode) {
        app->_mode = Mode::Capture;

        if (options.find(flags::output) == options.end()) {
            throw std::runtime_error("--output <file.pcap> is required in capture mode");
        }

        app->_outfile = options[flags::output];

    } else if (mode_flag == flags::export_mode) {
        app->_mode = Mode::Export;

        if (options.find(flags::input) == options.end()) {
            throw std::runtime_error("--input <file.pcap> is required in export mode");
        }
        if (options.find(flags::output) == options.end()) {
            throw std::runtime_error("--output <file.22000> is required in export mode");
        }

        app->_infile = options[flags::input];
        app->_outfile = options[flags::output];

    } else if (mode_flag == flags::list) {
        app->_mode = Mode::List;
    } else {
        throw std::runtime_error("Unknown mode: " + mode_flag);
    }

    auto ssid_it = options.find(flags::ssid);
    if (ssid_it == options.end()) {
        if (app->_mode != Mode::List) {
            throw std::runtime_error("--ssid <network_name> is required (hidden networks are not supported)");
        } else {
            app->_target_ssid = std::nullopt;
        }
    } else {
        app->_target_ssid = ssid_it->second;
    }

    return app;
}


void Whiff::run() {

    switch (_mode) {
        case Mode::Capture: {
            _target_bssid = std::nullopt;
            
            _beacon_filter = std::make_unique<BeaconFilter>(_registry, _mutex, _cv, _target_ssid, _target_bssid);
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
                    _abort.store(true); // _target_bssid might not have value yet
                    _cv.notify_one();
                }

                 if (monitor.joinable())
                     monitor.join(); 
            });
            SignalHandler::setup();

            if (!_pkt_handler->capture(_interface.c_str(), _outfile.c_str())) {
                LOG_F(ERROR, "Failed to start packet capture. Exiting.");
                _abort.store(true);
                _cv.notify_one();
                if (monitor.joinable())
                    monitor.join();
                return;
            }

            if (monitor.joinable())
                monitor.join();

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
            HandshakeExtractor extractor(_infile);

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

            Hc22000Exporter::export_to_file(data.value(), *_target_ssid, _outfile);
            LOG_F(INFO, "[*] Exported handshake to %s", _outfile.c_str());
            break;
        }

        case Mode::List: {
            SignalHandler::set_callback([&]() {
                 _pkt_handler->stop();
            });
            SignalHandler::setup();

            std::optional<std::string> empty_ssid;
            std::optional<std::string> empty_bssid;

            _beacon_filter = std::make_unique<BeaconFilter>(_registry, _mutex, _cv, empty_ssid, empty_bssid);
            _pkt_handler  = std::make_unique<PacketHandler>(_beacon_filter.get());

            LOG_F(INFO, "[*] Listening for beacons on interface '%s'...", _interface.c_str());
            LOG_F(INFO, "[*] Press Ctrl+C to stop...");

            if (!_pkt_handler->capture(_interface.c_str(), "")) 
            {
                LOG_F(ERROR, "Failed to start packet capture. Exiting.");
                return;
            }

            LOG_F(INFO, "[*] Access Points:");
            const auto& entries = _registry.get_entries();
            if (entries.empty()) {
                LOG_F(INFO, "No access points found.");
            } else {
                for (const auto& [ssid, bssid] : entries) {
                    LOG_F(INFO, "SSID: %s, BSSID: %s", ssid.c_str(), bssid.c_str());
                }
            }
            break;
        }
    }
}

}