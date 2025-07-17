#include <whiff.hpp>

#include <thread>
#include <signal_handler.hpp>

namespace whiff {

std::unique_ptr<Whiff> Whiff::from_args(int argc, char** argv) {
    if (argc < 2) {
        throw std::runtime_error("Usage:\n"
            "  ./whiff --capture <interface> <output.pcap>\n"
            "  ./whiff --export <interface> <output.pcap>\n");
    }

    auto app = std::make_unique<Whiff>();
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
            std::optional<std::string> target_bssid;
            
            _beacon_filter = std::make_unique<BeaconFilter>();

            _pkt_handler  = std::make_unique<PacketHandler>(_beacon_filter.get());

            std::thread monitor([&]() {
                std::unique_lock<std::mutex> lock(_mutex);
                _cv.wait(lock, [&]() { 
                    std::cout << "target_bssid gets value!" << std::endl;
                    return target_bssid.has_value(); 
                });
                _pkt_handler->stop();
            });

            SignalHandler::set_callback([&]() {
                 _pkt_handler->stop();

                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    target_bssid = std::nullopt; 
                    _cv.notify_one();
                }

                 if (monitor.joinable())
                     monitor.join(); 
            });
            SignalHandler::setup();

            _pkt_handler->capture(_interface.c_str(), _outfile.c_str(), 
                [&](const struct pcap_pkthdr* hdr, const u_char* pkt) 
                {
                    if (auto info = _beacon_filter->parse(pkt, hdr->len)) 
                    {
                        std::cout << "adding entry to registry" << std::endl;
                        _registry.add_entry(*info);

                        if (info->ssid == target_ssid) {
                            std::cout << "AP " << target_ssid << " detected" << std::endl;

                            target_bssid = info->bssid;
                            _cv.notify_one();
                        }
                    }
                }
            );

            if (monitor.joinable())
                monitor.join();

            _pkt_handler.reset();  

            if (target_bssid) {
                std::cout << "[*] Starting EAPOL capture for BSSID: " << *target_bssid << "\n";

                _eapol_filter = std::make_unique<EapolFilter>(*target_bssid);
                _pkt_handler = std::make_unique<PacketHandler>(_eapol_filter.get());

                _pkt_handler->capture(_interface.c_str(), _outfile.c_str(),
                    [&](const struct pcap_pkthdr* hdr, const u_char* pkt) {
                        if (_eapol_filter->match(pkt, hdr->len)) {
                            std::cout << "[*] EAPOL packet matched\n";
                        }
                    });

                std::cout << "[*] Finished EAPOL capture.\n";
            } else {
                std::cerr << "[-] No target SSID detected. EAPOL capture skipped.\n";
            }

            std::cout << "[*] Finished capture.\n";
            break;
        }

        case Mode::Export: {
            HandshakeExtractor extractor("/home/xichuz/workspace/whiff/eapol.pcap"); // TODO : set this using cli

            if (extractor.extract_handshake()) {
                std::cout << "[*] EAPOL handshake(s) found: "
                          << extractor.get_eapol_packets().size() << "\n";
            } else {
                std::cout << "[-] No EAPOL packets found.\n";
                return;
            }

            for (const auto& pkt : extractor.get_eapol_packets()) {
                extractor.parse_packet(pkt);
            }

            auto data = extractor.prepare_handshake_info();
            if (!data.has_value()) {
                std::cout << "[-] Could not prepare handshake data.\n";
                return;
            }

            Hc22000Exporter::export_to_file(data.value(), /*ssid=*/"", _outfile);
            std::cout << "[+] Exported handshake to " << _outfile << "\n";
            break;
        }
    }
}

}