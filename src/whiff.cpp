#include <whiff.hpp>

#include <signal_handler.hpp>

namespace whiff {

Whiff Whiff::from_args(int argc, char** argv) {
    if (argc < 2) {
        throw std::runtime_error("Usage:\n"
            "  ./whiff --capture <interface> <output.pcap>\n"
            "  ./whiff --dump <interface> <output.pcap>\n");
    }

    Whiff app;
    std::string flag = argv[1];

    if (flag == "--capture") {
        if (argc < 4) throw std::runtime_error("Missing args for --capture");
        app._mode = Mode::Capture;
        app._interface = argv[2];
        app._outfile = argv[3];

    } 
    else if (flag == "--export") {
        if (argc < 4) throw std::runtime_error("Missing args for --export");
        app._mode = Mode::Export;
        app._interface = argv[2];
        app._outfile = argv[3];
    } else {
        throw std::runtime_error("Unknown mode flag: " + flag);
    }

    return app;
}


void Whiff::run() {

    switch (_mode) {
        case Mode::Capture: {
            
            std::unique_ptr<BeaconFilter> filter = std::make_unique<BeaconFilter>();

            _pkt_handler  = std::make_unique<PacketHandler>(filter.get());

            SignalHandler::set_callback([&]() { _pkt_handler->stop(); });
            SignalHandler::setup();

            _pkt_handler->capture(_interface.c_str(), _outfile.c_str(), 
                [&](const struct pcap_pkthdr* hdr, const u_char* pkt) 
                {
                    if (auto info = filter->parse(pkt, hdr->len)) 
                    {
                        std::cout << "adding entry to registry" << std::endl;
                        _registry.add_entry(*info);
                    }
                }
            );

            std::cout << "[*] Finished capture.\n";
            break;
        }

        case Mode::Export: {
            HandshakeExtractor extractor("/home/xichuz/workspace/whiff/packets/dump5.pcap"); // TODO : set this using cli

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