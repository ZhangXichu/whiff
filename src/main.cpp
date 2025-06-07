#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>

struct CaptureContext 
{
    pcap_dumper_t* dumper;
};

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
   auto* ctx = reinterpret_cast<CaptureContext*>(user);

    std::cout << "[*] Packet length: " << header->len << "\n";
    pcap_dump((u_char*)ctx->dumper, header, packet);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }

    const char* dev = argv[1];
    const char* output_file = (argc >= 3) ? argv[2] : "handshakee.pcap";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[-] pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    pcap_dumper_t* dumper = pcap_dump_open(handle, output_file);
    if (!dumper) {
        std::cerr << "[-] pcap_dump_open failed: " << pcap_geterr(handle) << "\n";
        return 1;
    }

    std::cout << "[+] Capturing packets on " << dev << ", saving to: " << output_file << "\n";


    CaptureContext ctx{ dumper };
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&ctx));

    pcap_dump_close(dumper);
    pcap_close(handle);

    return 0;
}