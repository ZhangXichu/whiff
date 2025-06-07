#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>

void packet_handler(u_char* /*user*/, const struct pcap_pkthdr* header, const u_char* /*packet*/) {
    std::time_t ts = header->ts.tv_sec;
    std::tm* tm_info = std::localtime(&ts);
    char buf[26];
    strftime(buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    std::cout << "[*] " << buf << "." << std::setfill('0') << std::setw(6) << header->ts.tv_usec
              << " - Captured packet of length: " << header->len << " bytes\n";
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }

    const char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "[-] pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    std::cout << "[+] Sniffing on interface: " << dev << " (monitor mode)\n";

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);

    return 0;
}