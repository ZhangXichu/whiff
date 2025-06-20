#include <handshake_extractor.hpp>

#include <iostream>
#include <cstring>
#include <sstream>
#include  <iomanip>

namespace whiff {

HandshakeExtractor::HandshakeExtractor(const std::string& pcap_file)
    : _pcap_file(pcap_file) {}

HandshakeExtractor::~HandshakeExtractor() {}

bool HandshakeExtractor::extract_handshake() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(_pcap_file.c_str(), errbuf);
    if (!handle) {
        std::cerr << "[-] Failed to open pcap: " << errbuf << "\n";
        return false;
    }

    const u_char* packet;
    struct pcap_pkthdr* header;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;  // Timeout

        if (is_eapol_packet(packet, header->caplen)) {
            EapolPacket pkt;
            pkt.timestamp = header->ts;
            pkt.raw_data.assign(packet, packet + header->caplen);
            _eapol_packets.push_back(std::move(pkt));

            std::cout << "[+] EAPOL packet found, len=" << header->caplen << "\n";
        }
    }

    pcap_close(handle);
    return !_eapol_packets.empty();
}

const std::vector<EapolPacket>& HandshakeExtractor::get_eapol_packets() const {
    return _eapol_packets;
}

// looks for Ethertype 0x888e
bool HandshakeExtractor::is_eapol_packet(const u_char* packet, uint32_t len) {
    if (len < 36) return false;

    // Radiotap header length
    uint16_t radiotap_len = packet[2] | (packet[3] << 8);
    if (len <= radiotap_len + 24) return false;

    const u_char* payload = packet + radiotap_len;

    // Frame control field (first 2 bytes)
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xf;

    // Only handle Data frames
    if (type != 2) return false;

    // Check if Address4 is present (ToDS + FromDS both set)
    bool has_addr4 = (fc & 0x0300) == 0x0300;
    size_t hdr_len = 24 + (has_addr4 ? 6 : 0);

    // Add QoS control field if needed
    if (subtype & 0x08) {
        hdr_len += 2;
    }

    // Add HT control field if present (not handled here yet)
    if (len <= radiotap_len + hdr_len + 8) return false;

    const u_char* llc = payload + hdr_len;

    // Check for LLC/SNAP
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
        uint16_t ethertype = (llc[6] << 8) | llc[7];

        std::cout << "[debug] Packet len=" << len
          << ", radiotap=" << radiotap_len
          << ", 802.11 hdr=" << hdr_len
          << ", llc[0-2]=" << std::hex << (int)llc[0] << " " << (int)llc[1] << " " << (int)llc[2]
          << ", ethertype=" << std::hex << ethertype << "\n";

        return ethertype == 0x888E;
    }

    return false;
}

Eapol HandshakeExtractor::parse_packet(const EapolPacket& pkt)
{
    Eapol result;
    result.timestamp = pkt.timestamp;
    result.raw_frame = pkt.raw_data;

    const uint8_t* packet = pkt.raw_data.data();
    const uint32_t len = pkt.raw_data.size();

    if (len < 36) {
        std::cerr << "[-] Packet too short\n";
        return result;
    }

    // Radiotap header length
    uint16_t radiotap_len = packet[2] | (packet[3] << 8);
    if (radiotap_len >= len) {
        std::cerr << "[-] Radiotap length exceeds packet length\n";
        return result;
    }

    const uint8_t* payload = packet + radiotap_len;
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t subtype = (fc >> 4) & 0xf;
    bool has_addr4 = (fc & 0x0300) == 0x0300;
    size_t hdr_len = 24 + (has_addr4 ? 6 : 0);
    if (subtype & 0x08) hdr_len += 2;  // QoS

    if (radiotap_len + hdr_len + 8 > len) {
        std::cerr << "[-] Not enough space for LLC/SNAP\n";
        return result;
    }

    std::memcpy(result.dst_mac.data(), payload + 4, 6);
    std::memcpy(result.src_mac.data(), payload + 10, 6);

    const uint8_t* llc = payload + hdr_len;
    if (llc + 8 > packet + len || llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) {
        std::cerr << "[-] LLC/SNAP header missing or malformed\n";
        return result;
    }

    uint16_t ethertype = (llc[6] << 8) | llc[7];
    if (ethertype != 0x888E) {
        std::cerr << "[-] Not an EAPOL packet\n";
        return result;
    }

    const uint8_t* eapol = llc + 8;
    if (eapol + 4 > packet + len) {
        std::cerr << "[-] Truncated EAPOL header\n";
        return result;
    }

    uint8_t version = eapol[0];
    uint8_t type = eapol[1];
    uint16_t body_len = (eapol[2] << 8) | eapol[3];

    if (type != 3) {  // Only parse EAPOL-Key
        std::cerr << "[-] Not an EAPOL-Key packet (type=" << (int)type << ")\n";
        return result;
    }

    const uint8_t* eapol_key = eapol + 4;
    size_t remaining = packet + len - eapol_key;

    if (remaining < 96) {
        std::cerr << "[-] Truncated EAPOL-Key body\n";
        return result;
    }

    auto& desc = result.key_descriptor;
    desc.descriptor_type = eapol_key[0];
    desc.key_info = (eapol_key[1] << 8) | eapol_key[2];
    desc.key_length = (eapol_key[3] << 8) | eapol_key[4];

    std::memcpy(desc.replay_counter.data(), eapol_key + 5, 8);
    std::memcpy(desc.nonce.data(),         eapol_key + 13, 32);
    std::memcpy(desc.key_iv.data(),        eapol_key + 45, 16);
    std::memcpy(desc.key_rsc.data(),       eapol_key + 61, 8);
    std::memcpy(desc.mic.data(),           eapol_key + 77, 16);

    desc.key_data_length = (eapol_key[93] << 8) | eapol_key[94];

    const uint8_t* key_data_start = eapol_key + 95;
    if (key_data_start + desc.key_data_length <= packet + len) {
        desc.key_data.assign(key_data_start, key_data_start + desc.key_data_length);
    } else {
        std::cerr << "[-] Invalid Key Data length: exceeds packet bounds ("
                  << desc.key_data_length << " vs " << (packet + len - key_data_start) << ")\n";
        desc.key_data.clear();
    }

    result.has_mic = ((desc.key_info >> 8) & 0x01);
    result.is_from_ap = (payload[1] & 0x01) == 0;

    std::cout << "[*] Descriptor Type: " << std::dec << (int)desc.descriptor_type << "\n";
    std::cout << "[*] Key Info: 0x" << std::hex << desc.key_info << "\n";
    std::cout << "[*] Key Length: " << std::dec << desc.key_length << "\n";
    std::cout << "[*] Key Data Length: " << desc.key_data_length << "\n";
    std::cout << "[*] Has MIC: " << std::boolalpha << result.has_mic << "\n";
    std::cout << "[*] Is From AP: " << result.is_from_ap << "\n";

    return result;
}


std::optional<HandshakeData> HandshakeExtractor::prepare_handshake_info() {
    for (size_t i = 0; i + 1 < _eapol_packets.size(); ++i) {
        const auto& pkt1 = _eapol_packets[i];
        const auto& pkt2 = _eapol_packets[i + 1];

        Eapol h1 = parse_packet(pkt1);
        Eapol h2 = parse_packet(pkt2);

        std::cout << "        - h1: from_ap=" << std::boolalpha << h1.is_from_ap
                  << ", has_mic=" << h1.has_mic << "\n";
        std::cout << "        - h2: from_ap=" << std::boolalpha << h2.is_from_ap
                  << ", has_mic=" << h2.has_mic << "\n";

        if (!h1.is_from_ap || h2.is_from_ap) {
            std::cout << "        [-] Invalid direction (expect AP→Client then Client→AP)\n";
            continue;
        }

        // Match AP -> Client (msg1) then Client -> AP (msg2)
        if (!h1.is_from_ap || h2.is_from_ap)
            continue;

        // Both must have key descriptor
        const auto& d1 = h1.key_descriptor;
        const auto& d2 = h2.key_descriptor;

        if (!h2.has_mic) {
            std::cout << "        [-] h2 is missing MIC\n";
            continue;
        }

        if (d1.replay_counter != d2.replay_counter) {
            std::cout << "        [-] Replay counters do not match\n";
            continue;
        }

        std::cout << "        [+] Valid pair found!\n";

        // Check for valid MIC + matching replay counter
        if (!h2.has_mic) continue;
        if (d1.replay_counter != d2.replay_counter) continue;

        HandshakeData result;
        result.ap_mac = h1.src_mac;
        result.client_mac = h2.src_mac;
        result.anonce = d1.nonce;
        result.snonce = d2.nonce;
        result.mic = d2.mic;
        result.eapol_frame = h2.raw_frame;

        std::cout << "        [+] Extracted handshake fields:\n";
        std::cout << "            - AP MAC:      " << utils::to_hex(result.ap_mac.data(), 6) << "\n";
        std::cout << "            - Client MAC:  " << utils::to_hex(result.client_mac.data(), 6) << "\n";
        std::cout << "            - ANonce:      " << utils::to_hex(result.anonce.data(), 32) << "\n";
        std::cout << "            - SNonce:      " << utils::to_hex(result.snonce.data(), 32) << "\n";
        std::cout << "            - MIC:         " << utils::to_hex(result.mic.data(), 16) << "\n";
        std::cout << "            - EAPOL frame: " << utils::to_hex(result.eapol_frame.data(), std::min<size_t>(result.eapol_frame.size(), 64)) << "...\n";

        // TODO: if SSID is not in EAPOL frames, set manually
        // result.ssid = input_ssid;

        std::cout << "        [+] Handshake info prepared.\n";

        return result;
    }

    std::cout << "[-] No valid handshake info found.\n";

    return std::nullopt;
}
}