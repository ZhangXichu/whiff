#include <handshake_extractor.hpp>

#include <iostream>
#include <cstring>
#include <sstream>
#include  <iomanip>
#include <algorithm>
#include  <unordered_map>
#include <loguru.hpp>
#include <packet_filter.hpp>

namespace whiff {

HandshakeExtractor::HandshakeExtractor(const std::string& pcap_file)
    : _pcap_file(pcap_file) {}

HandshakeExtractor::~HandshakeExtractor() {}

bool HandshakeExtractor::extract_handshake() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(_pcap_file.c_str(), errbuf);
    if (!handle) 
    {
        LOG_F(ERROR, "Failed to open pcap: %s", errbuf);
        return false;
    }

    const u_char* packet;
    struct pcap_pkthdr* header;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;  // Timeout

        EapolPacket pkt;
        pkt.timestamp = header->ts;
        pkt.raw_data.assign(packet, packet + header->caplen);
        _eapol_packets.push_back(std::move(pkt));

        LOG_F(INFO, "[+] EAPOL packet found, len=%d", header->caplen);
    }

    pcap_close(handle);
    return !_eapol_packets.empty();
}

const std::vector<EapolPacket>& HandshakeExtractor::get_eapol_packets() const {
    return _eapol_packets;
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

    bool to_ds   = fc & 0x0100;
    bool from_ds = fc & 0x0200;

    // Pointer positions
    const uint8_t* addr1 = payload + 4;
    const uint8_t* addr2 = payload + 10;
    const uint8_t* addr3 = payload + 16;

    if (!to_ds && !from_ds) {
        // Ad-hoc or STA↔STA in infrastructure
        LOG_F(1, "Ad-hoc or STA <-> STA in infrastructure");
        result.dst_mac = utils::mac_from_bytes(addr1);  // Destination
        result.src_mac = utils::mac_from_bytes(addr2);  // Source STA
        result.bssid   = utils::mac_from_bytes(addr3);  // BSSID
        LOG_F(1, "BSSID: %s ", utils::mac_to_string(result.bssid).c_str());
    } else if (to_ds && !from_ds) {
        // STA → AP
        LOG_F(1, "STA <-> AP");
        result.bssid   = utils::mac_from_bytes(addr1);  // BSSID (AP)
        result.src_mac = utils::mac_from_bytes(addr2);  // Source STA
        result.dst_mac = utils::mac_from_bytes(addr3);  // Destination
        LOG_F(1, "BSSID: %s ", utils::mac_to_string(result.bssid).c_str());
    } else if (!to_ds && from_ds) {
        // AP → STA
        LOG_F(1, "AP <-> STA");
        result.dst_mac = utils::mac_from_bytes(addr1);  // Destination STA
        result.bssid   = utils::mac_from_bytes(addr2);  // BSSID (AP)
        result.src_mac = utils::mac_from_bytes(addr3);  // Source STA
        LOG_F(1, "BSSID: %s ", utils::mac_to_string(result.bssid).c_str());
    } else if (to_ds && from_ds) {
        // WDS or mesh network — we do not support
        LOG_F(ERROR, "Unsupported 4-address WDS frame");
        return result;
    }

    const uint8_t* llc = payload + hdr_len;
    if (llc + 8 > packet + len || llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) 
    {
        LOG_F(ERROR, "LLC/SNAP header missing or malformed");
        return result;
    }

    uint16_t ethertype = (llc[6] << 8) | llc[7];
    if (ethertype != 0x888E) {
        LOG_F(ERROR, "Not an EAPOL packet (Ethertype: 0x%04X)", ethertype);
        return result;
    }

    const uint8_t* eapol = llc + 8;
    if (eapol + 4 > packet + len) 
    {
        LOG_F(ERROR, "Truncated EAPOL header");
        return result;
    }

    uint8_t version = eapol[0];
    uint8_t type = eapol[1];
    uint16_t body_len = (eapol[2] << 8) | eapol[3];

    if (type != 3) {  // Only parse EAPOL-Key
        LOG_F(ERROR, "Not an EAPOL-Key packet (type= %d)", type);
        return result;
    }

    size_t eapol_total_len = 4 + body_len;
    const uint8_t* eapol_start = eapol;

    if (eapol_start + eapol_total_len > packet + len) 
    {
        LOG_F(ERROR, "EAPOL payload length exceeds packet size");
        return result;
    }

    result.eapol_payload.assign(eapol_start, eapol_start + eapol_total_len);

    result.eapol_payload_zeroed = result.eapol_payload;
    if (result.eapol_payload_zeroed.size() >= 97) {  // remove magic number
        std::fill(result.eapol_payload_zeroed.begin() + 81,
                result.eapol_payload_zeroed.begin() + 97, 0x00);
    } else {
        LOG_F(ERROR, "EAPOL payload too short to zero MIC");
    }

    const uint8_t* eapol_key = eapol + 4;
    size_t remaining = packet + len - eapol_key;

    if (remaining < 96) 
    {
        LOG_F(ERROR, "Truncated EAPOL-Key body");
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
        LOG_F(ERROR, "[-] Invalid Key Data length: exceeds packet bounds (%zu vs %zu)",
       static_cast<size_t>(desc.key_data_length),
       static_cast<size_t>(packet + len - key_data_start));
        desc.key_data.clear();
    }

    result.has_mic = ((desc.key_info >> 8) & 0x01);
    result.is_from_ap = (payload[1] & 0x01) == 0;

    LOG_F(1, "[*] Descriptor Type: %d", static_cast<int>(desc.descriptor_type));
    LOG_F(1, "[*] Key Info: 0x%04x", desc.key_info);
    LOG_F(1, "[*] Key Length: %u", desc.key_length);
    LOG_F(1, "[*] Key Data Length: %u", desc.key_data_length);
    LOG_F(1, "[*] Has MIC: %s", result.has_mic ? "true" : "false");
    LOG_F(1, "[*] Is From AP: %s", result.is_from_ap ? "true" : "false");
    LOG_F(1, "[*] Replay Counter: %s",
        utils::to_hex(desc.replay_counter.data(), desc.replay_counter.size()).c_str());
    LOG_F(1, "[*] Nonce: %s",
        utils::to_hex(desc.nonce.data(), desc.nonce.size()).c_str());
    LOG_F(1, "[*] EAPOL Payload (len=%zu): %s...",
        result.eapol_payload.size(),
        utils::to_hex(result.eapol_payload.data(),
                        std::min<size_t>(result.eapol_payload.size(), 64)).c_str());
    LOG_F(1, "[*] EAPOL (zeroed MIC): %s...",
        utils::to_hex(result.eapol_payload_zeroed.data(),
                        std::min<size_t>(result.eapol_payload_zeroed.size(), 64)).c_str());

    return result;
}


std::optional<HandshakeData> HandshakeExtractor::prepare_handshake_info() {

    auto is_zero_nonce = [](const std::array<uint8_t, 32>& nonce) {
        return std::all_of(nonce.begin(), nonce.end(), [](uint8_t b) { return b == 0; });
    };

    auto print_handshake = [](const HandshakeData& hs) {
        LOG_F(2, "        [+] Extracted handshake fields:");
        LOG_F(2, "            - AP MAC:      %s", utils::to_hex(hs.ap_mac.data(), 6).c_str());
        LOG_F(2, "            - Client MAC:  %s", utils::to_hex(hs.client_mac.data(), 6).c_str());
        LOG_F(2, "            - ANonce:      %s", utils::to_hex(hs.anonce.data(), 32).c_str());
        LOG_F(2, "            - SNonce:      %s", utils::to_hex(hs.snonce.data(), 32).c_str());
        LOG_F(2, "            - MIC:         %s", utils::to_hex(hs.mic.data(), 16).c_str());
        LOG_F(2, "            - EAPOL frame: %s...",
            utils::to_hex(hs.eapol_frame.data(),
                            std::min<size_t>(hs.eapol_frame.size(), 64)).c_str());
    };

    std::optional<HandshakeData> best_handshake;

    std::unordered_map<ReplayCounter, HandshakeBins> bins;

    for (const auto& pkt : _eapol_packets) {
        Eapol msg = parse_packet(pkt);
        const auto& d = msg.key_descriptor;
        ReplayCounter rc = utils::to_uint64_be(d.replay_counter);

        if (msg.is_from_ap &&
            !msg.has_mic &&
            !is_zero_nonce(msg.key_descriptor.nonce)) {
            bins[rc].m1s.push_back(msg);
        }else if (!msg.is_from_ap && !is_zero_nonce(d.nonce)) {
            // M2: from STA, has MIC, non-zero SNonce
            bins[rc].m2s.push_back(msg);
        } else if (msg.is_from_ap && !is_zero_nonce(d.nonce)) {
            // M3: from AP, has MIC, ANonce must be present
            bins[rc].m3s.push_back(msg);
        } else if (!msg.is_from_ap && is_zero_nonce(d.nonce)) {
            // M4: from STA, MIC with zeroed nonce
            bins[rc].m4s.push_back(msg);
        }
    }

    // Optional: print stats
    for (const auto& [rc, bin] : bins) {
        LOG_F(2, "[*] RC %zu: %zu M1, %zu M2, %zu M3, %zu M4",
        rc,
        bin.m1s.size(),
        bin.m2s.size(),
        bin.m3s.size(),
        bin.m4s.size());

        // Preferred: M2 + M3
        for (const auto& m2 : bin.m2s) {
            for (const auto& m3 : bin.m3s) {
                if (m2.src_mac != m3.dst_mac) continue;

                HandshakeData hs;
                hs.ap_mac = m3.src_mac;
                hs.client_mac = m2.src_mac;
                hs.anonce = m3.key_descriptor.nonce;
                hs.snonce = m2.key_descriptor.nonce;
                hs.mic = m2.key_descriptor.mic;
                hs.eapol_frame = m2.eapol_payload_zeroed;
                hs.message_pair = 0x02;

                LOG_F(INFO, "Valid M2 + M3 handshake found");
                return hs;
            }
        }

        // Fallback: M1 + M2
        for (const auto& m1 : bin.m1s) {
            for (const auto& m2 : bin.m2s) {
                if (m2.src_mac != m1.dst_mac) continue;

                HandshakeData hs;
                hs.ap_mac = m1.src_mac;
                hs.client_mac = m2.src_mac;
                hs.anonce = m1.key_descriptor.nonce;
                hs.snonce = m2.key_descriptor.nonce;
                hs.mic = m2.key_descriptor.mic;
                hs.eapol_frame = m2.eapol_payload_zeroed;
                hs.message_pair = 0x00;

                LOG_F(INFO, "Valid M1 + M2 handshake found");
                return hs;
            }
        }
    }

    if (best_handshake.has_value()) {
        LOG_F(INFO, "Handshake info prepared (message_pair = 0x%02X)",
            static_cast<int>(best_handshake->message_pair));

        print_handshake(*best_handshake);
    } else {
        LOG_F(ERROR, "No valid handshake info found.");
    }


    return best_handshake;
}

}