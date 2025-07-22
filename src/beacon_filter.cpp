#include <beacon_filter.hpp>

#include <utils.hpp>
#include <array>

namespace whiff {

BeaconFilter::BeaconFilter(AccessPointRegistry& registry,
                 std::mutex& mutex,
                 std::condition_variable& cv,
                 std::string& target_ssid,
                 std::optional<std::string>& target_bssid)
        : _registry(registry)
        , _mutex(mutex)
        , _cv(cv)
        , _target_ssid(target_ssid)
        , _target_bssid(target_bssid)
    {}

bool BeaconFilter::match(const u_char* packet, uint32_t len) const
{
    constexpr uint8_t BEACON_SUBTYPE = 0x8;      // 1000b
    if (len < 4) return false;                   // need at least radiotap header

    // Skip the radiotap header
    const uint16_t rt_len = le16(packet + 2);    // version (1) + pad (1) + len (2)
    if (rt_len >= len) return false;

    std::cout << "Radiotap header length: " << rt_len << '\n';

    const u_char* hdr   = packet + rt_len;       // start of IEEE-802.11 header
    const uint32_t hlen = len  - rt_len;
    if (hlen < 36) return false;                 // 24-byte mgmt hdr + 12 fixed parms

    std::cout << "IEEE 802.11 header length: " << hlen << '\n';

    // Check type and subtype => Beacon management frame
    const uint16_t fc = le16(hdr);
    const uint8_t stype = subtype(fc);
    std::cout << "802.11 frame subtype: " << static_cast<int>(stype) << '\n';

    if (!is_mgmt(fc) || stype != BEACON_SUBTYPE) return false;

    // Extract BSSID (Addr3 = bytes 16-21 in mgmt header)
    const u_char* bssid_ptr = hdr + 16;
    std::array<uint8_t, 6> mac{};
    std::memcpy(mac.data(), bssid_ptr, 6);
    std::string bssid = utils::mac_to_string(mac);

    std::cout << "BSSID: " << bssid << '\n';

    // Walk tagged parameters to grab SSID (tag ID 0)
    const u_char* tags = hdr + 36;               // 24 hdr + 12 fixed
    const u_char* end  = packet + len;

    int tag_index = 0;

    std::cout << "---- Begin Tagged Parameters ----\n";

    while (tags + 2 <= end) {
        const uint8_t tag_id  = tags[0];
        const uint8_t tag_len = tags[1];
        const u_char* tag_val = tags + 2;

        if (tags + 2 + tag_len > end) {
            std::cout << "Malformed tag at index " << tag_index << " (truncated)\n";
            break;
        }

        std::cout << "Tag " << tag_index++
              << ": ID = " << static_cast<int>(tag_id)
              << ", Len = " << static_cast<int>(tag_len);

        if (tag_id == 0 /*SSID*/) {
            if (tag_len == 0) break;             // hidden SSID, ignore
            const char* ssid_start = reinterpret_cast<const char*>(tags + 2);
            std::string ssid(ssid_start, tag_len);

            std::cout << " [SSID = \"" << ssid << "\"]";

            //  Update the cache (overwrites if a beacon changed channel)
            // _ssid_to_bssid.insert_or_assign(std::move(ssid), bssid);

            _registry.add_entry({ .ssid = ssid, .bssid = bssid });

            {
                std::lock_guard<std::mutex> lock(_mutex);
                if (std::equal(ssid.begin(), ssid.end(), _target_ssid.begin(), _target_ssid.end())) {
                    std::cout << "[BeaconFilter] Target BSSID for " << ssid << " detected, notifying...\n";
                    _target_bssid = bssid;
                    _cv.notify_one();
                }
            }

            break;
        }

        std::cout << ", Value = ";
        for (int i = 0; i < tag_len; ++i)
            std::printf("%02x ", tag_val[i]);
        std::cout << '\n';

        tags += 2 + tag_len;
    }

    std::cout << "\n---- End Tagged Parameters ----\n";

    return true;                                 // still a Beacon even w/o SSID
}


}