#include <sstream>
#include <iomanip>
#include <cstring>
#include <array>
#include <utils.hpp>

namespace whiff {
namespace utils {

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    return oss.str();
}

std::array<uint8_t, 6> mac_from_bytes(const uint8_t* p) {
    std::array<uint8_t, 6> mac;
    std::memcpy(mac.data(), p, 6);
    return mac;
}

std::string mac_to_string(const std::array<uint8_t, 6>& mac) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < mac.size(); ++i) {
            oss << std::setw(2) << static_cast<int>(mac[i]);
            if (i != mac.size() - 1)
                oss << ":";
        }
        return oss.str();
    }

}
}