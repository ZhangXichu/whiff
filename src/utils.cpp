#include <sstream>
#include <iomanip>
#include <utils.hpp>

namespace whiff {
namespace utils {

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    return oss.str();
}

}
}