#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

namespace whiff {
namespace utils {

std::string to_hex(const uint8_t* data, size_t len);
std::array<uint8_t, 6> mac_from_bytes(const uint8_t* p);
std::string mac_to_string(const std::array<uint8_t, 6>& mac);

}
}