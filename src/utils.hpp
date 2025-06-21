#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

namespace whiff {
namespace utils {

std::string to_hex(const uint8_t* data, size_t len);

}
}