cmake_minimum_required(VERSION 3.10)
project(whiff)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

add_executable(whiff 
    src/main.cpp
    src/packet_handler.cpp
    src/signal_handler.cpp
    src/handshake_extractor.cpp
    src/utils.cpp
    src/hc22000_exporter.cpp)
target_include_directories(
    whiff
    PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(whiff ${PCAP_LIBRARIES})