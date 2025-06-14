#include <iostream>
#include <cstring>
#include <iomanip>

#include <pcap_reader.hpp>

namespace whiff {
    
PcapReader::PcapReader(const std::string& file_path)
    : _file(file_path, std::ios::binary)
{
    if (!_file.is_open()) return;

    _valid = read_global_header();
    if (_valid) {
        _valid = read_all();
    }
}

bool PcapReader::read_global_header() {
    _file.read(reinterpret_cast<char*>(&_global_header), sizeof(PcapGlobalHeader));
    if (_file.gcount() != sizeof(PcapGlobalHeader)) return false;

    std::cout << "[PcapReader] Magic: 0x" << std::hex << _global_header.magic_number << std::dec << "\n";
    std::cout << "[PcapReader] Version: " << _global_header.version_major << "." << _global_header.version_minor << "\n";
    std::cout << "[PcapReader] Snaplen: " << _global_header.snaplen << "\n";
    std::cout << "[PcapReader] Network: " << _global_header.network << "\n";

    return true;
}

bool PcapReader::read_next_packet() {
    PcapPacketHeader header{};
    _file.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (_file.gcount() != sizeof(header)) return false;

    std::vector<uint8_t> data(header.incl_len);
    _file.read(reinterpret_cast<char*>(data.data()), header.incl_len);
    if (_file.gcount() != header.incl_len) return false;

    std::cout << "[PcapReader] Packet: ts=" << header.ts_sec
              << "." << std::setfill('0') << std::setw(6) << header.ts_usec
              << ", len=" << header.incl_len << "\n";

    _packets.push_back({header, std::move(data)});
    return true;
}

bool PcapReader::read_all() {
    while (_file && ! _file.eof()) {
        if (!read_next_packet()) break;
    }
    return true;
}

bool PcapReader::is_valid() const {
    return _valid;
}

const PcapGlobalHeader& PcapReader::global_header() const {
    return _global_header;
}

const std::vector<RawPacket>& PcapReader::packets() const {
    return _packets;
}

}