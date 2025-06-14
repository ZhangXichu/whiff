#include <string>
#include <vector>
#include <cstdint>
#include <fstream>

namespace whiff {

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of bytes of packet saved in file
    uint32_t orig_len; // actual length of packet
};

struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};


class PcapReader {

public:
    explicit PcapReader(const std::string& file_path);

    bool is_valid() const;
    const PcapGlobalHeader& global_header() const;
    const std::vector<RawPacket>& packets() const;

    bool read_all(); // Read entire file

private:
    std::ifstream _file;
    PcapGlobalHeader _global_header{};
    std::vector<RawPacket> _packets;
    bool _valid = false;

    bool read_global_header();
    bool read_next_packet();

};

}