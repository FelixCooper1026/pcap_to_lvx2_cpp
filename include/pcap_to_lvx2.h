#pragma once
#include <string>
#include <vector>
#include <pcap.h>
#include "packet_parser.h"
#include "lvx2_writer.h"

class PCAPToLVX2 {
public:
    PCAPToLVX2(const std::string& input_file, const std::string& output_file);
    bool convert();
    std::string convertPcapngToPcap(const std::string& pcapng_file);
    bool isPcapFile(const std::string& filename);
    bool isPcapngFile(const std::string& filename);

private:
    bool extractDeviceInfo(const std::vector<std::vector<uint8_t>>& packets);
    uint64_t getTimestampFromPayload(const std::vector<uint8_t>& payload);

    std::string input_file_;
    std::string output_file_;
    std::vector<std::vector<uint8_t>> frame_packages_;
    uint32_t frame_index_ = 0;
    uint64_t current_offset_ = 0;
    DeviceInfo device_info_;
    const uint64_t ns_threshold_ = 50000000; // 50ms in nanoseconds
};