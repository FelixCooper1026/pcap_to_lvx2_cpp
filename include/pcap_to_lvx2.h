#pragma once
#include <string>
#include <deque>
#include <vector>
#include <cstdint>
#include "device_info.h"

class PCAPToLVX2 {
public:
    PCAPToLVX2(const std::string& pcap_file, const std::string& output_file);
    bool convert();

private:
    std::string pcap_file_;
    std::string output_file_;
    DeviceInfo device_info_;
    uint64_t frame_index_;
    uint64_t current_offset_;
    std::deque<std::vector<uint8_t>> frame_packages_;
    const uint64_t ns_threshold_ = 50'000'000; // 50ms
    bool extractDeviceInfo(const std::vector<std::vector<uint8_t>>& all_raw_packets);
    uint64_t getTimestampFromPayload(const std::vector<uint8_t>& payload);
};