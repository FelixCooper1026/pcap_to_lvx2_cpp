#pragma once
#include <fstream>
#include <vector>
#include <cstdint>
#include "device_info.h"

class LVX2Writer {
public:
    static bool writeHeaders(std::ofstream& file, const std::vector<DeviceInfo>& device_infos);
    static bool writeFrameHeader(std::ofstream& file, uint64_t current_offset, uint64_t next_offset, uint64_t frame_index);
    static std::vector<uint8_t> createPackageHeader(const std::vector<uint8_t>& raw_udp_payload, uint32_t data_length, const DeviceInfo& device_info);
};