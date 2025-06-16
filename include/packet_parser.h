#pragma once
#include <vector>
#include <cstdint>
#include "device_info.h"

struct PacketInfo {
    std::vector<uint8_t> payload;
    uint16_t src_port;
    uint16_t dst_port;
};

class PacketParser {
public:
    static PacketInfo parseRawUdpPacket(const std::vector<uint8_t>& pkt_data);
    static void parseUdpPayload(const std::vector<uint8_t>& payload, DeviceInfo& device_info);
    static uint32_t ipToLidarId(const std::string& ip_str);
};