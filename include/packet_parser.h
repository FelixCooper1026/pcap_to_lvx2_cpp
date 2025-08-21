#pragma once
#include <vector>
#include <cstdint>
#include "device_info.h"

struct PacketInfo {
    std::vector<uint8_t> payload;
    uint16_t src_port;
    uint16_t dst_port;
    std::string src_ip;
    std::string dst_ip;
};

class PacketParser {
public:
    static PacketInfo parseRawUdpPacket(const std::vector<uint8_t>& pkt_data);
    static void parseUdpPayload(const std::vector<uint8_t>& payload, DeviceInfo& device_info);
    static uint32_t ipToLidarId(const std::string& ip_str);
    
    // 点云数据解析方法
    static PointCloudDataType detectPointCloudDataType(const std::vector<uint8_t>& payload);
    static std::vector<PointCloudPoint> parsePointCloudData(const std::vector<uint8_t>& payload, PointCloudDataType data_type);
    static std::vector<PointCloudPoint> convertSphericalToCartesian(const std::vector<PointCloudPoint>& spherical_points);
    static std::vector<uint8_t> convertToDataType1(const std::vector<PointCloudPoint>& points);
    static std::vector<uint8_t> convertToDataType2(const std::vector<PointCloudPoint>& points);
};