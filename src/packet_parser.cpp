#include "packet_parser.h"
#include <cstring>
#include <cmath>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

PacketInfo PacketParser::parseRawUdpPacket(const std::vector<uint8_t>& pkt_data) {
    PacketInfo info;
    info.src_port = 0;
    info.dst_port = 0;
    info.payload.clear();

    if (pkt_data.size() < 14) return info;
    uint16_t eth_type = (pkt_data[12] << 8) | pkt_data[13];
    if (eth_type != 0x0800) return info;

    uint8_t ip_header_len = (pkt_data[14] & 0x0F) * 4;
    if (pkt_data.size() < 14 + ip_header_len) return info;
    if (pkt_data[23] != 17) return info; // UDP

    uint16_t udp_header_start = 14 + ip_header_len;
    if (pkt_data.size() < udp_header_start + 8) return info;

    info.src_port = (pkt_data[udp_header_start] << 8) | pkt_data[udp_header_start + 1];
    info.dst_port = (pkt_data[udp_header_start + 2] << 8) | pkt_data[udp_header_start + 3];
    info.payload = std::vector<uint8_t>(pkt_data.begin() + udp_header_start + 8, pkt_data.end());

    info.src_ip = std::to_string(pkt_data[26]) + "." + std::to_string(pkt_data[27]) + "." +
                  std::to_string(pkt_data[28]) + "." + std::to_string(pkt_data[29]);
    info.dst_ip = std::to_string(pkt_data[30]) + "." + std::to_string(pkt_data[31]) + "." +
                  std::to_string(pkt_data[32]) + "." + std::to_string(pkt_data[33]);

    return info;
}

void PacketParser::parseUdpPayload(const std::vector<uint8_t>& payload, DeviceInfo& device_info) {
    size_t index = 28;
    while (index + 4 <= payload.size()) {
        uint16_t key = payload[index] | (payload[index + 1] << 8);
        index += 2;
        uint16_t length = payload[index] | (payload[index + 1] << 8);
        index += 2;
        if (index + length > payload.size()) break;

        if (key == 0x8000) { // SN
            device_info.lidar_sn = std::string(payload.begin() + index, payload.begin() + index + length);
            size_t null_pos = device_info.lidar_sn.find('\0');
            if (null_pos != std::string::npos) {
                device_info.lidar_sn.erase(null_pos);
            }
        } else if (key == 0x0004 && length >= 4) { // lidar_ipcfg
            std::string ip = std::to_string(payload[index]) + "." +
                             std::to_string(payload[index + 1]) + "." +
                             std::to_string(payload[index + 2]) + "." +
                             std::to_string(payload[index + 3]);
            device_info.lidar_id = ipToLidarId(ip);
        } else if (key == 0x0012 && length >= 24) { // install_attitude
            float roll, pitch, yaw;
            int32_t x, y, z;
            memcpy(&roll, &payload[index], 4);
            memcpy(&pitch, &payload[index + 4], 4);
            memcpy(&yaw, &payload[index + 8], 4);
            memcpy(&x, &payload[index + 12], 4);
            memcpy(&y, &payload[index + 16], 4);
            memcpy(&z, &payload[index + 20], 4);
            device_info.enable_extrinsic = true;
            device_info.offset_roll = roll;
            device_info.offset_pitch = pitch;
            device_info.offset_yaw = yaw;
            device_info.offset_x = x / 1000.0f;
            device_info.offset_y = y / 1000.0f;
            device_info.offset_z = z / 1000.0f;
        }
        index += length;
    }
}

uint32_t PacketParser::ipToLidarId(const std::string& ip_str) {
#ifdef _WIN32
    unsigned long addr = inet_addr(ip_str.c_str());
    return ntohl(addr);
#else
    struct in_addr addr;
    inet_pton(AF_INET, ip_str.c_str(), &addr);
    return ntohl(addr.s_addr);
#endif
}

PointCloudDataType PacketParser::detectPointCloudDataType(const std::vector<uint8_t>& payload) {
    if (payload.size() < 36) return PointCloudDataType::CARTESIAN_32BIT; // 默认类型
    
    // 从payload[10]获取数据类型
    uint8_t data_type = payload[10];
    
    switch (data_type) {
        case 1:
            return PointCloudDataType::CARTESIAN_32BIT;
        case 2:
            return PointCloudDataType::CARTESIAN_16BIT;
        case 3:
            return PointCloudDataType::SPHERICAL;
        default:
            return PointCloudDataType::CARTESIAN_32BIT; // 默认类型
    }
}

std::vector<PointCloudPoint> PacketParser::parsePointCloudData(const std::vector<uint8_t>& payload, PointCloudDataType data_type) {
    std::vector<PointCloudPoint> points;
    
    if (payload.size() < 36) return points;
    
    // 跳过36字节的头部
    size_t data_start = 36;
    size_t data_size = payload.size() - data_start;
    
    switch (data_type) {
        case PointCloudDataType::CARTESIAN_32BIT: {
            // 数据类型1：14字节/点
            size_t point_size = 14;
            size_t point_count = data_size / point_size;
            
            for (size_t i = 0; i < point_count; ++i) {
                size_t offset = data_start + i * point_size;
                if (offset + point_size > payload.size()) break;
                
                PointCloudPoint point;
                int32_t x, y, z;
                
                memcpy(&x, &payload[offset], 4);
                memcpy(&y, &payload[offset + 4], 4);
                memcpy(&z, &payload[offset + 8], 4);
                
                point.x = static_cast<float>(x);      // 单位：mm
                point.y = static_cast<float>(y);
                point.z = static_cast<float>(z);
                point.reflectivity = payload[offset + 12];
                point.tag = payload[offset + 13];
                
                points.push_back(point);
            }
            break;
        }
        
        case PointCloudDataType::CARTESIAN_16BIT: {
            // 数据类型2：8字节/点
            size_t point_size = 8;
            size_t point_count = data_size / point_size;
            
            for (size_t i = 0; i < point_count; ++i) {
                size_t offset = data_start + i * point_size;
                if (offset + point_size > payload.size()) break;
                
                PointCloudPoint point;
                int16_t x, y, z;
                
                memcpy(&x, &payload[offset], 2);
                memcpy(&y, &payload[offset + 2], 2);
                memcpy(&z, &payload[offset + 4], 2);
                
                point.x = static_cast<float>(x) * 10.0f;  // 单位：10mm -> mm
                point.y = static_cast<float>(y) * 10.0f;
                point.z = static_cast<float>(z) * 10.0f;
                point.reflectivity = payload[offset + 6];
                point.tag = payload[offset + 7];
                
                points.push_back(point);
            }
            break;
        }
        
        case PointCloudDataType::SPHERICAL: {
            // 数据类型3：10字节/点
            size_t point_size = 10;
            size_t point_count = data_size / point_size;
            
            for (size_t i = 0; i < point_count; ++i) {
                size_t offset = data_start + i * point_size;
                if (offset + point_size > payload.size()) break;
                
                PointCloudPoint point;
                uint32_t depth;
                uint16_t zenith_angle, azimuth_angle;
                
                memcpy(&depth, &payload[offset], 4);
                memcpy(&zenith_angle, &payload[offset + 4], 2);
                memcpy(&azimuth_angle, &payload[offset + 6], 2);
                
                point.depth = static_cast<float>(depth);                    // 单位：mm
                point.zenith_angle = static_cast<float>(zenith_angle) / 100.0f;    // 单位：0.01° -> °
                point.azimuth_angle = static_cast<float>(azimuth_angle) / 100.0f;  // 单位：0.01° -> °
                point.reflectivity = payload[offset + 8];
                point.tag = payload[offset + 9];
                
                points.push_back(point);
            }
            break;
        }
    }
    
    return points;
}

std::vector<PointCloudPoint> PacketParser::convertSphericalToCartesian(const std::vector<PointCloudPoint>& spherical_points) {
    std::vector<PointCloudPoint> cartesian_points;
    
    for (const auto& sp : spherical_points) {
        PointCloudPoint cp;
        
        // 球坐标转直角坐标
        // x = depth * sin(zenith_angle) * cos(azimuth_angle)
        // y = depth * sin(zenith_angle) * sin(azimuth_angle)
        // z = depth * cos(zenith_angle)
        
        const float PI = 3.14159265359f;
        float zenith_rad = sp.zenith_angle * PI / 180.0f;      // 度转弧度
        float azimuth_rad = sp.azimuth_angle * PI / 180.0f;    // 度转弧度
        
        cp.x = sp.depth * sin(zenith_rad) * cos(azimuth_rad);
        cp.y = sp.depth * sin(zenith_rad) * sin(azimuth_rad);
        cp.z = sp.depth * cos(zenith_rad);
        cp.reflectivity = sp.reflectivity;
        cp.tag = sp.tag;
        
        cartesian_points.push_back(cp);
    }
    
    return cartesian_points;
}

std::vector<uint8_t> PacketParser::convertToDataType1(const std::vector<PointCloudPoint>& points) {
    std::vector<uint8_t> data;
    
    for (const auto& point : points) {
        // 数据类型1：14字节/点
        int32_t x = static_cast<int32_t>(point.x);      // 单位：mm
        int32_t y = static_cast<int32_t>(point.y);
        int32_t z = static_cast<int32_t>(point.z);
        
        data.resize(data.size() + 14);
        size_t offset = data.size() - 14;
        
        memcpy(&data[offset], &x, 4);
        memcpy(&data[offset + 4], &y, 4);
        memcpy(&data[offset + 8], &z, 4);
        data[offset + 12] = point.reflectivity;
        data[offset + 13] = point.tag;
    }
    
    return data;
}

std::vector<uint8_t> PacketParser::convertToDataType2(const std::vector<PointCloudPoint>& points) {
    std::vector<uint8_t> data;
    
    for (const auto& point : points) {
        // 数据类型2：8字节/点
        int16_t x = static_cast<int16_t>(point.x / 10.0f);      // 单位：mm -> 10mm
        int16_t y = static_cast<int16_t>(point.y / 10.0f);
        int16_t z = static_cast<int16_t>(point.z / 10.0f);
        
        data.resize(data.size() + 8);
        size_t offset = data.size() - 8;
        
        memcpy(&data[offset], &x, 2);
        memcpy(&data[offset + 2], &y, 2);
        memcpy(&data[offset + 4], &z, 2);
        data[offset + 6] = point.reflectivity;
        data[offset + 7] = point.tag;
    }
    
    return data;
}