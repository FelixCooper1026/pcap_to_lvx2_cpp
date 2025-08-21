#include "lvx2_writer.h"
#include "packet_parser.h"
#include <cstring>

bool LVX2Writer::writeHeaders(std::ofstream& file, const std::vector<DeviceInfo>& device_infos) {
    // 公共头
    char signature[16] = "livox_tech";
    file.write(signature, 16);
    uint8_t version[4] = {2, 0, 0, 0};
    file.write(reinterpret_cast<char*>(version), 4);
    uint32_t magic_code = 0xAC0EA767;
    file.write(reinterpret_cast<char*>(&magic_code), 4);

    // 私有头
    uint32_t duration = 50;
    file.write(reinterpret_cast<char*>(&duration), 4);
    uint8_t device_count = static_cast<uint8_t>(device_infos.size());
    file.write(reinterpret_cast<char*>(&device_count), 1);

    // 设备信息
    for (const auto& device_info : device_infos) {
        std::string lidar_sn = device_info.lidar_sn;
        lidar_sn.resize(16, '\0');
        file.write(lidar_sn.c_str(), 16);
        std::string hub_sn = device_info.hub_sn;
        hub_sn.resize(16, '\0');
        file.write(hub_sn.c_str(), 16);
        uint32_t lidar_id_le = 
            ((device_info.lidar_id & 0xFF) << 24) |
            ((device_info.lidar_id & 0xFF00) << 8) |
            ((device_info.lidar_id & 0xFF0000) >> 8) |
            ((device_info.lidar_id & 0xFF000000) >> 24);
        file.write(reinterpret_cast<const char*>(&lidar_id_le), 4);
        file.write(reinterpret_cast<const char*>(&device_info.lidar_type), 1);
        file.write(reinterpret_cast<const char*>(&device_info.device_type), 1);
        uint8_t enable_extrinsic = device_info.enable_extrinsic ? 1 : 0;
        file.write(reinterpret_cast<char*>(&enable_extrinsic), 1);
        file.write(reinterpret_cast<const char*>(&device_info.offset_roll), 4);
        file.write(reinterpret_cast<const char*>(&device_info.offset_pitch), 4);
        file.write(reinterpret_cast<const char*>(&device_info.offset_yaw), 4);
        // 自动转换为cm再写入
        float offset_x_cm = device_info.offset_x * 100.0f;
        float offset_y_cm = device_info.offset_y * 100.0f;
        float offset_z_cm = device_info.offset_z * 100.0f;
        file.write(reinterpret_cast<const char*>(&offset_x_cm), 4);
        file.write(reinterpret_cast<const char*>(&offset_y_cm), 4);
        file.write(reinterpret_cast<const char*>(&offset_z_cm), 4);
    }
    return true;
}

bool LVX2Writer::writeFrameHeader(std::ofstream& file, uint64_t current_offset, uint64_t next_offset, uint64_t frame_index) {
    file.write(reinterpret_cast<const char*>(&current_offset), 8);
    file.write(reinterpret_cast<const char*>(&next_offset), 8);
    file.write(reinterpret_cast<const char*>(&frame_index), 8);
    return true;
}

std::vector<uint8_t> LVX2Writer::createPackageHeader(const std::vector<uint8_t>& raw_udp_payload, uint32_t data_length, const DeviceInfo& device_info) {
    std::vector<uint8_t> header(27, 0);
    header[0] = raw_udp_payload[0];
    uint32_t lidar_id_le = 
        ((device_info.lidar_id & 0xFF) << 24) |
        ((device_info.lidar_id & 0xFF00) << 8) |
        ((device_info.lidar_id & 0xFF0000) >> 8) |
        ((device_info.lidar_id & 0xFF000000) >> 24);
    memcpy(&header[1], &lidar_id_le, 4);
    header[5] = 8;
    header[6] = raw_udp_payload[11];
    memcpy(&header[7], &raw_udp_payload[28], 8);
    memcpy(&header[15], &raw_udp_payload[7], 2);
    header[17] = raw_udp_payload[10];
    memcpy(&header[18], &data_length, 4);
    header[22] = raw_udp_payload[9];
    // header[23-26] 保持为0
    return header;
}

std::vector<uint8_t> LVX2Writer::createPackageHeaderForDataType(const std::vector<uint8_t>& raw_udp_payload, 
                                                               uint32_t data_length, 
                                                               const DeviceInfo& device_info,
                                                               PointCloudDataType data_type) {
    std::vector<uint8_t> header(27, 0);
    header[0] = raw_udp_payload[0];
    uint32_t lidar_id_le = 
        ((device_info.lidar_id & 0xFF) << 24) |
        ((device_info.lidar_id & 0xFF00) << 8) |
        ((device_info.lidar_id & 0xFF0000) >> 8) |
        ((device_info.lidar_id & 0xFF000000) >> 24);
    memcpy(&header[1], &lidar_id_le, 4);
    header[5] = 8;
    header[6] = raw_udp_payload[11];
    memcpy(&header[7], &raw_udp_payload[28], 8);
    memcpy(&header[15], &raw_udp_payload[7], 2);
    
    // 根据数据类型设置相应的值
    switch (data_type) {
        case PointCloudDataType::CARTESIAN_32BIT:
            header[17] = 1;  // 数据类型1
            break;
        case PointCloudDataType::CARTESIAN_16BIT:
            header[17] = 2;  // 数据类型2
            break;
        case PointCloudDataType::SPHERICAL:
            header[17] = 1;  // 球坐标转换为数据类型1
            break;
    }
    
    memcpy(&header[18], &data_length, 4);
    header[22] = raw_udp_payload[9];
    // header[23-26] 保持为0
    return header;
}

std::vector<uint8_t> LVX2Writer::processPointCloudData(const std::vector<uint8_t>& raw_udp_payload, 
                                                       PointCloudDataType data_type,
                                                       bool convert_to_type1) {
    // 解析点云数据
    auto points = PacketParser::parsePointCloudData(raw_udp_payload, data_type);
    
    if (points.empty()) {
        return std::vector<uint8_t>();
    }
    
    // 如果是球坐标，需要转换为直角坐标
    if (data_type == PointCloudDataType::SPHERICAL) {
        points = PacketParser::convertSphericalToCartesian(points);
    }
    
    // 根据convert_to_type1参数决定输出格式
    if (convert_to_type1) {
        // 转换为数据类型1（14字节/点）
        return PacketParser::convertToDataType1(points);
    } else {
        // 转换为数据类型2（8字节/点）
        return PacketParser::convertToDataType2(points);
    }
}