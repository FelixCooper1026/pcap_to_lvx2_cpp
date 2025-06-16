#include "lvx2_writer.h"
#include <cstring>

bool LVX2Writer::writeHeaders(std::ofstream& file, const DeviceInfo& device_info) {
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
    uint8_t device_count = 1;
    file.write(reinterpret_cast<char*>(&device_count), 1);

    // 设备信息
    std::string lidar_sn = device_info.lidar_sn;
    lidar_sn.resize(16, '\0');
    file.write(lidar_sn.c_str(), 16);
    std::string hub_sn = device_info.hub_sn;
    hub_sn.resize(16, '\0');
    file.write(hub_sn.c_str(), 16);
    file.write(reinterpret_cast<const char*>(&device_info.lidar_id), 4);
    file.write(reinterpret_cast<const char*>(&device_info.lidar_type), 1);
    file.write(reinterpret_cast<const char*>(&device_info.device_type), 1);
    uint8_t enable_extrinsic = device_info.enable_extrinsic ? 1 : 0;
    file.write(reinterpret_cast<char*>(&enable_extrinsic), 1);
    file.write(reinterpret_cast<const char*>(&device_info.offset_roll), 4);
    file.write(reinterpret_cast<const char*>(&device_info.offset_pitch), 4);
    file.write(reinterpret_cast<const char*>(&device_info.offset_yaw), 4);
    file.write(reinterpret_cast<const char*>(&device_info.offset_x), 4);
    file.write(reinterpret_cast<const char*>(&device_info.offset_y), 4);
    file.write(reinterpret_cast<const char*>(&device_info.offset_z), 4);
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
    memcpy(&header[1], &device_info.lidar_id, 4);
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