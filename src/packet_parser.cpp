#include "packet_parser.h"
#include <cstring>
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
            device_info.lidar_sn.erase(device_info.lidar_sn.find('\0'));
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