#include "packet_parser.h"
#include "pcap_to_lvx2.h"
#include "device_info.h"
#include <pcap.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <string>
#include <ctime>
#include "log_dialog.h"

struct ImuDataRow {
    uint32_t packet_num;
    uint16_t udp_cnt;
    uint64_t timestamp;
    float gyro_x, gyro_y, gyro_z;
    float acc_x, acc_y, acc_z;
};

extern void logToDialog(LogLevel level, const std::string& message);
extern HWND g_hLogDlg;

bool extractImuDataToCsv(const std::string& pcap_file, const std::string& csv_file, HWND hDlg) {
    g_hLogDlg = hDlg;
    std::string input_file = std::filesystem::absolute(pcap_file).string();
    std::string intermediate_pcap;  // 存储中间文件的路径
    
    // 创建临时PCAPToLVX2实例来调用pcapng转换函数
    PCAPToLVX2 temp_converter("", "");
    bool is_pcapng = temp_converter.isPcapngFile(input_file);
    
    if (is_pcapng) {
        logToDialog(LogLevel::LOG_INFO, "检测到pcapng格式，正在转换为pcap，请稍候...");
        intermediate_pcap = temp_converter.convertPcapngToPcap(input_file);
        if (intermediate_pcap.empty()) {
            logToDialog(LogLevel::LOG_ERROR, "转换 pcapng 到 pcap 格式失败！");
            //MessageBoxA(NULL, "转换 pcapng 到 pcap 格式失败！", "转换错误", MB_ICONERROR);
            return false;
        }
        input_file = intermediate_pcap;  // 使用转换后的文件
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(input_file.c_str(), errbuf);
    if (!pcap) {
        logToDialog(LogLevel::LOG_ERROR, "打开文件失败： " + input_file + ", 错误： " + errbuf);
        //MessageBoxA(NULL, ("打开文件失败：" + input_file + "\n错误：" + errbuf).c_str(), "文件打开错误", MB_ICONERROR);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_ERROR, "删除中间 pcap 文件失败: " + std::string(e.what()));
            }
        }
        return false;
    }

    // 首先检测设备类型
    LivoxDeviceType detected_device_type = LivoxDeviceType::MID_360; // 默认值
    bool imu_data_found = false;
    
    // 读取所有数据包来检测设备类型
    std::vector<std::vector<uint8_t>> all_raw_packets;
    struct pcap_pkthdr* header;
    const u_char* data;
    int result;
    
    while ((result = pcap_next_ex(pcap, &header, &data)) > 0) {
        all_raw_packets.emplace_back(data, data + header->caplen);
    }
    
    // 检测设备类型（通过点云端口）
    for (const auto& [device_type, config] : DEVICE_CONFIGS) {
        for (const auto& pkt_data : all_raw_packets) {
            PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
            if (info.src_port == config.point_cloud_port) {
                detected_device_type = device_type;
                logToDialog(LogLevel::LOG_INFO, "检测到设备类型: " + config.device_name + "，将提取IMU数据");
                break;
            }
        }
        if (detected_device_type != LivoxDeviceType::MID_360) break;
    }
    
    // 重新打开文件进行IMU数据提取
    pcap_close(pcap);
    pcap = pcap_open_offline(input_file.c_str(), errbuf);
    if (!pcap) {
        logToDialog(LogLevel::LOG_ERROR, "重新打开文件失败： " + input_file + ", 错误： " + errbuf);
        return false;
    }
    
    std::vector<ImuDataRow> imu_rows;
    uint32_t packet_num = 0;
    const auto& detected_config = DEVICE_CONFIGS.at(detected_device_type);

    while ((result = pcap_next_ex(pcap, &header, &data)) > 0) {
        packet_num++;
        std::vector<uint8_t> pkt_data(data, data + header->caplen);
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.payload.empty() || info.src_port != detected_config.imu_port) continue;
        if (info.payload.size() < 60) continue;
        
        // Livox IMU包头部解析
        uint8_t version = info.payload[0];
        uint16_t length = info.payload[1] | (info.payload[2] << 8);
        uint16_t time_interval = info.payload[3] | (info.payload[4] << 8);
        uint16_t dot_num = info.payload[5] | (info.payload[6] << 8);
        uint16_t udp_cnt = info.payload[7] | (info.payload[8] << 8);
        uint16_t frame_cnt = info.payload[9] | (info.payload[10] << 8);
        uint8_t data_type = info.payload[11];
        uint8_t time_type = info.payload[12];
        if (version != 0 || length != 60 || data_type != 0) continue;
        
        uint64_t timestamp = 0;
        memcpy(&timestamp, &info.payload[28], 8);
        float gyro_x, gyro_y, gyro_z, acc_x, acc_y, acc_z;
        memcpy(&gyro_x, &info.payload[36], 4);
        memcpy(&gyro_y, &info.payload[40], 4);
        memcpy(&gyro_z, &info.payload[44], 4);
        memcpy(&acc_x, &info.payload[48], 4);
        memcpy(&acc_y, &info.payload[52], 4);
        memcpy(&acc_z, &info.payload[56], 4);
        imu_rows.push_back({packet_num, udp_cnt, timestamp, gyro_x, gyro_y, gyro_z, acc_x, acc_y, acc_z});
        imu_data_found = true;
    }
    pcap_close(pcap);

    // 写入CSV前判断是否有IMU数据
    if (imu_rows.empty()) {
        std::string error_msg = "PCAP 文件中未找到来自端口 " + std::to_string(detected_config.imu_port) + 
                               " 的 IMU 数据。支持的IMU端口: ";
        for (const auto& [device_type, config] : DEVICE_CONFIGS) {
            error_msg += std::to_string(config.imu_port) + "(" + config.device_name + "), ";
        }
        error_msg = error_msg.substr(0, error_msg.length() - 2); // 移除最后的逗号和空格
        logToDialog(LogLevel::LOG_ERROR, error_msg);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            } catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_ERROR, std::string("删除中间文件失败: ") + e.what());
            }
        }
        return false;
    }

    // 写入CSV
    std::ofstream ofs(csv_file);
    if (!ofs) {
        logToDialog(LogLevel::LOG_ERROR, "无法打开输出CSV文件: " + csv_file);
        //MessageBoxA(NULL, ("无法打开输出CSV文件: " + csv_file).c_str(), "文件打开错误", MB_ICONERROR);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_ERROR, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }
    ofs << "packet_num,udp_cnt,timestamp,gyro_x,gyro_y,gyro_z,acc_x,acc_y,acc_z\n";
    for (const auto& row : imu_rows) {
        ofs << row.packet_num << ',' << row.udp_cnt << ',' << row.timestamp << ','
            << std::setprecision(8) << row.gyro_x << ',' << row.gyro_y << ',' << row.gyro_z << ','
            << row.acc_x << ',' << row.acc_y << ',' << row.acc_z << '\n';
    }
    
    // 如果是 pcapng 文件，删除中间转换的 pcap 文件
    if (is_pcapng && !intermediate_pcap.empty()) {
        try {
            if (std::filesystem::exists(intermediate_pcap)) {
                std::filesystem::remove(intermediate_pcap);
            }
        }
        catch (const std::exception& e) {
            logToDialog(LogLevel::LOG_ERROR, std::string("删除中间文件失败: ") + e.what());
        }
    }
    
    return true;
}