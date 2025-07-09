#include "pcap_to_lvx2.h"
#include "packet_parser.h"
#include "lvx2_writer.h"
#include "config_manager.h"
#include <fstream>
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <chrono>
#include <iomanip>
#include <map>
#include "log_dialog.h"



// 日志打印函数
void log(LogLevel level, const std::string& message) {
    std::string levelStr;
    switch (level) {
        case LogLevel::LOG_INFO:
            levelStr = "[INFO]";
            break;
        case LogLevel::LOG_WARNING:
            levelStr = "[WARNING]";
            break;
        case LogLevel::LOG_ERROR:
            levelStr = "[ERROR]";
            break;
        case LogLevel::LOG_SUCCESS:
            levelStr = "[SUCCESS]";
            break;
    }
    std::cout << getCurrentTimeString() << " " << levelStr << " " << message << std::endl;
}

extern void logToDialog(LogLevel level, const std::string& message);
extern HWND g_hLogDlg;

bool PCAPToLVX2::isPcapFile(const std::string& filename) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) return false;

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    return (magic == 0xa1b2c3d4 ||
        magic == 0xd4c3b2a1 ||
        magic == 0x0a0d0d0a);
}

bool PCAPToLVX2::isPcapngFile(const std::string& filename) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) return false;

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    return (magic == 0x0a0d0d0a);
}

std::string selectEditcapPath() {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"Executable Files\0editcap.exe\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrTitle = L"选择editcap.exe文件";

    if (GetOpenFileNameW(&ofn)) {
        int size_needed = WideCharToMultiByte(CP_ACP, 0, szFile, -1, NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_ACP, 0, szFile, -1, &strTo[0], size_needed, NULL, NULL);

        // 使用 ConfigManager 保存路径
        ConfigManager::getInstance().setEditcapPath(strTo);
        return strTo;
    }
    return "";
}

std::string PCAPToLVX2::convertPcapngToPcap(const std::string& pcapng_file) {
    // 1. 优先从配置加载路径（自动处理空配置情况）
    std::string editcap_path = ConfigManager::getInstance().getEditcapPath();

    // 2. 路径有效性二次验证（包括路径格式标准化）
    bool need_reselect = editcap_path.empty();
    if (!need_reselect) {
        try {
            editcap_path = std::filesystem::absolute(editcap_path).lexically_normal().string();
            need_reselect = !std::filesystem::exists(editcap_path);
        }
        catch (...) {
            need_reselect = true;
        }
    }

    // 3. 路径无效时让用户选择并保存
    if (need_reselect) {
        logToDialog(LogLevel::LOG_INFO, "未找到有效的editcap.exe路径，请选择Wireshark安装目录下的editcap.exe。");
        //MessageBoxA(NULL, "未找到有效的 editcap.exe 路径，请选择 Wireshark 安装目录下的 editcap.exe 文件。", "选择 editcap.exe", MB_ICONINFORMATION);
        editcap_path = selectEditcapPath();
        if (editcap_path.empty()) {
            logToDialog(LogLevel::LOG_ERROR, "未选择 editcap.exe 文件。");
            //MessageBoxA(NULL, "未选择 editcap.exe 文件，转换终止。", "转换错误", MB_ICONERROR);
            return "";
        }

        try {
            editcap_path = std::filesystem::absolute(editcap_path).lexically_normal().string();
            ConfigManager::getInstance().setEditcapPath(editcap_path);
            logToDialog(LogLevel::LOG_SUCCESS, "已保存新路径: " + editcap_path);
        }
        catch (...) {
            logToDialog(LogLevel::LOG_ERROR, "选择的路径格式无效: " + editcap_path);
            //MessageBoxA(NULL, "选择的路径格式无效，请重新选择。", "路径错误", MB_ICONERROR);
            return "";
        }
    }

    // 4. 规范化输入输出路径（增强异常处理）
    std::filesystem::path input_path, output_path;
    try {
        input_path = std::filesystem::absolute(pcapng_file).lexically_normal();
        output_path = input_path.parent_path() / (input_path.stem().string() + "_converted.pcap");
        output_path = std::filesystem::absolute(output_path).lexically_normal();
    }
    catch (const std::exception& e) {
        logToDialog(LogLevel::LOG_ERROR, std::string("路径规范化失败: ") + e.what());
        return "";
    }

    // 5. 自动创建输出目录（增强错误处理）
    try {
        std::filesystem::create_directories(output_path.parent_path());
    }
    catch (const std::exception& e) {
        logToDialog(LogLevel::LOG_ERROR, std::string("无法创建输出目录: ") + e.what());
        return "";
    }

    // 4. 调试信息增强
    //std::cout << "[DEBUG] Current dir: " << std::filesystem::current_path() << "\n"
    //    << "[DEBUG] Input file: " << input_path << "\n"
    //    << "[DEBUG] Output file: " << output_path << "\n"
    //    << "[DEBUG] Editcap path: " << editcap_path << "\n"
    //    << "[DEBUG] Editcap exists: " << std::filesystem::exists(editcap_path) << std::endl;

    // 5. 构建命令（参数顺序修正）
    std::string cmd = "\"" + editcap_path + "\" \"" + input_path.string() + "\" \"" +
        output_path.string() + "\" -F pcap";
    //std::cout << "[DEBUG] Execute: " << cmd << std::endl;

    // 6. 错误输出捕获设置
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        logToDialog(LogLevel::LOG_ERROR, std::string("创建管道失败: ") + std::to_string(GetLastError()));
        return "";
    }

    // 7. 进程创建配置
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;

    // 8. 工作目录设置
    std::string working_dir = std::filesystem::path(editcap_path).parent_path().string();

    // 9. 创建进程
    std::vector<char> cmd_vec(cmd.begin(), cmd.end());
    cmd_vec.push_back('\0');

    if (!CreateProcessA(
        NULL, cmd_vec.data(), NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, working_dir.c_str(), &si, &pi
    )) {
        logToDialog(LogLevel::LOG_ERROR, std::string("创建进程失败: ") + std::to_string(GetLastError()));
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return "";
    }

    // 10. 实时读取错误输出
    CloseHandle(hWrite);
    std::string error_output;
    char buffer[4096];
    DWORD bytes_read;

    while (ReadFile(hRead, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        error_output.append(buffer, bytes_read);
    }

    // 11. 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    // 12. 输出错误信息（如果有）
    if (!error_output.empty()) {
        logToDialog(LogLevel::LOG_INFO, error_output);
    }

    // 13. 资源清理
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 14. 结果验证
    if (exit_code != 0 || !std::filesystem::exists(output_path)) {
        logToDialog(LogLevel::LOG_ERROR, std::string("转换失败，退出码: ") + std::to_string(exit_code));
        return "";
    }

    //std::cout << "[SUCCESS] Output file created: " << output_path << std::endl;
    return output_path.string();
}

PCAPToLVX2::PCAPToLVX2(const std::string& input_file, const std::string& output_file)
    : input_file_(input_file), output_file_(output_file), frame_index_(0), current_offset_(92) {}

bool PCAPToLVX2::extractDeviceInfo(const std::vector<std::vector<uint8_t>>& all_raw_packets) {
    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.payload.empty()) continue;
        
        // 检查所有设备的推送数据端口
        for (const auto& [device_type, config] : DEVICE_CONFIGS) {
            if (info.src_port == config.push_data_port || info.dst_port == config.push_data_port) {
                // HAP设备需要特殊处理：只有长度=333的数据包才是推送数据
                if (device_type == LivoxDeviceType::HAP && info.payload.size() < 333) {
                    continue;
                }
                
                PacketParser::parseUdpPayload(info.payload, device_info_);
                if (!device_info_.lidar_sn.empty() && device_info_.lidar_sn != "DEFAULT_LIDAR") {
                    // 使用对应设备类型的配置
                    device_info_.lidar_type = config.lidar_type;
                    device_info_.device_type = config.device_type;
                    return true;
                }
            }
        }
    }
    return false;
}

uint64_t PCAPToLVX2::getTimestampFromPayload(const std::vector<uint8_t>& payload) {
    if (payload.size() >= 36) {
        uint64_t ts = 0;
        memcpy(&ts, &payload[28], 8);
        return ts;
    }
    return 0;
}

bool PCAPToLVX2::convert() {
    std::string input_file = std::filesystem::absolute(input_file_).string();
    std::string intermediate_pcap;  // 存储中间文件的路径
    bool is_pcapng = isPcapngFile(input_file);
    
    if (is_pcapng) {
        logToDialog(LogLevel::LOG_INFO, "检测到pcapng格式，正在转换为pcap，请稍候...");
        intermediate_pcap = convertPcapngToPcap(input_file);
        if (intermediate_pcap.empty()) {
            MessageBoxA(NULL, "转换 pcapng 到 pcap 格式失败。", "转换错误", MB_ICONERROR);
            return false;
        }
        input_file = intermediate_pcap;  // 使用转换后的文件
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(input_file.c_str(), errbuf);
    if (!pcap) {
        std::string error_msg = "Failed to open file: " + std::string(errbuf);
        logToDialog(LogLevel::LOG_ERROR, "打开文件失败： " + input_file + ", 错误： " + errbuf);
        //MessageBoxA(NULL, ("打开文件失败: " + std::string(errbuf)).c_str(), "文件打开错误", MB_ICONERROR);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_WARNING, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }

    int linktype = pcap_datalink(pcap);
    if (linktype != DLT_EN10MB) {
        std::string warning_msg = "Unsupported link type: " + std::to_string(linktype) + "\nExpected Ethernet (DLT_EN10MB)";
        logToDialog(LogLevel::LOG_WARNING, "警告: " + warning_msg);
        //MessageBoxA(NULL, ("不支持的链路类型: " + std::to_string(linktype) + "\n期望类型: 以太网 (DLT_EN10MB)").c_str(), "警告", MB_ICONWARNING);
    }

    std::vector<std::vector<uint8_t>> all_raw_packets;
    struct pcap_pkthdr* header;
    const u_char* data;
    int result;
    int packet_count = 0;

    while ((result = pcap_next_ex(pcap, &header, &data)) > 0) {
        all_raw_packets.emplace_back(data, data + header->caplen);
        packet_count++;
    }

    if (result == -1) {
        std::string error_msg = "读取数据包时出错: " + std::string(pcap_geterr(pcap));
        logToDialog(LogLevel::LOG_ERROR, "错误: " + error_msg);
        //MessageBoxA(NULL, ("读取数据包时出错: " + std::string(pcap_geterr(pcap))).c_str(), "数据包读取错误", MB_ICONERROR);
        pcap_close(pcap);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_WARNING, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }

    pcap_close(pcap);
    logToDialog(LogLevel::LOG_INFO, "已读取数据包数量: " + std::to_string(packet_count));

    if (all_raw_packets.empty()) {
        std::string error_msg = "文件中未找到数据包。";
        logToDialog(LogLevel::LOG_ERROR, error_msg);
        //MessageBoxA(NULL, "文件中未找到数据包。", "转换错误", MB_ICONERROR);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_WARNING, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }

    if (!extractDeviceInfo(all_raw_packets)) {
        std::string warning_msg = "无法从 PCAP 文件中提取到设备信息，将使用默认值。";
        logToDialog(LogLevel::LOG_WARNING, warning_msg);
        //MessageBoxA(NULL, "无法从 PCAP 文件中提取到设备信息，将使用默认值。", "警告", MB_ICONWARNING);
    }

    // 自动检测设备类型
    LivoxDeviceType detected_device_type = LivoxDeviceType::MID_360; // 默认值
    bool point_data_found = false;
    
    // 检查所有支持的点云端口
    for (const auto& [device_type, config] : DEVICE_CONFIGS) {
        for (const auto& pkt_data : all_raw_packets) {
            PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
            if (info.src_port == config.point_cloud_port) {
                detected_device_type = device_type;
                point_data_found = true;
                logToDialog(LogLevel::LOG_INFO, "检测到设备类型: " + config.device_name + " (端口: " + std::to_string(config.point_cloud_port) + ")");
                break;
            }
        }
        if (point_data_found) break;
    }
    
    if (!point_data_found) {
        std::string error_msg = "PCAP 文件中未找到支持的点云数据端口。支持的端口: ";
        for (const auto& [device_type, config] : DEVICE_CONFIGS) {
            error_msg += std::to_string(config.point_cloud_port) + "(" + config.device_name + "), ";
        }
        error_msg = error_msg.substr(0, error_msg.length() - 2); // 移除最后的逗号和空格
        logToDialog(LogLevel::LOG_ERROR, error_msg);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_WARNING, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }

    // --- Device Info Collection and IP Mapping ---
    std::vector<DeviceInfo> device_infos;
    std::map<std::string, DeviceInfo> ip2info;
    std::map<uint32_t, std::string> lidar_id_to_ip; // Helper to avoid duplicate devices with same lidar_id
    
    // 获取检测到的设备配置（只定义一次）
    const auto& detected_config = DEVICE_CONFIGS.at(detected_device_type);

    // 1. Try to get info from device info packets (push data ports)
    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.payload.empty() || info.src_ip.empty()) continue;

        // 检查所有设备的推送数据端口
        for (const auto& [device_type, config] : DEVICE_CONFIGS) {
            if (info.src_port == config.push_data_port || info.dst_port == config.push_data_port) {
                // HAP设备需要特殊处理：只有长度=333的数据包才是推送数据
                if (device_type == LivoxDeviceType::HAP && info.payload.size() < 333) {
                    continue;
                }
                DeviceInfo tmp_info;
                PacketParser::parseUdpPayload(info.payload, tmp_info);
                if (!tmp_info.lidar_sn.empty()) {
                    if (lidar_id_to_ip.find(tmp_info.lidar_id) == lidar_id_to_ip.end()) {
                        // 使用对应设备类型的配置
                        tmp_info.lidar_type = config.lidar_type;
                        tmp_info.device_type = config.device_type;
                        lidar_id_to_ip[tmp_info.lidar_id] = info.src_ip;
                        ip2info[info.src_ip] = tmp_info;
                        logToDialog(LogLevel::LOG_INFO, "从端口 " + std::to_string(config.push_data_port) +
                                  " 获取到设备信息: " + config.device_name + ", SN: " + tmp_info.lidar_sn + ", IP: " + info.src_ip);
                    }
                }
            }
        }
    }

    for (const auto& kv : ip2info) {
        device_infos.push_back(kv.second);
    }
    logToDialog(LogLevel::LOG_INFO, "从推送数据端口获取到 " + std::to_string(device_infos.size()) + " 个设备信息");
    
    // 2. Fallback: if no device info from push data ports, infer from point cloud packet source IPs
    // 但只处理那些还没有设备信息的IP
    std::map<std::string, int> unique_src_ips;
    
    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.src_port == detected_config.point_cloud_port && !info.src_ip.empty()) {
            // 只收集那些还没有设备信息的IP
            if (ip2info.find(info.src_ip) == ip2info.end()) {
                unique_src_ips[info.src_ip] = 1;
            }
        }
    }

    if (!unique_src_ips.empty()) {
        for (auto const& [ip_str, val] : unique_src_ips) {
            DeviceInfo default_info;
            std::string ip_for_sn = ip_str;
            std::replace(ip_for_sn.begin(), ip_for_sn.end(), '.', '_');
            default_info.lidar_sn = ip_for_sn;
            default_info.lidar_id = PacketParser::ipToLidarId(ip_str);
            // 使用检测到的设备类型配置
            default_info.lidar_type = detected_config.lidar_type;
            default_info.device_type = detected_config.device_type;
            device_infos.push_back(default_info);
            ip2info[ip_str] = default_info;
            logToDialog(LogLevel::LOG_INFO, "为IP " + ip_str + " 创建默认设备信息");
        }
    }

    // 3. Final fallback: if still no devices found, use a single IP-based default (should rarely happen)
    if (device_infos.empty()) {
        DeviceInfo default_info;
        default_info.lidar_sn = "LIDAR_UNKNOWN";
        default_info.lidar_id = 0;
        // 使用检测到的设备类型配置
        default_info.lidar_type = detected_config.lidar_type;
        default_info.device_type = detected_config.device_type;
        device_infos.push_back(default_info);
    }

    std::ofstream out_file(output_file_, std::ios::binary);
    if (!out_file) {
        logToDialog(LogLevel::LOG_ERROR, "无法打开输出文件: " + output_file_);
        //MessageBoxA(NULL, ("无法打开输出文件: " + output_file_).c_str(), "文件打开错误", MB_ICONERROR);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_WARNING, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }

    if (!LVX2Writer::writeHeaders(out_file, device_infos)) {
        logToDialog(LogLevel::LOG_ERROR, "写入文件头失败。");
        //MessageBoxA(NULL, "写入文件头失败。", "转换错误", MB_ICONERROR);
        if (is_pcapng && !intermediate_pcap.empty()) {
            try {
                if (std::filesystem::exists(intermediate_pcap)) {
                    std::filesystem::remove(intermediate_pcap);
                }
            }
            catch (const std::exception& e) {
                logToDialog(LogLevel::LOG_WARNING, "Failed to delete intermediate file: " + std::string(e.what()));
            }
        }
        return false;
    }

    // 定义帧内package结构
    struct FramePackage {
        std::vector<uint8_t> payload;
        DeviceInfo device_info;
    };
    std::vector<std::vector<FramePackage>> frames;
    std::vector<FramePackage> current_frame;
    uint64_t frame_start_ts = 0;

    // 遍历点云包，按原始顺序分帧
    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.payload.empty()) continue;
        if (info.src_port == detected_config.point_cloud_port && info.payload.size() >= 36) {
            auto it = ip2info.find(info.src_ip);
            if (it == ip2info.end()) continue;
            uint64_t timestamp = getTimestampFromPayload(info.payload);

            if (current_frame.empty()) {
                // 新开第一帧
                frame_start_ts = timestamp;
            }
            if (timestamp >= frame_start_ts + ns_threshold_) {
                // 超出当前帧区间，写入上一帧，开启新帧
                frames.push_back(current_frame);
                current_frame.clear();
                frame_start_ts = timestamp;
            }
            current_frame.push_back(FramePackage{info.payload, it->second});
        }
    }
    if (!current_frame.empty()) frames.push_back(current_frame);

    // 写入所有帧
    frame_index_ = 0;
    size_t header_size = 24 + 5 + device_infos.size() * 63;
    current_offset_ = header_size;
    for (const auto& frame : frames) {
        uint32_t frame_size = 0;
        std::vector<std::vector<uint8_t>> pkgs;
        for (const auto& pkg : frame) {
            std::vector<uint8_t> data(pkg.payload.begin() + 36, pkg.payload.end());
            auto pkg_header = LVX2Writer::createPackageHeader(pkg.payload, data.size(), pkg.device_info);
            if (pkg_header.empty()) continue;
            std::vector<uint8_t> pkg_bytes(pkg_header);
            pkg_bytes.insert(pkg_bytes.end(), data.begin(), data.end());
            pkgs.push_back(pkg_bytes);
            frame_size += pkg_bytes.size();
        }
        if (pkgs.empty()) continue;
        uint64_t next_offset = current_offset_ + 24 + frame_size;
        if (!LVX2Writer::writeFrameHeader(out_file, current_offset_, next_offset, frame_index_)) {
            std::string error_msg = "Failed to write frame header.";
            logToDialog(LogLevel::LOG_ERROR, error_msg);
            //MessageBoxA(NULL, "写入Frame Header失败。", "转换错误", MB_ICONERROR);
            return false;
        }
        for (const auto& pkg : pkgs) {
            out_file.write(reinterpret_cast<const char*>(pkg.data()), pkg.size());
            if (out_file.fail()) {
                std::string error_msg = "Failed to write frame data.";
                logToDialog(LogLevel::LOG_ERROR, error_msg);
                //MessageBoxA(NULL, "写入Frame Data失败。", "转换错误", MB_ICONERROR);
                return false;
            }
        }
        current_offset_ = next_offset;
        frame_index_++;
    }

    out_file.close();

    // 如果是 pcapng 文件，删除中间转换的 pcap 文件
    if (is_pcapng && !intermediate_pcap.empty()) {
        try {
            if (std::filesystem::exists(intermediate_pcap)) {
                std::filesystem::remove(intermediate_pcap);
            }
        }
        catch (const std::exception& e) {
            std::string warning_msg = "删除中间 PCAP 文件失败: " + std::string(e.what());
            logToDialog(LogLevel::LOG_WARNING, warning_msg);
            //MessageBoxA(NULL, ("删除中间 PCAP 文件失败: " + std::string(e.what())).c_str(), "警告", MB_ICONWARNING);
        }
    }
    
    return true;
}