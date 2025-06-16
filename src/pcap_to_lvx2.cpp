#include "pcap_to_lvx2.h"
#include "packet_parser.h"
#include "lvx2_writer.h"
#include <fstream>
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>
#include <filesystem>
#include <sstream>
#include <algorithm>

bool isPcapFile(const std::string& filename) {
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

bool isPcapngFile(const std::string& filename) {
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

std::string findEditcapPath() {
    // 可能的 Wireshark 安装路径
    std::vector<std::string> possible_paths = {
        "C:\\Program Files\\Wireshark\\editcap.exe",
        "C:\\Program Files (x86)\\Wireshark\\editcap.exe",
        "S:\\Software\\Wireshark\\editcap.exe"
    };

    // 检查环境变量 PATH 中的 Wireshark
    char* path = getenv("PATH");
    if (path) {
        std::string path_str(path);
        std::stringstream ss(path_str);
        std::string dir;
        while (std::getline(ss, dir, ';')) {
            possible_paths.push_back(dir + "\\editcap.exe");
        }
    }

    // 检查每个可能的路径
    for (const auto& path : possible_paths) {
        if (std::filesystem::exists(path)) {
            // 检查文件是否可访问
            FILE* fp = fopen(path.c_str(), "rb");
            if (fp) {
                fclose(fp);
                //std::cout << "Found editcap at: " << path << std::endl;
                return path;
            }
        }
    }

    return "";
}

std::string convertPcapngToPcap(const std::string& pcapng_file) {
    std::filesystem::path input_path = std::filesystem::absolute(pcapng_file);
    std::filesystem::path output_path = input_path.parent_path() / 
                                      (input_path.stem().string() + "_converted.pcap");
    
    std::string editcap_path = findEditcapPath();
    if (editcap_path.empty()) {
        std::cerr << "\n[ERROR] Could not find editcap.exe. Please make sure Wireshark is installed." << std::endl;
        return "";
    }
    
    // 添加调试信息
    //std::cout << "Current directory: " << std::filesystem::current_path() << std::endl;
    //std::cout << "Input file path: " << input_path << std::endl;
    //std::cout << "Output file path: " << output_path << std::endl;
    //std::cout << "Editcap path: " << editcap_path << std::endl;
    
    // 切换到文件所在目录
    std::string current_dir = std::filesystem::current_path().string();
    std::filesystem::current_path(input_path.parent_path());
    
    // 构建命令，使用相对路径
    std::string command = editcap_path + " -F pcap " + 
                         input_path.filename().string() + " " + 
                         output_path.filename().string();
    //std::cout << "Converting pcapng to pcap: " << command << std::endl;
    
    int result = system(command.c_str());
    if (result != 1) {
        std::cerr << "Command execution failed with error code: " << result << std::endl;
        return "";
    }
    
    // 恢复原目录
    std::filesystem::current_path(current_dir);
    
    // 检查输出文件是否存在
    if (std::filesystem::exists(output_path)) {
        //std::cout << "Successfully created pcap file: " << output_path << std::endl;
        return output_path.string();
    } else {
        std::cerr << "Failed to create pcap file" << std::endl;
        return "";
    }
}

PCAPToLVX2::PCAPToLVX2(const std::string& pcap_file, const std::string& output_file)
    : pcap_file_(pcap_file), output_file_(output_file), frame_index_(0), current_offset_(92) {}

bool PCAPToLVX2::extractDeviceInfo(const std::vector<std::vector<uint8_t>>& all_raw_packets) {
    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.payload.empty()) continue;
        if (info.src_port == 56200 || info.dst_port == 56200) {
            PacketParser::parseUdpPayload(info.payload, device_info_);
            if (!device_info_.lidar_sn.empty() && device_info_.lidar_sn != "DEFAULT_LIDAR")
                return true;
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
    //std::cout << "Opening file: " << pcap_file_ << std::endl;

    std::string input_file = std::filesystem::absolute(pcap_file_).string();
    if (isPcapngFile(input_file)) {
        std::cout << "Detected pcapng format, converting to pcap, please wait..." << std::endl;
        input_file = convertPcapngToPcap(input_file);
        if (input_file.empty()) {
            return false;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(input_file.c_str(), errbuf);
    if (!pcap) {
        std::cerr << "Failed to open file: " << errbuf << std::endl;
        return false;
    }

    int linktype = pcap_datalink(pcap);
    //std::cout << "Link layer type: " << linktype << std::endl;
    if (linktype != DLT_EN10MB) {
        std::cerr << "Warning: Unsupported link type: " << linktype << std::endl;
        std::cerr << "Expected Ethernet (DLT_EN10MB)" << std::endl;
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
        std::cerr << "Error reading packets: " << pcap_geterr(pcap) << std::endl;
        pcap_close(pcap);
        return false;
    }

    pcap_close(pcap);
    std::cout << "Read " << packet_count << " packets" << std::endl;

    if (all_raw_packets.empty()) {
        std::cerr << "No packets found in the file." << std::endl;
        return false;
    }

    if (!extractDeviceInfo(all_raw_packets)) {
        std::cerr << "Warning: Failed to extract device information, using default values." << std::endl;
    }

    bool point_data_found = false;
    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.src_port == 56300) {
            point_data_found = true;
            break;
        }
    }
    if (!point_data_found) {
        std::cerr << "No point cloud data found from port 56300." << std::endl;
        return false;
    }

    std::ofstream out_file(output_file_, std::ios::binary);
    if (!out_file) {
        std::cerr << "Failed to open output file: " << output_file_ << std::endl;
        return false;
    }

    if (!LVX2Writer::writeHeaders(out_file, device_info_)) {
        std::cerr << "Failed to write headers to output file." << std::endl;
        return false;
    }

    frame_index_ = 0;
    current_offset_ = 92;
    frame_packages_.clear();
    uint64_t last_timestamp = 0;

    for (const auto& pkt_data : all_raw_packets) {
        PacketInfo info = PacketParser::parseRawUdpPacket(pkt_data);
        if (info.payload.empty()) continue;
        if (info.src_port == 56300) {
            if (info.payload.size() >= 36) {
                uint64_t timestamp = getTimestampFromPayload(info.payload);
                if (last_timestamp == 0 || timestamp - last_timestamp >= ns_threshold_) {
                    if (!frame_packages_.empty()) {
                        uint32_t frame_size = 0;
                        for (const auto& pkg : frame_packages_) frame_size += pkg.size();
                        uint64_t next_offset = current_offset_ + 24 + frame_size;
                        if (!LVX2Writer::writeFrameHeader(out_file, current_offset_, next_offset, frame_index_)) {
                            std::cerr << "Failed to write frame header." << std::endl;
                            return false;
                        }
                        for (const auto& pkg : frame_packages_) {
                            out_file.write(reinterpret_cast<const char*>(pkg.data()), pkg.size());
                            if (out_file.fail()) {
                                std::cerr << "Failed to write frame data." << std::endl;
                                return false;
                            }
                        }
                        current_offset_ = next_offset;
                        frame_index_++;
                        frame_packages_.clear();
                    }
                    last_timestamp = timestamp;
                }
                std::vector<uint8_t> data(info.payload.begin() + 36, info.payload.end());
                auto pkg_header = LVX2Writer::createPackageHeader(info.payload, data.size(), device_info_);
                if (pkg_header.empty()) {
                    std::cerr << "Failed to create package header." << std::endl;
                    return false;
                }
                std::vector<uint8_t> pkg(pkg_header);
                pkg.insert(pkg.end(), data.begin(), data.end());
                frame_packages_.push_back(pkg);
            }
        }
    }

    if (!frame_packages_.empty()) {
        uint32_t frame_size = 0;
        for (const auto& pkg : frame_packages_) frame_size += pkg.size();
        uint64_t next_offset = current_offset_ + 24 + frame_size;
        if (!LVX2Writer::writeFrameHeader(out_file, current_offset_, next_offset, frame_index_)) {
            std::cerr << "Failed to write final frame header." << std::endl;
            return false;
        }
        for (const auto& pkg : frame_packages_) {
            out_file.write(reinterpret_cast<const char*>(pkg.data()), pkg.size());
            if (out_file.fail()) {
                std::cerr << "Failed to write final frame data." << std::endl;
                return false;
            }
        }
    }

    out_file.close();
    //std::cout << "Conversion completed successfully. Output file: " << output_file_ << std::endl;
    return true;
}