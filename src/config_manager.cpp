#include "config_manager.h"
#include <fstream>
#include <shlobj.h>
#pragma comment(lib, "Shell32.lib")

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager() {
    // 配置文件路径: %APPDATA%\pcap_to_lvx2\config.ini
    wchar_t* appdata = nullptr;
    if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) == S_OK) {
        // 转换为 std::filesystem::path 并处理路径
        std::filesystem::path config_dir = std::filesystem::path(appdata) / "pcap_to_lvx2";
        config_path_ = (config_dir / "editcap_path.ini").string(); // 显式转换为 string

        // 创建目录
        std::filesystem::create_directories(config_dir);
        CoTaskMemFree(appdata);
    }
}

std::string ConfigManager::getEditcapPath() const {
    if (!std::filesystem::exists(config_path_)) return "";

    std::ifstream file(config_path_);
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("editcap_path=") == 0) {
            return line.substr(13); // 跳过"editcap_path="
        }
    }
    return "";
}

void ConfigManager::setEditcapPath(const std::string& path) {
    std::ofstream file(config_path_, std::ios::out | std::ios::trunc);
    if (file) {
        file << "editcap_path=" << path << "\n";
    }
}