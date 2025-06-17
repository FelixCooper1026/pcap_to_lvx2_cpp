#pragma once
#include <string>
#include <filesystem>

class ConfigManager {
public:
    static ConfigManager& getInstance();

    std::string getEditcapPath() const;
    void setEditcapPath(const std::string& path);

private:
    ConfigManager();
    std::string config_path_;
};