#pragma once
#include <string>
#include <cstdint>
#include <map>

// 设备类型枚举
enum class LivoxDeviceType {
    MID_360 = 0,
    HAP = 1
};

// 点云数据类型枚举
enum class PointCloudDataType {
    CARTESIAN_32BIT = 1,    // 数据类型1：直角坐标，32位，14字节
    CARTESIAN_16BIT = 2,    // 数据类型2：直角坐标，16位，8字节
    SPHERICAL = 3           // 数据类型3：球坐标，10字节
};

// 点云数据结构
struct PointCloudPoint {
    // 直角坐标 (数据类型1和2)
    float x, y, z;          // 单位：mm (数据类型1) 或 10mm (数据类型2)
    uint8_t reflectivity;   // 反射率
    uint8_t tag;            // 标签
    
    // 球坐标 (数据类型3)
    float depth;             // 深度，单位：mm
    float zenith_angle;      // 天顶角，单位：度
    float azimuth_angle;     // 方位角，单位：度
    
    PointCloudPoint() : x(0), y(0), z(0), reflectivity(0), tag(0), 
                       depth(0), zenith_angle(0), azimuth_angle(0) {}
};

// 设备信息结构
struct DeviceConfig {
    uint16_t point_cloud_port;
    uint16_t push_data_port;  // 推送数据端口
    uint16_t imu_port;        // IMU数据端口
    uint8_t lidar_type;
    uint8_t device_type;
    std::string device_name;
};

// 设备配置映射
static const std::map<LivoxDeviceType, DeviceConfig> DEVICE_CONFIGS = {
    {LivoxDeviceType::MID_360, {56300, 56200, 56400, 247, 9, "Mid-360"}},
    {LivoxDeviceType::HAP, {57000, 56000, 58000, 246, 15, "HAP"}}
};

struct DeviceInfo {
    std::string lidar_sn;
    std::string hub_sn;
    uint32_t lidar_id;
    uint8_t lidar_type;
    uint8_t device_type;
    bool enable_extrinsic;
    float offset_roll, offset_pitch, offset_yaw;
    float offset_x, offset_y, offset_z;

    DeviceInfo()
        : lidar_sn("DEFAULT_LIDAR"), hub_sn("DEFAULT_HUB"), lidar_id(0),
          lidar_type(247), device_type(9), enable_extrinsic(false),
          offset_roll(0), offset_pitch(0), offset_yaw(0),
          offset_x(0), offset_y(0), offset_z(0) {}
    
    // 根据设备类型创建DeviceInfo的静态方法
    static DeviceInfo createForDeviceType(LivoxDeviceType device_type) {
        DeviceInfo info;
        const auto& config = DEVICE_CONFIGS.at(device_type);
        info.lidar_type = config.lidar_type;
        info.device_type = config.device_type;
        return info;
    }
};