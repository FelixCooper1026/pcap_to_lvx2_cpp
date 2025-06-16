#pragma once
#include <string>
#include <cstdint>

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
};