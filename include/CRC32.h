// include/CRC32.h

#ifndef MINIBACKUP_CRC32_H
#define MINIBACKUP_CRC32_H

#include <vector>
#include <string>
#include <fstream>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <filesystem> // [新增]

class CRC32 {
public:
    // 计算内存数据的 CRC32
    static uint32_t calculate(const char* data, size_t size) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            auto byte = static_cast<uint8_t>(data[i]);
            crc ^= byte;
            for (int j = 0; j < 8; ++j) {
                constexpr uint32_t polynomial = 0xEDB88320;
                uint32_t mask = -static_cast<int>(crc & 1);
                crc = (crc >> 1) ^ (polynomial & mask);
            }
        }
        return ~crc;
    }

    // [修改] 参数改为 std::filesystem::path，完美支持中文
    static std::string getFileCRC(const std::filesystem::path& filepath) {
        // 直接传入 path 对象，Windows 下会自动调用宽字符接口
        std::ifstream file(filepath, std::ios::binary);

        // 如果打开失败，返回全0
        if (!file.is_open()) return "00000000";

        char buffer[4096];
        uint32_t crc = 0xFFFFFFFF;

        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            for (std::streamsize i = 0; i < file.gcount(); ++i) {
                auto byte = static_cast<uint8_t>(buffer[i]);
                crc ^= byte;
                for (int j = 0; j < 8; ++j) {
                    constexpr uint32_t polynomial = 0xEDB88320;
                    uint32_t mask = -static_cast<int>(crc & 1);
                    crc = (crc >> 1) ^ (polynomial & mask);
                }
            }
        }
        crc = ~crc;

        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc;
        return ss.str();
    }
};

#endif //MINIBACKUP_CRC32_H