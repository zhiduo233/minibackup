// include/BackupEngine.h
#ifndef MINIBACKUP_BACKUPENGINE_H
#define MINIBACKUP_BACKUPENGINE_H

#include <string>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

// 定义文件类型
enum class FileType {
    REGULAR,    // 普通文件
    DIRECTORY,  // 目录
    SYMLINK,    // 软链接
    OTHER       // 其他
};

// 定义文件记录结构
struct FileRecord {
    std::string relPath;    // 相对路径
    std::string absPath;    // 绝对路径
    FileType type;          // 类型
    uint64_t size;          // 大小 (或链接长度)
    std::string linkTarget; // 软链接指向的目标
};

// [新增] 加密模式枚举
enum class EncryptionMode {
    NONE, // 不加密
    XOR,  // 简单异或 (算法1)
    RC4   // RC4 流密码 (算法2 - 进阶)
};

class BackupEngine {
public:
    // === 基础功能 ===
    static void backup(const std::string& srcPath, const std::string& destPath);
    static bool verify(const std::string& destPath);
    static void restore(const std::string& srcPath, const std::string& destPath);

    // === 扩展功能：打包/解包 (含加密) ===

    // pack: 支持指定密码和加密模式
    static void pack(const std::string& srcPath, const std::string& outputFile,
                     const std::string& password = "",
                     EncryptionMode mode = EncryptionMode::NONE);

    // unpack: 只需要密码，模式由文件头自动识别
    static void unpack(const std::string& packFile, const std::string& destPath,
                       const std::string& password = "");

private:
    // 内部辅助函数
    static std::vector<FileRecord> scanDirectory(const std::string& srcPath);
    static void packFiles(const std::vector<FileRecord>& files, const std::string& outputFile,
                          const std::string& password, EncryptionMode mode);
};

#endif //MINIBACKUP_BACKUPENGINE_H