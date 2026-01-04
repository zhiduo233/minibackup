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

    // --- 元数据 ---
    uint32_t mode = 0;   // 权限
    int64_t mtime = 0;   // 修改时间 (时间戳)
    uint32_t uid = 0;    // 用户ID
    uint32_t gid = 0;    // 组ID
};

// [新增] 加密模式枚举
enum class EncryptionMode {
    NONE, // 不加密
    XOR,  // 简单异或 (算法1)
    RC4   // RC4 流密码 (算法2 - 进阶)
};

// 压缩模式枚举
enum class CompressionMode {
    NONE,
    RLE
};

struct FilterOptions {
    // 1. 名字筛选 : 如果不为空，只备份文件名包含此字符串的文件
    std::string nameContains;

    // 2. 路径筛选: 如果不为空，只备份路径包含此字符串的文件
    std::string pathContains;

    // 3. 类型筛选: 如果不为 -1，只备份指定类型 (0=File, 1=Dir, 2=Link)
    int type = -1;

    // 4. 尺寸筛选: 只备份大小 >= minSize 且 <= maxSize 的文件
    // 0 表示不限制
    uint64_t minSize = 0;
    uint64_t maxSize = 0;

    // 5. 时间筛选: 只备份修改时间 >= startTime (Unix时间戳) 的文件
    long long startTime = 0;

    // 6. 用户筛选: 只备份属于指定 UID (User ID) 的文件 (-1表示不限制)
    int targetUid = -1;
};

class BackupEngine {
public:
    // === 基础功能 ===
    static void backup(const std::string& srcPath, const std::string& destPath);
    static std::string verify(const std::string& dest);
    static void restore(const std::string& srcPath, const std::string& destPath);

    // === 扩展功能：打包/解包 (含加密) ===

    // pack: 支持指定密码和加密模式
    static void pack(const std::string& srcPath, const std::string& outputFile,
                     const std::string& password = "",
                     EncryptionMode encMode = EncryptionMode::NONE,
                     const FilterOptions& filter = FilterOptions(),
                     CompressionMode compMode = CompressionMode::NONE); // 默认全选

    // unpack: 只需要密码，模式由文件头自动识别
    static void unpack(const std::string& packFile, const std::string& destPath,
                       const std::string& password = "");

private:
    // 内部辅助函数
    static std::vector<FileRecord> scanDirectory(const std::string& sourcePath, const FilterOptions& filter);
    static void packFiles(const std::vector<FileRecord>& files, const std::string& outputFile,
                          const std::string& password, EncryptionMode encMode,
                          CompressionMode compMode);
};

#endif //MINIBACKUP_BACKUPENGINE_H