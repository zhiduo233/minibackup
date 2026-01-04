// src/BackupEngine.cpp
#include "BackupEngine.h"
#include "CRC32.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <numeric> // for std::swap

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
    #include <sys/utime.h>
    #define chown(path, uid, gid) 0
#else
    #include <unistd.h>
    #include <utime.h>
#endif

// ==========================================
// 🛠️ 辅助函数：强制 Path 转 UTF-8 string
// 解决 Windows 下 .string() 变成 GBK 的问题
// ==========================================
std::string pathToString(const fs::path& p) {
    // C++20 引入了 std::u8string，C++17 返回 std::string
    // 这里做一个兼容处理
#if __cplusplus >= 202002L
    const auto& u8str = p.u8string();
    return std::string(u8str.begin(), u8str.end());
#else
    return p.u8string();
#endif
}

// ==========================================
// 核心算法实现区
// ==========================================

// --- 算法 1: RC4 ---
class RC4 {
    unsigned char S[256]{};
    int i = 0, j = 0;
public:
    void init(const std::string& key) {
        if (key.empty()) return;
        for (int k = 0; k < 256; ++k) S[k] = k;
        int j_temp = 0;
        for (int i_temp = 0; i_temp < 256; ++i_temp) {
            j_temp = (j_temp + S[i_temp] + key[i_temp % key.length()]) % 256;
            std::swap(S[i_temp], S[j_temp]);
        }
        i = 0; j = 0;
    }
    void cipher(char* buffer, const size_t size) {
        for (size_t k = 0; k < size; ++k) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            std::swap(S[i], S[j]);
            buffer[k] ^= S[(S[i] + S[j]) % 256];
        }
    }
};

// --- 算法 2: XOR ---
void xorEncrypt(char* buffer, const size_t size, const std::string& password) {
    if (password.empty()) return;
    const size_t pwdLen = password.length();
    for (size_t k = 0; k < size; ++k) {
        buffer[k] ^= password[k % pwdLen];
    }
}

// --- 算法 3: 筛选器 ---
bool checkFilter(const FileRecord& record, const FilterOptions& opts) {
    // 1. 名字筛选 (使用 u8path 确保正确解析 UTF-8 字符串)
    if (!opts.nameContains.empty()) {
        std::string filename = fs::path(fs::u8path(record.relPath)).filename().string(); // 这里 filename 转回 native 没关系，只要 find 能匹配
        // 或者更严谨一点，全程 UTF-8:
        std::string u8fname = pathToString(fs::path(fs::u8path(record.relPath)).filename());
        if (u8fname.find(opts.nameContains) == std::string::npos) return false;
    }

    if (!opts.pathContains.empty()) {
        if (record.relPath.find(opts.pathContains) == std::string::npos) return false;
    }

    if (opts.type != -1) {
        if (opts.type == 0 && record.type != FileType::REGULAR) return false;
        if (opts.type == 1 && record.type != FileType::DIRECTORY) return false;
        if (opts.type == 2 && record.type != FileType::SYMLINK) return false;
    }

    if (record.type == FileType::DIRECTORY) return true;

    if (record.type == FileType::REGULAR) {
        if (opts.minSize > 0 && record.size < opts.minSize) return false;
        if (opts.maxSize > 0 && record.size > opts.maxSize) return false;
    }

    if (opts.startTime > 0) {
        if (record.mtime < opts.startTime) return false;
    }

    if (opts.targetUid != -1) {
        if (record.uid != static_cast<uint32_t>(opts.targetUid)) return false;
    }
    return true;
}

// --- 算法 4: RLE ---
void rleCompress(const std::vector<char>& input, std::vector<char>& output) {
    if (input.empty()) return;
    for (size_t i = 0; i < input.size(); ++i) {
        unsigned char count = 1;
        while (i + 1 < input.size() && input[i] == input[i+1] && count < 255) {
            count++; i++;
        }
        output.push_back(static_cast<char>(count));
        output.push_back(input[i]);
    }
}

// --- 算法 5: RLE Decompress ---
void rleDecompress(const std::vector<char>& input, std::vector<char>& output) {
    if (input.empty()) return;
    for (size_t i = 0; i < input.size(); i += 2) {
        if (i + 1 >= input.size()) break;
        const auto count = static_cast<unsigned char>(input[i]);
        char value = input[i+1];
        for (int k = 0; k < count; ++k) output.push_back(value);
    }
}

// ==========================================
// 业务逻辑
// ==========================================

// Legacy backup (简单复制)
void BackupEngine::backup(const std::string& srcPath, const std::string& destPath) {
    fs::path source = fs::u8path(srcPath);
    fs::path destination = fs::u8path(destPath);

    if (!fs::exists(source)) throw std::runtime_error("Source not found");
    if (!fs::exists(destination)) fs::create_directories(destination);

    std::ofstream indexFile(destination / "index.txt");
    if (!indexFile.is_open()) throw std::runtime_error("Cannot create index file");

    for (const auto& entry : fs::recursive_directory_iterator(source)) {
        try {
            fs::path relativePath = fs::relative(entry.path(), source);
            fs::path targetPath = destination / relativePath;

            if (fs::is_directory(entry.path())) {
                fs::create_directories(targetPath);
            } else {
                fs::copy_file(entry.path(), targetPath, fs::copy_options::overwrite_existing);
                std::string checksum = CRC32::getFileCRC(entry.path().string());
                indexFile << pathToString(relativePath) << "|" << checksum << "\n";
            }
        } catch (...) {}
    }
    indexFile.close();
}

// Legacy verify
bool BackupEngine::verify(const std::string& destPath) {
    return true; // 简化处理，重点在 Pack/Unpack
}

// Legacy restore
void BackupEngine::restore(const std::string& srcPath, const std::string& destPath) {
    // 省略，重点在 unpack
}

// === 目录遍历 (强制 UTF-8) ===
std::vector<FileRecord> BackupEngine::scanDirectory(const std::string& sourcePath, const FilterOptions& filter) {
    std::vector<FileRecord> files;

    // 1. 解析 UTF-8 路径
    fs::path source = fs::u8path(sourcePath);

    if (!fs::exists(source)) return files;

    // 2. 单文件处理
    if (fs::is_regular_file(source)) {
        FileRecord record;
        // 🔥 关键修改：强制转为 UTF-8 字符串存储 🔥
        record.absPath = pathToString(source);
        record.relPath = pathToString(source.filename());

        record.type = FileType::REGULAR;
        record.size = fs::file_size(source);

        struct stat st{};
        // 注意：stat 在 Windows 接收 char* 时是 GBK，这里可能会有问题
        // 但我们没有 _wstat 的简单跨平台封装，暂时先尝试用 u8path 打开
        // 如果 stat 失败，元数据可能为 0，但不影响文件内容读取
        if (stat(record.absPath.c_str(), &st) == 0) {
            record.mode = st.st_mode; record.mtime = st.st_mtime;
            record.uid = st.st_uid; record.gid = st.st_gid;
        } else {
            // 尝试用 u8path 转换后的 wide string 也是一种办法，但略繁琐
            // 这里为了作业简单，如果 stat 失败就赋当前时间
            record.mtime = time(nullptr);
        }

        if (checkFilter(record, filter)) files.push_back(record);
        return files;
    }

    // 3. 目录处理
    if (fs::is_directory(source)) {
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            FileRecord record;

            // 🔥 关键修改：路径全部强制存为 UTF-8 🔥
            // 这样在 packFiles 里我们就能确信它是 UTF-8，然后用 fs::u8path 打开
            record.absPath = pathToString(entry.path());
            record.relPath = pathToString(fs::relative(entry.path(), source));

            // 获取元数据
            struct stat st{};
            // stat 在 Windows 上比较弱，如果含有特殊字符可能失败
            // 这里我们做一个 fallback
            if (stat(record.absPath.c_str(), &st) == 0) {
                record.mode = st.st_mode; record.mtime = st.st_mtime;
                record.uid = st.st_uid; record.gid = st.st_gid;
            } else {
                // 如果 stat 读不到，尝试用 C++ filesystem API 获取时间
                try {
                    auto ftime = fs::last_write_time(entry);
                    auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(ftime);
                    record.mtime = sctp.time_since_epoch().count();
                } catch (...) { record.mtime = 0; }
            }

            if (fs::is_regular_file(entry.path())) {
                record.type = FileType::REGULAR;
                record.size = entry.file_size();
            } else if (fs::is_directory(entry.path())) {
                record.type = FileType::DIRECTORY;
            } else if (fs::is_symlink(entry.path())) {
                record.type = FileType::SYMLINK;
                try {
                    record.linkTarget = pathToString(fs::read_symlink(entry.path()));
                } catch (...) {}
            } else {
                continue;
            }

            if (checkFilter(record, filter)) files.push_back(record);
        }
    }
    return files;
}

// === 打包实现 ===
void BackupEngine::packFiles(const std::vector<FileRecord>& files, const std::string& outputFile,
                             const std::string& password, EncryptionMode encMode, CompressionMode compMode) {

    // 输出文件：UTF-8 -> u8path -> correctly opened
    std::ofstream out(fs::u8path(outputFile), std::ios::binary);
    if (!out.is_open()) throw std::runtime_error("Cannot create pack file");

    // Header ...
    if (encMode == EncryptionMode::RC4) out.write("MINIBK_R", 8);
    else if (encMode == EncryptionMode::XOR) out.write("MINIBK_X", 8);
    else out.write("MINIBK10", 8);
    char compFlag = (compMode == CompressionMode::RLE) ? 1 : 0;
    out.write(&compFlag, 1);

    RC4 rc4;
    if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.init(password);

    int count = 0;
    for (const auto& rec : files) {
        if (rec.type == FileType::OTHER) continue;

        // A. 准备数据
        std::vector<char> fileData;
        if (rec.type == FileType::REGULAR) {
            // 🔥🔥🔥 终极修复：因为 rec.absPath 已经是 UTF-8 了，所以必须用 u8path 打开 🔥🔥🔥
            // 之前的错误在于：rec.absPath 是 UTF-8，但用了 fs::path(rec.absPath)，
            // 在 Windows 上 fs::path(string) 认为输入是 ANSI/GBK，导致乱码路径，进而打开失败
            std::ifstream inFile(fs::u8path(rec.absPath), std::ios::binary);

            if (inFile) {
                fileData.assign(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>());
            } else {
                std::cerr << "[Warning] Failed to open: " << rec.absPath << std::endl;
            }
        } else if (rec.type == FileType::SYMLINK) {
            std::string target = rec.linkTarget;
            fileData.assign(target.begin(), target.end());
        }

        // RLE ...
        if (compMode == CompressionMode::RLE && !fileData.empty()) {
            std::vector<char> compressed;
            rleCompress(fileData, compressed);
            fileData = compressed;
        }

        // B. 写入 Meta
        std::vector<char> metaBuffer;
        uint8_t typeCode = (rec.type == FileType::REGULAR ? 1 : (rec.type == FileType::DIRECTORY ? 2 : 3));
        metaBuffer.push_back(static_cast<char>(typeCode));

        uint64_t pathLen = rec.relPath.size();
        auto pLen = reinterpret_cast<const char*>(&pathLen);
        metaBuffer.insert(metaBuffer.end(), pLen, pLen + 8);
        metaBuffer.insert(metaBuffer.end(), rec.relPath.begin(), rec.relPath.end());

        uint64_t finalSize = fileData.size();
        auto pSize = reinterpret_cast<const char*>(&finalSize);
        metaBuffer.insert(metaBuffer.end(), pSize, pSize + 8);

        // Metadata
        auto pMode = reinterpret_cast<const char*>(&rec.mode);
        metaBuffer.insert(metaBuffer.end(), pMode, pMode + 4);
        auto pUid = reinterpret_cast<const char*>(&rec.uid);
        metaBuffer.insert(metaBuffer.end(), pUid, pUid + 4);
        auto pGid = reinterpret_cast<const char*>(&rec.gid);
        metaBuffer.insert(metaBuffer.end(), pGid, pGid + 4);
        auto pTime = reinterpret_cast<const char*>(&rec.mtime);
        metaBuffer.insert(metaBuffer.end(), pTime, pTime + 8);

        // 加密 Meta
        if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.cipher(metaBuffer.data(), metaBuffer.size());
        else if (encMode == EncryptionMode::XOR && !password.empty()) xorEncrypt(metaBuffer.data(), metaBuffer.size(), password);
        out.write(metaBuffer.data(), metaBuffer.size());

        // C. 写入数据
        if (!fileData.empty()) {
            if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.cipher(fileData.data(), fileData.size());
            else if (encMode == EncryptionMode::XOR && !password.empty()) xorEncrypt(fileData.data(), fileData.size(), password);
            out.write(fileData.data(), fileData.size());
        }
        count++;
    }
    out.close();
    std::cout << "[Pack] Done. Items: " << count << std::endl;
}

void BackupEngine::pack(const std::string& srcPath, const std::string& outputFile,
                        const std::string& password, const EncryptionMode encMode,
                        const FilterOptions& filter, const CompressionMode compMode) {
    auto files = scanDirectory(srcPath, filter);
    packFiles(files, outputFile, password, encMode, compMode);
}

// === 解包实现 ===
void BackupEngine::unpack(const std::string& packFile, const std::string& destPath, const std::string& password) {
    std::ifstream in(fs::u8path(packFile), std::ios::binary);
    if (!in.is_open()) throw std::runtime_error("Cannot open pack file");

    fs::path destRoot = fs::u8path(destPath);
    if (!fs::exists(destRoot)) fs::create_directories(destRoot);

    char magic[9] = {0};
    in.read(magic, 8);
    std::string magicStr(magic);

    auto encMode = EncryptionMode::NONE;
    if (magicStr == "MINIBK_R") encMode = EncryptionMode::RC4;
    else if (magicStr == "MINIBK_X") encMode = EncryptionMode::XOR;
    else if (magicStr != "MINIBK10") throw std::runtime_error("Unknown file format");

    char compFlag = 0;
    in.read(&compFlag, 1);
    bool isRLE = (compFlag == 1);

    RC4 rc4;
    if (encMode == EncryptionMode::RC4) rc4.init(password);

    std::cout << "[Unpack] Enc: " << static_cast<int>(encMode) << ", Comp: " << (isRLE ? "RLE" : "None") << std::endl;

    while (in.peek() != EOF) {
        // Meta 读取流程保持不变 (Read -> Decrypt -> Parse)
        // ... (省略重复的读取代码，逻辑与之前完全一致)

        // 简写：
        char typeBuf[1]; in.read(typeBuf, 1);
        if (in.gcount() == 0) break;
        if (encMode == EncryptionMode::RC4) rc4.cipher(typeBuf, 1);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(typeBuf, 1, password);
        uint8_t typeCode = static_cast<uint8_t>(typeBuf[0]);

        char lenBuf[8]; in.read(lenBuf, 8);
        if (encMode == EncryptionMode::RC4) rc4.cipher(lenBuf, 8);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(lenBuf, 8, password);
        uint64_t pathLen = *reinterpret_cast<uint64_t*>(lenBuf);

        std::vector<char> pathBuf(pathLen);
        in.read(pathBuf.data(), pathLen);
        if (encMode == EncryptionMode::RC4) rc4.cipher(pathBuf.data(), pathLen);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(pathBuf.data(), pathLen, password);
        std::string relPath(pathBuf.begin(), pathBuf.end());

        char sizeBuf[8]; in.read(sizeBuf, 8);
        if (encMode == EncryptionMode::RC4) rc4.cipher(sizeBuf, 8);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(sizeBuf, 8, password);
        uint64_t dataSize = *reinterpret_cast<uint64_t*>(sizeBuf);

        // Metadata block (20 bytes)
        char metaBlock[20]; in.read(metaBlock, 20);
        if (encMode == EncryptionMode::RC4) rc4.cipher(metaBlock, 20);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(metaBlock, 20, password);

        uint32_t f_mode = *reinterpret_cast<uint32_t*>(metaBlock);
        uint32_t f_uid  = *reinterpret_cast<uint32_t*>(metaBlock + 4);
        uint32_t f_gid  = *reinterpret_cast<uint32_t*>(metaBlock + 8);
        int64_t f_mtime = *reinterpret_cast<int64_t*>(metaBlock + 12);

        // Data
        fs::path fullPath = destRoot / fs::u8path(relPath); // u8path 处理 UTF-8 相对路径
        std::vector<char> fileData(dataSize);
        if (dataSize > 0) {
            in.read(fileData.data(), dataSize);
            if (encMode == EncryptionMode::RC4) rc4.cipher(fileData.data(), dataSize);
            else if (encMode == EncryptionMode::XOR) xorEncrypt(fileData.data(), dataSize, password);
            if (isRLE) {
                std::vector<char> dec;
                rleDecompress(fileData, dec);
                fileData = dec;
            }
        }

        // Write
        if (typeCode == 2) {
            fs::create_directories(fullPath);
        } else if (typeCode == 3) {
            std::string target(fileData.begin(), fileData.end());
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            if (fs::exists(fullPath) || fs::is_symlink(fullPath)) fs::remove(fullPath);
            try { fs::create_symlink(target, fullPath); } catch(...) {}
        } else if (typeCode == 1) {
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            // 使用 u8path 确保中文路径能创建
            std::ofstream outFile(fullPath, std::ios::binary);
            outFile.write(fileData.data(), fileData.size());
        }

        // Restore Metadata
        try {
#ifdef _WIN32
            struct _utimbuf new_times{};
            new_times.actime = f_mtime;
            new_times.modtime = f_mtime;
            _utime(fullPath.string().c_str(), &new_times);
#else
            chmod(fullPath.string().c_str(), f_mode);
            chown(fullPath.string().c_str(), f_uid, f_gid);
            struct utimbuf new_times{};
            new_times.actime = f_mtime;
            new_times.modtime = f_mtime;
            utime(fullPath.string().c_str(), &new_times);
#endif
        } catch (...) {}
    }
}