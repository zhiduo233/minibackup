// src/BackupEngine.cpp
#include "BackupEngine.h"
#include "CRC32.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <numeric>
#include <chrono> // [新增] 用于时间转换

// [修改] 移除了 sys/stat.h 等底层头文件，改用 C++ 标准库
#ifdef _WIN32
    #include <sys/utime.h>
    #define chown(path, uid, gid) 0
#else
    #include <unistd.h>
    #include <utime.h>
    #include <sys/stat.h>
    #include <sys/types.h>
#endif

// ==========================================
// 🛠️ 辅助工具
// ==========================================
std::string pathToString(const fs::path& p) {
#if __cplusplus >= 202002L
    const auto& u8str = p.u8string();
    return std::string(u8str.begin(), u8str.end());
#else
    return p.u8string();
#endif
}

// 这种方式比 stat/_wstat 更稳定，支持 Windows 中文路径
void fillMetadata(const fs::path& fullPath, FileRecord& record) {
    std::error_code ec; // 用于捕获错误，防止程序崩溃

    // 1. 获取大小
    record.size = fs::file_size(fullPath, ec);
    if (ec) record.size = 0;

    // 2. 获取时间 (这是最稳的写法)
    auto ftime = fs::last_write_time(fullPath, ec);
    if (!ec) {
        // 将 file_time_type 转换为系统时间戳 (Unix Timestamp)
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        record.mtime = sctp.time_since_epoch().count();
    } else {
        record.mtime = 0;
    }

    // 3. 填充默认权限 (Windows 下无实际意义，但为了兼容性保留)
    record.mode = 0644;
    record.uid = 0;
    record.gid = 0;
}

// ==========================================
// 核心算法
// ==========================================
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

void xorEncrypt(char* buffer, const size_t size, const std::string& password) {
    if (password.empty()) return;
    const size_t pwdLen = password.length();
    for (size_t k = 0; k < size; ++k) {
        buffer[k] ^= password[k % pwdLen];
    }
}

// 筛选器逻辑
bool checkFilter(const FileRecord& record, const FilterOptions& opts) {
    // 1. 文件名筛选
    if (!opts.nameContains.empty()) {
        std::string u8fname = pathToString(fs::path(fs::u8path(record.relPath)).filename());
        if (u8fname.find(opts.nameContains) == std::string::npos) return false;
    }
    // 2. 路径筛选
    if (!opts.pathContains.empty()) {
        if (record.relPath.find(opts.pathContains) == std::string::npos) return false;
    }
    // 3. 类型筛选
    if (opts.type != -1) {
        if (opts.type == 0 && record.type != FileType::REGULAR) return false;
        if (opts.type == 1 && record.type != FileType::DIRECTORY) return false;
        if (opts.type == 2 && record.type != FileType::SYMLINK) return false;
    }

    if (record.type == FileType::DIRECTORY) return true;

    // 4. 大小筛选 (只针对文件)
    if (record.type == FileType::REGULAR) {
        // 比如 minSize=1000, size=500 -> 500 < 1000 -> false (过滤掉)
        if (opts.minSize > 0 && record.size < opts.minSize) return false;
        if (opts.maxSize > 0 && record.size > opts.maxSize) return false;
    }

    // 5. 时间筛选
    // opts.startTime 是 "现在减去X天" 的时间戳
    // 如果文件的修改时间(mtime) 小于 startTime，说明文件太旧了
    if (opts.startTime > 0) {
        if (record.mtime < opts.startTime) return false;
    }

    return true;
}

// RLE
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
// 业务逻辑 (Backup, Restore, Verify)
// ==========================================

// 1. 基础备份 (支持单文件)
void BackupEngine::backup(const std::string& srcPath, const std::string& destPath) {
    fs::path source = fs::u8path(srcPath);
    fs::path destination = fs::u8path(destPath);

    if (!fs::exists(source)) throw std::runtime_error("Source not found");
    if (!fs::exists(destination)) fs::create_directories(destination);

    std::ofstream indexFile(destination / "index.txt");
    if (!indexFile.is_open()) throw std::runtime_error("Cannot create index file");

    std::cout << "Scanning and backing up..." << std::endl;
    int successCount = 0;

    auto processOneFile = [&](const fs::path& filePath, const fs::path& relPath) {
        fs::path targetPath = destination / relPath;
        if (targetPath.has_parent_path()) fs::create_directories(targetPath.parent_path());
        fs::copy_file(filePath, targetPath, fs::copy_options::overwrite_existing);

        // 使用 path 传递给 CRC32
        std::string checksum = CRC32::getFileCRC(filePath);
        indexFile << pathToString(relPath) << "|" << checksum << "\n";

        std::cout << "  [OK] " << relPath.string() << std::endl;
        successCount++;
    };

    if (fs::is_regular_file(source)) {
        processOneFile(source, source.filename());
    } else if (fs::is_directory(source)) {
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            try {
                fs::path relativePath = fs::relative(entry.path(), source);
                if (fs::is_directory(entry.path())) {
                    fs::create_directories(destination / relativePath);
                } else {
                    processOneFile(entry.path(), relativePath);
                }
            } catch (...) {}
        }
    }
    indexFile.close();
    std::cout << "[Backup] Complete. Success: " << successCount << std::endl;
}

// 2. 基础校验 (返回 string 错误信息)
std::string BackupEngine::verify(const std::string& destPath) {
    fs::path destination = fs::u8path(destPath);
    fs::path indexFilePath = destination / "index.txt";

    if (!fs::exists(indexFilePath)) return "错误：找不到 index.txt 索引文件";

    std::ifstream indexFile(indexFilePath);
    std::string line;
    std::stringstream errorMsg;
    int errorCount = 0;

    while (std::getline(indexFile, line)) {
        if (line.empty()) continue;
        size_t delimiterPos = line.find('|');
        if (delimiterPos == std::string::npos) continue;

        std::string relPath = line.substr(0, delimiterPos);
        std::string expectedCRC = line.substr(delimiterPos + 1);
        fs::path currentFile = destination / fs::u8path(relPath);

        try {
            if (!fs::exists(currentFile)) {
                errorMsg << "❌ 丢失: " << relPath << "\n";
                errorCount++;
                continue;
            }
            std::string actualCRC = CRC32::getFileCRC(currentFile);
            if (actualCRC != expectedCRC) {
                errorMsg << "❌ 篡改: " << relPath << "\n";
                errorCount++;
            }
        } catch (...) { errorCount++; }
    }
    return (errorCount > 0) ? errorMsg.str() : "";
}

// 3. 基础恢复
void BackupEngine::restore(const std::string& srcPath, const std::string& destPath) {
    const fs::path backupDir = fs::u8path(srcPath);
    const fs::path targetDir = fs::u8path(destPath);
    if (!fs::exists(targetDir)) fs::create_directories(targetDir);

    for (const auto& entry : fs::recursive_directory_iterator(backupDir)) {
        try {
            fs::path relativePath = fs::relative(entry.path(), backupDir);
            if (relativePath.filename() == "index.txt") continue;

            fs::path targetPath = targetDir / relativePath;
            if (fs::is_directory(entry.path())) {
                fs::create_directories(targetPath);
            } else {
                fs::copy_file(entry.path(), targetPath, fs::copy_options::overwrite_existing);
            }
        } catch (...) {}
    }
}

// ==========================================
// 4. 高级打包
// ==========================================

std::vector<FileRecord> BackupEngine::scanDirectory(const std::string& sourcePath, const FilterOptions& filter) {
    std::vector<FileRecord> files;
    fs::path source = fs::u8path(sourcePath);

    if (!fs::exists(source)) return files;

    // 单文件
    if (fs::is_regular_file(source)) {
        FileRecord record;
        record.absPath = pathToString(source);
        record.relPath = pathToString(source.filename());
        record.type = FileType::REGULAR;

        // 🔥 调用新的元数据获取逻辑
        fillMetadata(source, record);

        if (checkFilter(record, filter)) files.push_back(record);
        return files;
    }

    // 目录
    if (fs::is_directory(source)) {
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            FileRecord record;
            record.absPath = pathToString(entry.path());
            record.relPath = pathToString(fs::relative(entry.path(), source));

            // 🔥 调用新的元数据获取逻辑
            fillMetadata(entry.path(), record);

            if (fs::is_regular_file(entry.path())) {
                record.type = FileType::REGULAR;
            } else if (fs::is_directory(entry.path())) {
                record.type = FileType::DIRECTORY;
                record.size = 0;
            } else if (fs::is_symlink(entry.path())) {
                record.type = FileType::SYMLINK;
                record.size = 0;
                try { record.linkTarget = pathToString(fs::read_symlink(entry.path())); } catch (...) {}
            } else { continue; }

            if (checkFilter(record, filter)) files.push_back(record);
        }
    }
    return files;
}

// 打包 Files
void BackupEngine::packFiles(const std::vector<FileRecord>& files, const std::string& outputFile,
                             const std::string& password, EncryptionMode encMode, CompressionMode compMode) {

    std::ofstream out(fs::u8path(outputFile), std::ios::binary);
    if (!out.is_open()) throw std::runtime_error("Cannot create pack file");

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

        std::vector<char> fileData;
        if (rec.type == FileType::REGULAR) {
            std::ifstream inFile(fs::u8path(rec.absPath), std::ios::binary);
            if (inFile) {
                fileData.assign(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>());
            }
        } else if (rec.type == FileType::SYMLINK) {
            std::string target = rec.linkTarget;
            fileData.assign(target.begin(), target.end());
        }

        if (compMode == CompressionMode::RLE && !fileData.empty()) {
            std::vector<char> compressed;
            rleCompress(fileData, compressed);
            fileData = compressed;
        }

        uint32_t fileCRC = 0;
        if (!fileData.empty()) {
            fileCRC = CRC32::calculate(fileData.data(), fileData.size());
        }

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

        auto pCRC = reinterpret_cast<const char*>(&fileCRC);
        metaBuffer.insert(metaBuffer.end(), pCRC, pCRC + 4);

        auto pMode = reinterpret_cast<const char*>(&rec.mode);
        metaBuffer.insert(metaBuffer.end(), pMode, pMode + 4);
        auto pUid = reinterpret_cast<const char*>(&rec.uid);
        metaBuffer.insert(metaBuffer.end(), pUid, pUid + 4);
        auto pGid = reinterpret_cast<const char*>(&rec.gid);
        metaBuffer.insert(metaBuffer.end(), pGid, pGid + 4);
        auto pTime = reinterpret_cast<const char*>(&rec.mtime);
        metaBuffer.insert(metaBuffer.end(), pTime, pTime + 8);

        if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.cipher(metaBuffer.data(), metaBuffer.size());
        else if (encMode == EncryptionMode::XOR && !password.empty()) xorEncrypt(metaBuffer.data(), metaBuffer.size(), password);
        out.write(metaBuffer.data(), metaBuffer.size());

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

// 解包
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

    while (in.peek() != EOF) {
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

        char crcBuf[4]; in.read(crcBuf, 4);
        if (encMode == EncryptionMode::RC4) rc4.cipher(crcBuf, 4);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(crcBuf, 4, password);
        uint32_t expectedCRC = *reinterpret_cast<uint32_t*>(crcBuf);

        char metaBlock[20]; in.read(metaBlock, 20);
        if (encMode == EncryptionMode::RC4) rc4.cipher(metaBlock, 20);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(metaBlock, 20, password);

        uint32_t f_mode = *reinterpret_cast<uint32_t*>(metaBlock);
        uint32_t f_uid  = *reinterpret_cast<uint32_t*>(metaBlock + 4);
        uint32_t f_gid  = *reinterpret_cast<uint32_t*>(metaBlock + 8);
        int64_t f_mtime = *reinterpret_cast<int64_t*>(metaBlock + 12);

        fs::path fullPath = destRoot / fs::u8path(relPath);
        std::vector<char> fileData(dataSize);
        if (dataSize > 0) {
            in.read(fileData.data(), dataSize);
            if (encMode == EncryptionMode::RC4) rc4.cipher(fileData.data(), dataSize);
            else if (encMode == EncryptionMode::XOR) xorEncrypt(fileData.data(), dataSize, password);

            uint32_t actualCRC = CRC32::calculate(fileData.data(), dataSize);
            if (actualCRC != expectedCRC) {
                std::cerr << "[Error] CRC Mismatch: " << relPath << std::endl;
            }

            if (isRLE) {
                std::vector<char> dec;
                rleDecompress(fileData, dec);
                fileData = dec;
            }
        }

        if (typeCode == 2) {
            fs::create_directories(fullPath);
        } else if (typeCode == 3) {
            std::string target(fileData.begin(), fileData.end());
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            if (fs::exists(fullPath) || fs::is_symlink(fullPath)) fs::remove(fullPath);
            try { fs::create_symlink(target, fullPath); } catch(...) {}
        } else if (typeCode == 1) {
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            std::ofstream outFile(fullPath, std::ios::binary);
            outFile.write(fileData.data(), fileData.size());
        }

        try {
#ifdef _WIN32
            struct __utimbuf64 new_times{}; // 双下划线
            new_times.actime = f_mtime;
            new_times.modtime = f_mtime;
            _wutime64(fullPath.c_str(), &new_times);
#else
            chmod(fullPath.c_str(), f_mode);
            chown(fullPath.c_str(), f_uid, f_gid);
            struct utimbuf new_times{};
            new_times.actime = f_mtime;
            new_times.modtime = f_mtime;
            utime(fullPath.c_str(), &new_times);
#endif
        } catch (...) {}
    }
}