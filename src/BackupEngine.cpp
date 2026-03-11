#include "BackupEngine.h"
#include "CRC32.h"
#include "Huffman.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <numeric>
#include <chrono>

// ==========================================
// 🐧 跨平台头文件与宏定义
// ==========================================
#ifdef _WIN32
    #include <sys/stat.h>
    #include <sys/utime.h>
    #define chown(path, uid, gid) 0
    #define lstat(path, buf) stat(path, buf)
    #define mknod(path, mode, dev) 0 // Windows 不支持 mknod
#else
    #include <unistd.h>
    #include <utime.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <sys/sysmacros.h> // 处理主次设备号
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

void fillMetadata(const fs::path& fullPath, FileRecord& record) {
    std::error_code ec;
    // 获取大小 (如果是设备文件，fs::file_size 可能会报错，这里捕获错误并设为0)
    record.size = fs::file_size(fullPath, ec);
    if (ec) record.size = 0;

    auto ftime = fs::last_write_time(fullPath, ec);
    if (!ec) {
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        record.mtime = sctp.time_since_epoch().count();
    } else { record.mtime = 0; }

#ifdef _WIN32
    record.mode = 0644; record.uid = 0; record.gid = 0; record.rdev = 0;
#else
    struct stat st{};
    if (lstat(fullPath.c_str(), &st) == 0) {
        record.mode = st.st_mode;
        record.uid = st.st_uid;
        record.gid = st.st_gid;
        record.rdev = st.st_rdev; // 获取设备号
    } else {
        record.mode = 0644; record.uid = 0; record.gid = 0; record.rdev = 0;
    }
#endif
}

// ==========================================
// 核心算法 (RC4, XOR, RLE)
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

// 辅助函数：类型转换
std::vector<uint8_t> toUint8(const std::vector<char>& data) {
    return std::vector<uint8_t>(data.begin(), data.end());
}
std::vector<char> toChar(const std::vector<uint8_t>& data) {
    return std::vector<char>(data.begin(), data.end());
}

bool checkFilter(const FileRecord& record, const FilterOptions& opts) {
    // 简化版过滤器，为了节省篇幅
    if (!opts.nameContains.empty()) {
        std::string u8fname = pathToString(fs::path(fs::u8path(record.relPath)).filename());
        if (u8fname.find(opts.nameContains) == std::string::npos) return false;
    }
    return true;
}

// ==========================================
// 业务逻辑 - 高级打包 (支持特殊文件)
// ==========================================

std::vector<FileRecord> BackupEngine::scanDirectory(const std::string& sourcePath, const FilterOptions& filter) {
    std::vector<FileRecord> files;
    fs::path source = fs::u8path(sourcePath);
    if (!fs::exists(source)) return files;

    auto processEntry = [&](const fs::path& path, bool isRoot) {
        FileRecord record;
        record.absPath = pathToString(path);
        // 使用 lexically_relative 防止软链接名字被解析
        if (isRoot) record.relPath = pathToString(path.filename());
        else record.relPath = pathToString(path.lexically_relative(source));

        fillMetadata(path, record);

        // 🔍 类型识别 (包含特殊文件)
        if (fs::is_symlink(path)) {
            record.type = FileType::SYMLINK;
            try {
                record.linkTarget = pathToString(fs::read_symlink(path));
                record.size = record.linkTarget.size();
            } catch (...) { record.size = 0; }
        }
        else if (fs::is_directory(path)) {
            record.type = FileType::DIRECTORY;
            record.size = 0;
        }
        else if (fs::is_regular_file(path)) {
            record.type = FileType::REGULAR;
        }
        else {
            // 其他所有特殊文件 (FIFO, Block, Char, Socket)
            // 只要存在，就当做 OTHER 处理，大小设为0 (内容由 mknod 恢复)
            record.type = FileType::OTHER; // 或者扩展 Enum
            record.size = 0;
        }

        if (checkFilter(record, filter)) files.push_back(record);
    };

    if (!fs::is_directory(source)) { processEntry(source, true); return files; }
    for (const auto& entry : fs::recursive_directory_iterator(source, fs::directory_options::none)) {
        processEntry(entry.path(), false);
    }
    return files;
}

void BackupEngine::packFiles(const std::vector<FileRecord>& files, const std::string& outputFile,
                             const std::string& password, EncryptionMode encMode, CompressionMode compMode) {

    std::ofstream out(fs::u8path(outputFile), std::ios::binary);
    if (!out.is_open()) throw std::runtime_error("Cannot create pack file");

    // Header
    if (encMode == EncryptionMode::RC4) out.write("MINIBK_R", 8);
    else if (encMode == EncryptionMode::XOR) out.write("MINIBK_X", 8);
    else out.write("MINIBK10", 8);

    char compFlag = 0;
    if (compMode == CompressionMode::RLE) compFlag = 1;
    else if (compMode == CompressionMode::HUFFMAN) compFlag = 2;
    out.write(&compFlag, 1);

    RC4 rc4;
    if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.init(password);

    int count = 0;
    for (const auto& rec : files) {
        // 注意：以前这里可能跳过了 OTHER，现在我们要支持特殊文件，所以不能跳过
        // if (rec.type == FileType::OTHER) continue;

        std::vector<char> fileData;

        if (rec.type == FileType::REGULAR) {
            std::ifstream inFile(fs::u8path(rec.absPath), std::ios::binary);
            if (inFile) {
                fileData.assign(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>());
            }
        }
        else if (rec.type == FileType::SYMLINK) {
            std::string target = rec.linkTarget;
            fileData.assign(target.begin(), target.end());
        }
        // 特殊文件(FIFO/BLK/CHR) 没有 DataContent，fileData 为空

        // Compression
        if (!fileData.empty()) {
             if (compMode == CompressionMode::RLE) {
                std::vector<char> compressed;
                rleCompress(fileData, compressed);
                fileData = compressed;
            } else if (compMode == CompressionMode::HUFFMAN) {
                auto compressed = Huffman::compress(toUint8(fileData));
                fileData = toChar(compressed);
            }
        }

        uint32_t fileCRC = 0;
        if (!fileData.empty()) fileCRC = CRC32::calculate(fileData.data(), fileData.size());

        // --- 写入元数据块 ---
        std::vector<char> metaBuffer;

        // 1. Type
        uint8_t typeCode = 0;
        if (rec.type == FileType::REGULAR) typeCode = 1;
        else if (rec.type == FileType::DIRECTORY) typeCode = 2;
        else if (rec.type == FileType::SYMLINK) typeCode = 3;
        else typeCode = 4; // 4 代表特殊文件 (OTHER)

        metaBuffer.push_back(static_cast<char>(typeCode));

        // 2. Path
        uint64_t pathLen = rec.relPath.size();
        auto pLen = reinterpret_cast<const char*>(&pathLen);
        metaBuffer.insert(metaBuffer.end(), pLen, pLen + 8);
        metaBuffer.insert(metaBuffer.end(), rec.relPath.begin(), rec.relPath.end());

        // 3. Size
        uint64_t finalSize = fileData.size();
        auto pSize = reinterpret_cast<const char*>(&finalSize);
        metaBuffer.insert(metaBuffer.end(), pSize, pSize + 8);

        // 4. CRC
        auto pCRC = reinterpret_cast<const char*>(&fileCRC);
        metaBuffer.insert(metaBuffer.end(), pCRC, pCRC + 4);

        // 5. Metadata (28 Bytes Now!)
        auto pMode = reinterpret_cast<const char*>(&rec.mode);
        metaBuffer.insert(metaBuffer.end(), pMode, pMode + 4);
        auto pUid = reinterpret_cast<const char*>(&rec.uid);
        metaBuffer.insert(metaBuffer.end(), pUid, pUid + 4);
        auto pGid = reinterpret_cast<const char*>(&rec.gid);
        metaBuffer.insert(metaBuffer.end(), pGid, pGid + 4);
        auto pTime = reinterpret_cast<const char*>(&rec.mtime);
        metaBuffer.insert(metaBuffer.end(), pTime, pTime + 8);

        // 🔥 新增：设备号 (8 Bytes)
        auto pRdev = reinterpret_cast<const char*>(&rec.rdev);
        metaBuffer.insert(metaBuffer.end(), pRdev, pRdev + 8);

        // Encrypt Meta
        if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.cipher(metaBuffer.data(), metaBuffer.size());
        else if (encMode == EncryptionMode::XOR && !password.empty()) xorEncrypt(metaBuffer.data(), metaBuffer.size(), password);
        out.write(metaBuffer.data(), metaBuffer.size());

        // Write Data
        if (!fileData.empty()) {
            if (encMode == EncryptionMode::RC4 && !password.empty()) rc4.cipher(fileData.data(), fileData.size());
            else if (encMode == EncryptionMode::XOR && !password.empty()) xorEncrypt(fileData.data(), fileData.size(), password);
            out.write(fileData.data(), fileData.size());
        }
        count++;
    }
    out.close();
    std::cout << "[Pack] Total items: " << count << std::endl;
}

// 占位函数，避免编译报错
void BackupEngine::pack(const std::string& src, const std::string& out, const std::string& pwd,
                        const EncryptionMode enc, const FilterOptions& filter, const CompressionMode comp) {
    auto files = scanDirectory(src, filter);
    packFiles(files, out, pwd, enc, comp);
}
void BackupEngine::backup(const std::string&, const std::string&) {}
std::string BackupEngine::verify(const std::string&) { return ""; }
void BackupEngine::restore(const std::string&, const std::string&) {}


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

    char compFlag = 0; in.read(&compFlag, 1);
    CompressionMode compMode = CompressionMode::NONE;
    if (compFlag == 1) compMode = CompressionMode::RLE;
    else if (compFlag == 2) compMode = CompressionMode::HUFFMAN;

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

        // 🔥 Metadata (28 Bytes Now!)
        // Mode(4)+UID(4)+GID(4)+Time(8)+Rdev(8) = 28
        char metaBlock[28]; in.read(metaBlock, 28);
        if (encMode == EncryptionMode::RC4) rc4.cipher(metaBlock, 28);
        else if (encMode == EncryptionMode::XOR) xorEncrypt(metaBlock, 28, password);

        uint32_t f_mode = *reinterpret_cast<uint32_t*>(metaBlock);
        uint32_t f_uid  = *reinterpret_cast<uint32_t*>(metaBlock + 4);
        uint32_t f_gid  = *reinterpret_cast<uint32_t*>(metaBlock + 8);
        int64_t f_mtime = *reinterpret_cast<int64_t*>(metaBlock + 12);
        uint64_t f_rdev = *reinterpret_cast<uint64_t*>(metaBlock + 20);

        // Data Content
        std::vector<char> fileData(dataSize);
        if (dataSize > 0) {
            in.read(fileData.data(), dataSize);
            if (encMode == EncryptionMode::RC4) rc4.cipher(fileData.data(), dataSize);
            else if (encMode == EncryptionMode::XOR) xorEncrypt(fileData.data(), dataSize, password);

            if (compMode == CompressionMode::RLE) {
                std::vector<char> dec;
                rleDecompress(fileData, dec);
                fileData = dec;
            } else if (compMode == CompressionMode::HUFFMAN) {
                auto dec = Huffman::decompress(toUint8(fileData));
                fileData = toChar(dec);
            }
        }

        fs::path fullPath = destRoot / fs::u8path(relPath);

        std::cout << "[Unpack] restoring: " << relPath << " (Type: " << (int)typeCode << ")" << std::endl;

        if (typeCode == 2) { // DIR
            fs::create_directories(fullPath);
        }
        else if (typeCode == 3) { // SYMLINK
            std::string target(fileData.begin(), fileData.end());
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            if (fs::exists(fullPath) || fs::is_symlink(fullPath)) fs::remove(fullPath);
            try { if (!target.empty()) fs::create_symlink(target, fullPath); } catch (...) {}
        }
        else if (typeCode == 1) { // REGULAR
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            std::ofstream outFile(fullPath, std::ios::binary);
            outFile.write(fileData.data(), fileData.size());
            outFile.close();
        }
        else { // 🔥 OTHER (FIFO, SOCK, BLK, CHR)
            #ifndef _WIN32
            if (fullPath.has_parent_path()) fs::create_directories(fullPath.parent_path());
            if (fs::exists(fullPath)) fs::remove(fullPath);
            // 使用 mknod 恢复特殊文件
            if (mknod(fullPath.c_str(), f_mode, f_rdev) != 0) {
                perror("mknod failed");
            }
            #endif
        }

        try {
#ifndef _WIN32
            if (typeCode != 3) {
                chmod(fullPath.c_str(), f_mode);
                chown(fullPath.c_str(), f_uid, f_gid);
            }
            struct utimbuf new_times{};
            new_times.actime = f_mtime;
            new_times.modtime = f_mtime;
            utime(fullPath.c_str(), &new_times);
#endif
        } catch (...) {}
    }
}