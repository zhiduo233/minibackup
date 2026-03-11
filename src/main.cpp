#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include "BackupEngine.h"

// 简单的 ANSI 颜色，方便助教在 Linux 终端看结果
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"

void printUsage() {
    std::cout << "MiniBackup CLI Tool (Linux/TA Edition)\n"
              << "--------------------------------------\n"
              << "Usage:\n"
              << "  [Basic Mode]\n"
              << "    backup  <src_dir> <dst_dir>          Mirror copy with checksum index\n"
              << "    restore <src_dir> <dst_dir>          Restore from mirror\n"
              << "    verify  <dst_dir>                    Check integrity of mirror\n\n"
              << "  [Pro Mode (Pack/Unpack)]\n"
              << "    pack    <src> <pck_file> [options]   Create archive\n"
              << "    unpack  <pck_file> <dst_dir> [pwd]   Extract archive\n\n"
              << "  [Pack Options]\n"
              << "    -pwd <password>      Set encryption password\n"
              << "    -xor                 Use XOR encryption\n"
              << "    -rc4                 Use RC4 encryption\n"
              << "    -rle                 Enable RLE compression\n"
              << "    -huff                Enable Huffman compression\n"
              << "    -name <str>          Filter by filename (contains)\n"
              << "    -path <str>          Filter by path (contains)\n"
              << "    -min <bytes>         Min file size\n"
              << "    -max <bytes>         Max file size\n"
              << "    -days <n>            Only files modified in last N days\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 0;
    }

    const std::string command = argv[1];

    try {
        // ==========================================
        // 1. Basic Backup (文件夹 -> 文件夹)
        // ==========================================
        if (command == "backup") {
            if (argc < 4) { printUsage(); return 1; }
            BackupEngine::backup(argv[2], argv[3]);

        // ==========================================
        // 2. Basic Restore
        // ==========================================
        } else if (command == "restore") {
            if (argc < 4) { printUsage(); return 1; }
            BackupEngine::restore(argv[2], argv[3]);
            std::cout << GREEN << "Restore complete." << RESET << std::endl;

        // ==========================================
        // 3. Basic Verify
        // ==========================================
        } else if (command == "verify") {
            if (argc < 3) { printUsage(); return 1; }
            std::string result = BackupEngine::verify(argv[2]);
            if (result.empty()) {
                std::cout << GREEN << "[PASS] Integrity Check Passed." << RESET << std::endl;
            } else {
                std::cout << RED << "[FAIL] Integrity Check Failed:" << RESET << "\n" << result << std::endl;
                return 1; // Return error code for scripts
            }

        // ==========================================
        // 4. Pro Pack (高级打包)
        // ==========================================
        } else if (command == "pack") {
            if (argc < 4) {
                std::cerr << "Error: pack requires <src> and <dest>" << std::endl;
                printUsage();
                return 1;
            }

            std::string src = argv[2];
            std::string dest = argv[3];
            std::string pwd = "";
            EncryptionMode enc = EncryptionMode::NONE;
            CompressionMode comp = CompressionMode::NONE;
            FilterOptions filter;
            filter.type = -1;      // Default: All types
            filter.targetUid = -1; // Default: Any UID

            // 解析可选参数
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "-pwd" && i + 1 < argc) {
                    pwd = argv[++i];
                } else if (arg == "-xor") {
                    enc = EncryptionMode::XOR;
                } else if (arg == "-rc4") {
                    enc = EncryptionMode::RC4;
                } else if (arg == "-rle") {
                    comp = CompressionMode::RLE;
                } else if (arg == "-huff") {
                    comp = CompressionMode::HUFFMAN;
                } else if (arg == "-name" && i + 1 < argc) {
                    filter.nameContains = argv[++i];
                } else if (arg == "-path" && i + 1 < argc) {
                    filter.pathContains = argv[++i];
                } else if (arg == "-min" && i + 1 < argc) {
                    filter.minSize = std::stoull(argv[++i]);
                } else if (arg == "-max" && i + 1 < argc) {
                    filter.maxSize = std::stoull(argv[++i]);
                } else if (arg == "-days" && i + 1 < argc) {
                    int days = std::stoi(argv[++i]);
                    if (days > 0) {
                        filter.startTime = std::time(nullptr) - (days * 86400);
                    }
                }
            }

            std::cout << "Packing " << src << " -> " << dest << " ..." << std::endl;
            if (enc != EncryptionMode::NONE) std::cout << "Encryption: Enabled" << std::endl;
            if (comp == CompressionMode::RLE) std::cout << "Compression: RLE" << std::endl;
            else if (comp == CompressionMode::HUFFMAN) std::cout << "Compression: Huffman" << std::endl;

            BackupEngine::pack(src, dest, pwd, enc, filter, comp);
            std::cout << GREEN << "[SUCCESS] Pack created." << RESET << std::endl;

        // ==========================================
        // 5. Pro Unpack (高级解包)
        // ==========================================
        } else if (command == "unpack") {
            if (argc < 4) {
                std::cerr << "Error: unpack requires <pck_file> and <dest>" << std::endl;
                printUsage();
                return 1;
            }
            std::string pck = argv[2];
            std::string dest = argv[3];
            std::string pwd = "";

            // 简单的参数检查，支持 unpack pck dst pwd 这种旧格式，也支持 -pwd
            if (argc >= 5) {
                std::string arg4 = argv[4];
                if (arg4 == "-pwd" && argc >= 6) {
                    pwd = argv[5];
                } else {
                    pwd = arg4; // 兼容旧写法
                }
            }

            std::cout << "Unpacking " << pck << " -> " << dest << " ..." << std::endl;
            BackupEngine::unpack(pck, dest, pwd);
            std::cout << GREEN << "[SUCCESS] Unpack complete & Verified." << RESET << std::endl;

        } else {
            std::cout << RED << "Unknown command: " << command << RESET << std::endl;
            printUsage();
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << RED << "\n[ERROR] Exception occurred: " << e.what() << RESET << std::endl;
        return 1;
    }

    return 0;
}