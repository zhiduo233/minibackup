// src/main.cpp
#include <iostream>
#include <string>
#include "BackupEngine.h"

void printUsage() {
    std::cout << "Usage:\n"
              << "  minibackup backup <src> <dest>\n"
              << "  minibackup restore <backup_dir> <dest>\n"
              << "  minibackup verify <backup_dir>\n"
              << "  minibackup pack <src> <file.pck> [password] [-rc4|-xor]\n"
              << "  minibackup unpack <file.pck> <dest> [password]\n";
}

int main(const int argc, char* argv[]) {
    if (argc < 3) {
        printUsage();
        return 1;
    }

    const std::string command = argv[1];

    try {
        if (command == "backup") {
            if (argc < 4) { printUsage(); return 1; }
            BackupEngine::backup(argv[2], argv[3]);

        } else if (command == "restore") {
            if (argc < 4) { printUsage(); return 1; }
            BackupEngine::restore(argv[2], argv[3]);

        } else if (command == "verify") {
            if (BackupEngine::verify(argv[2])) {
                std::cout << "Verification Passed." << std::endl;
                return 0;
            }
            std::cerr << "Verification Failed." << std::endl;
            return -1;
        } else if (command == "pack") {
            if (argc < 4) {
                std::cerr << "Missing args for pack.\n";
                return 1;
            }
            // 解析可选参数
            std::string pwd = (argc >= 5) ? argv[4] : "";
            std::string algFlag = (argc >= 6) ? argv[5] : "";

            EncryptionMode mode = EncryptionMode::NONE;
            if (!pwd.empty()) {
                // 如果有密码，默认 XOR，指定 -rc4 则用 RC4
                if (algFlag == "-rc4") mode = EncryptionMode::RC4;
                else mode = EncryptionMode::XOR;
            }

            BackupEngine::pack(argv[2], argv[3], pwd, mode);

        } else if (command == "unpack") {
            if (argc < 4) {
                std::cerr << "Missing args for unpack.\n";
                return 1;
            }
            std::string pwd = (argc >= 5) ? argv[4] : "";
            BackupEngine::unpack(argv[2], argv[3], pwd);

        } else {
            std::cerr << "Unknown command.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[Fatal Error] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}