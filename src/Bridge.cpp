// src/Bridge.cpp
#include "BackupEngine.h"
#include <cstring>

// === 跨平台导出宏定义 ===
// 如果是 Windows，需要声明 "这是要导出给别人用的函数" (dllexport)
// 如果是 Linux/Mac，默认就是导出的，这里留空即可
#ifdef _WIN32
    #define LIBRARY_API __declspec(dllexport)
#else
    #define LIBRARY_API
#endif

extern "C" {

    // 1. 备份接口
    // 在每个函数前加上 LIBRARY_API
    LIBRARY_API int C_Backup(const char* src, const char* dest) {
        try {
            BackupEngine::backup(src, dest);
            return 1;
        } catch (...) {
            return 0;
        }
    }

    // 2. 还原接口
    LIBRARY_API int C_Restore(const char* src, const char* dest) {
        try {
            BackupEngine::restore(src, dest);
            return 1;
        } catch (...) {
            return 0;
        }
    }

    // 3. 验证接口
    LIBRARY_API int C_Verify(const char* backupDir) {
        try {
            return BackupEngine::verify(backupDir) ? 1 : 0;
        } catch (...) {
            return 0;
        }
    }

    // 4. 打包接口
    LIBRARY_API int C_Pack(const char* src, const char* pckFile, const char* pwd, int mode) {
        try {
            EncryptionMode cppMode = EncryptionMode::NONE;
            if (mode == 1) cppMode = EncryptionMode::XOR;
            else if (mode == 2) cppMode = EncryptionMode::RC4;

            BackupEngine::pack(src, pckFile, pwd, cppMode);
            return 1;
        } catch (...) {
            return 0;
        }
    }

    // 5. 解包接口
    LIBRARY_API int C_Unpack(const char* pckFile, const char* dest, const char* pwd) {
        try {
            BackupEngine::unpack(pckFile, dest, pwd);
            return 1;
        } catch (...) {
            return 0;
        }
    }
}