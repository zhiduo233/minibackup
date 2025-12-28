// src/Bridge.cpp
#include "BackupEngine.h"
#include <cstring>

// extern "C" 告诉 C++ 编译器：
// "请不要乱改这些函数的名字（No Name Mangling），按 C 语言的标准编译它们"
// 这样 Python 才能找到这些函数。

extern "C" {

    // 1. 备份接口
    // 返回值：1 成功，0 失败
    int C_Backup(const char* src, const char* dest) {
        try {
            BackupEngine::backup(src, dest);
            return 1; // Success
        } catch (...) {
            return 0; // Fail
        }
    }

    // 2. 还原接口
    int C_Restore(const char* src, const char* dest) {
        try {
            BackupEngine::restore(src, dest);
            return 1;
        } catch (...) {
            return 0;
        }
    }

    // 3. 验证接口
    // 返回值：1 通过，0 失败
    int C_Verify(const char* backupDir) {
        // verify 内部自己会打印信息，也会返回 bool
        // 这里简单封装，如果抛出异常也算失败
        try {
            return BackupEngine::verify(backupDir) ? 1 : 0;
        } catch (...) {
            return 0;
        }
    }

    // 4. 打包接口
    // mode: 0=None, 1=XOR, 2=RC4 (对应 int)
    int C_Pack(const char* src, const char* pckFile, const char* pwd, int mode) {
        try {
            // 将 int 转回 C++ 的 enum
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
    int C_Unpack(const char* pckFile, const char* dest, const char* pwd) {
        try {
            BackupEngine::unpack(pckFile, dest, pwd);
            return 1;
        } catch (...) {
            return 0;
        }
    }
}