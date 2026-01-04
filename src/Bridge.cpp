// src/Bridge.cpp
#include "BackupEngine.h"
#include <cstring>
#include <iostream>

// === 跨平台导出宏定义 ===
#ifdef _WIN32
    #define LIBRARY_API __declspec(dllexport)
#else
    #define LIBRARY_API
#endif

// 定义 Filter 结构体
struct CFilter {
    const char* nameContains;
    const char* pathContains;
    int type;
    int _pad; // <--- [新增] 手动填充4字节，确保后续字段8字节对齐
    unsigned long long minSize;
    unsigned long long maxSize;
    long long startTime;
    int targetUid;
};

extern "C" {

    // ==========================================
    // 1. 基础模式接口 (演示视频 Tab 1 用)
    // ==========================================

    // [修改] 改名为 C_BackupSimple
    LIBRARY_API int C_BackupSimple(const char* src, const char* dest) {
        try {
            BackupEngine::backup(src, dest);
            return 1;
        } catch (...) { return 0; }
    }

    // [修改] 改名为 C_RestoreSimple
    LIBRARY_API int C_RestoreSimple(const char* src, const char* dest) {
        try {
            BackupEngine::restore(src, dest);
            return 1;
        } catch (...) { return 0; }
    }

    // [修改] 改名为 C_VerifySimple
    LIBRARY_API const char* C_VerifySimple(const char* dest) {
        try {
            // 使用 static，让它在函数结束后依然存在
            static std::string g_lastVerifyMsg;
            g_lastVerifyMsg = BackupEngine::verify(dest);
            return g_lastVerifyMsg.c_str();
        } catch (...) {
            return "发生未知异常";
        }
    }

    // ==========================================
    // 2. 高级模式接口 (演示视频 Tab 2 & 3 用)
    // ==========================================

    // 打包接口 (支持加密、压缩、筛选)
    LIBRARY_API int C_PackWithFilter(const char* src, const char* pckFile,
                                     const char* pwd, const int encMode,
                                     const CFilter* c_filter,
                                     int compMode) {
        try {
            std::cout << "\n=== [C++ Bridge Debug] ===" << std::endl;
            std::cout << "源路径: " << src << std::endl;

            auto cppEnc = EncryptionMode::NONE;
            if (encMode == 1) cppEnc = EncryptionMode::XOR;
            else if (encMode == 2) cppEnc = EncryptionMode::RC4;

            auto cppComp = CompressionMode::NONE;
            if (compMode == 1) cppComp = CompressionMode::RLE;

            FilterOptions opts;
            if (c_filter) {
                // 打印调试信息，看看 C++ 到底收到了什么
                std::cout << "接收筛选器配置:" << std::endl;

                if (c_filter->nameContains) {
                    opts.nameContains = c_filter->nameContains;
                    std::cout << "  - 名字含: " << opts.nameContains << std::endl;
                }

                // 路径筛选
                if (c_filter->pathContains) {
                    opts.pathContains = c_filter->pathContains;
                    std::cout << "  - 路径含: " << opts.pathContains << std::endl;
                }

                opts.type = c_filter->type;
                opts.minSize = c_filter->minSize;
                opts.maxSize = c_filter->maxSize;
                opts.startTime = c_filter->startTime;
                opts.targetUid = c_filter->targetUid;

                std::cout << "  - 最小大小: " << opts.minSize << std::endl;
                std::cout << "  - 最大大小: " << opts.maxSize << std::endl;
                std::cout << "  - 起始时间戳: " << opts.startTime << std::endl;
            } else {
                std::cout << "警告: 未收到筛选器指针 (nullptr)" << std::endl;
            }
            std::cout << "==========================\n" << std::endl;

            BackupEngine::pack(src, pckFile, pwd, cppEnc, opts, cppComp);
            return 1;
        } catch (const std::exception& e) {
            std::cerr << "C++ Exception: " << e.what() << std::endl;
            return 0;
        } catch (...) {
            return 0;
        }
    }

    // 解包接口
    LIBRARY_API int C_Unpack(const char* pckFile, const char* dest, const char* pwd) {
        try {
            BackupEngine::unpack(pckFile, dest, pwd);
            return 1;
        } catch (...) { return 0; }
    }
}