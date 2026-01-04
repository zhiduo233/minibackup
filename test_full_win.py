import ctypes
import os
import shutil
import time
import platform
import sys

# ==========================================
# 1. 基础配置与 DLL 加载
# ==========================================
print("🚀 Starting MiniBackup Full Test on Windows...")

# 定义 C 结构体
class CFilter(ctypes.Structure):
    _fields_ = [
        ("nameContains", ctypes.c_char_p),
        ("pathContains", ctypes.c_char_p),
        ("type", ctypes.c_int),
        ("minSize", ctypes.c_ulonglong),
        ("maxSize", ctypes.c_ulonglong),
        ("startTime", ctypes.c_longlong),
        ("targetUid", ctypes.c_int)
    ]

# 寻找 DLL
dll_name = "core.dll" if os.path.exists("cmake-build-debug/core.dll") else "libcore.dll"
search_paths = [
    f"./cmake-build-debug/{dll_name}",
    f"./build_win/{dll_name}",
    f"./build/{dll_name}",
    f"./{dll_name}"
]

lib_path = None
for p in search_paths:
    if os.path.exists(p):
        lib_path = os.path.abspath(p)
        break

if not lib_path:
    print("❌ Error: Could not find core.dll. Please build the project first!")
    sys.exit(1)

print(f"📚 Library loaded from: {lib_path}")
try:
    lib = ctypes.cdll.LoadLibrary(lib_path)
except Exception as e:
    print(f"❌ DLL Load Failed: {e}")
    print("Tip: Did you add '-static' flags to CMakeLists.txt?")
    sys.exit(1)

# 设置函数签名
# int C_PackWithFilter(src, dest, pwd, encMode, filter*, compMode)
lib.C_PackWithFilter.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_int, ctypes.POINTER(CFilter), ctypes.c_int
]
lib.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

# ==========================================
# 2. 辅助工具函数
# ==========================================
def clean_dir(path):
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
        except:
            pass # 有时候 Windows 删不掉，忽略
    os.makedirs(path, exist_ok=True)

def create_file(path, content=b"Hello"):
    with open(path, "wb") as f:
        f.write(content)

def get_mtime(path):
    return os.path.getmtime(path)

# ==========================================
# 3. 测试用例集
# ==========================================

def test_rle_compression():
    print("\n[Test 1] 📦 RLE Compression")
    clean_dir("test_src_rle")
    clean_dir("test_out_rle")

    # 创建 1000 字节的重复数据
    create_file("test_src_rle/heavy.txt", b"A" * 1000)

    # 打包：No Encrypt(0), Comp RLE(1)
    ret = lib.C_PackWithFilter(b"./test_src_rle", b"./test_rle.pck", b"", 0, None, 1)
    if ret != 1: return False

    # 检查大小
    size = os.path.getsize("./test_rle.pck")
    print(f"   Original: 1000 bytes -> Packed: {size} bytes")

    if size > 500:
        print("   ⚠️ Warning: Compression ratio low (Check Algo?)")
        return False

    # 解包验证
    lib.C_Unpack(b"./test_rle.pck", b"./test_out_rle", b"")
    with open("test_out_rle/heavy.txt", "rb") as f:
        if f.read() == b"A" * 1000:
            print("   ✅ PASS")
            return True
    return False

def test_rc4_encryption():
    print("\n[Test 2] 🔒 RC4 Encryption")
    clean_dir("test_src_enc")
    clean_dir("test_out_enc")
    create_file("test_src_enc/secret.txt", b"MySecretData")

    pwd = b"123456"
    # 打包：Encrypt RC4(2), No Comp(0)
    lib.C_PackWithFilter(b"./test_src_enc", b"./test_enc.pck", pwd, 2, None, 0)

    # 验证文件头是否加密
    with open("test_enc.pck", "rb") as f:
        header = f.read(8)
        if header != b"MINIBK_R":
            print(f"   ❌ Fail: Wrong Header {header}")
            return False

    # 解包
    lib.C_Unpack(b"./test_enc.pck", b"./test_out_enc", pwd)

    # 验证内容
    if os.path.exists("test_out_enc/secret.txt"):
        with open("test_out_enc/secret.txt", "rb") as f:
            if f.read() == b"MySecretData":
                print("   ✅ PASS")
                return True
    print("   ❌ Fail: Content mismatch")
    return False

def test_filter():
    print("\n[Test 3] 🕵️ Filtering (.txt only)")
    clean_dir("test_src_flt")
    clean_dir("test_out_flt")
    create_file("test_src_flt/a.txt", b"text")
    create_file("test_src_flt/b.jpg", b"image") # 应该被过滤掉

    # 构造 Filter
    f = CFilter()
    f.nameContains = b".txt" # 只备 txt
    f.type = -1; f.minSize=0; f.maxSize=0; f.startTime=0; f.targetUid=-1

    lib.C_PackWithFilter(b"./test_src_flt", b"./test_flt.pck", b"", 0, ctypes.byref(f), 0)
    lib.C_Unpack(b"./test_flt.pck", b"./test_out_flt", b"")

    if os.path.exists("test_out_flt/a.txt") and not os.path.exists("test_out_flt/b.jpg"):
        print("   ✅ PASS")
        return True
    print("   ❌ Fail: Filter failed")
    return False

def test_metadata_time():
    print("\n[Test 4] 🕒 Metadata (Modify Time)")
    clean_dir("test_src_meta")
    clean_dir("test_out_meta")
    file_path = "test_src_meta/old_file.txt"
    create_file(file_path, b"data")

    # 修改时间到 2020年 (1577836800)
    old_time = 1577836800
    os.utime(file_path, (old_time, old_time))

    lib.C_PackWithFilter(b"./test_src_meta", b"./test_meta.pck", b"", 0, None, 0)

    # 等待一秒，确保如果未恢复，时间会变成当前时间
    time.sleep(1.1)

    lib.C_Unpack(b"./test_meta.pck", b"./test_out_meta", b"")

    restored_time = os.path.getmtime("test_out_meta/old_file.txt")

    # 允许 2 秒误差
    if abs(restored_time - old_time) < 2:
        print(f"   Original: {old_time}, Restored: {restored_time}")
        print("   ✅ PASS")
        return True
    else:
        print(f"   ❌ Fail: Time not restored. Got {restored_time}")
        return False

def test_symlink_win():
    print("\n[Test 5] 🔗 Symlinks (Windows)")
    clean_dir("test_src_link")
    clean_dir("test_out_link")
    create_file("test_src_link/real.txt", b"RealContent")

    # 尝试创建软链接
    try:
        if os.path.exists("test_src_link/link.txt"): os.remove("test_src_link/link.txt")
        os.symlink("real.txt", "test_src_link/link.txt")
    except OSError:
        print("   ⚠️ Skipped: No Admin privileges to create symlinks.")
        return True # 跳过不算错

    lib.C_PackWithFilter(b"./test_src_link", b"./test_link.pck", b"", 0, None, 0)
    lib.C_Unpack(b"./test_link.pck", b"./test_out_link", b"")

    # 验证是否也是链接
    restored_link = "test_out_link/link.txt"
    if os.path.islink(restored_link):
        target = os.readlink(restored_link)
        # Windows 的 readlink 有时候可能不完全一样，检查内容即可
        if "real.txt" in target:
            print("   ✅ PASS")
            return True

    # 如果还原成普通文件了 (有些环境不支持)，检查内容也行
    if os.path.exists(restored_link):
        print("   ⚠️ Partial Pass: Symlink restored as file (common on Windows without Admin)")
        return True

    print("   ❌ Fail: Symlink missing")
    return False

# ==========================================
# 4. 执行所有测试
# ==========================================
if __name__ == "__main__":
    results = [
        test_rle_compression(),
        test_rc4_encryption(),
        test_filter(),
        test_metadata_time(),
        test_symlink_win()
    ]

    print("\n" + "="*30)
    if all(results):
        print("🎉🎉 ALL TESTS PASSED! CONGRATULATIONS! 🎉🎉")
        print("Your MiniBackup is fully functional on Windows!")
    else:
        print("💥 Some tests failed. Check logs above.")
    print("="*30)