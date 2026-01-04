import ctypes
import os
import platform
import shutil


# 1. 定义 Filter 结构体 (必须与 Bridge.cpp 一致)
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

# 2. 加载库
current_os = platform.system()
lib_name = ""
if current_os == "Windows":
    # Windows 下通常在 cmake-build-debug 或者 build_win 目录
    # 你可能需要根据实际生成的路径调整这里，或者把 core.dll 复制到脚本旁边
    lib_name = "libcore.dll"
    # 如果是 MinGW 生成的，有时候可能会叫 libcore.dll，请去 build 文件夹看一眼
elif current_os == "Linux":
    lib_name = "libcore.so"
elif current_os == "Darwin":
    lib_name = "libcore.dylib"

# 尝试在几个常见位置查找库
possible_paths = [
    f"./build/{lib_name}",
    f"./build_win/{lib_name}",
    f"./cmake-build-debug/{lib_name}",
    f"./{lib_name}" # 当前目录
]

lib_path = None
for p in possible_paths:
    if os.path.exists(p):
        lib_path = os.path.abspath(p)
        break

if not lib_path:
    print(f"❌ Error: Cannot find {lib_name} in build folders.")
    exit(1)

print(f"Loading library: {lib_path}")
try:
    lib = ctypes.cdll.LoadLibrary(lib_path)
except OSError as e:
    print(f"❌ Load Error: {e}")
    print("Tip: On Windows, make sure libgcc_s_dw2-1.dll etc. are in PATH if using MinGW.")
    exit(1)

# 3. 【重点】设置函数参数类型
# int C_PackWithFilter(src, pck, pwd, encMode, filter*, compMode)
# 现在是 6 个参数,最后一个是 int (compMode)
lib.C_PackWithFilter.argtypes = [
    ctypes.c_char_p,        # src
    ctypes.c_char_p,        # dest
    ctypes.c_char_p,        # pwd
    ctypes.c_int,           # encMode
    ctypes.POINTER(CFilter),# filter
    ctypes.c_int            # compMode <--- 新增的
]

# 设置 Unpack 参数类型
lib.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

# 4. 准备测试数据 (造一个重复字符很多的文件，rle RLE 效果)
if os.path.exists("rle"):
    shutil.rmtree("rle")
if os.path.exists("rle_out"):
    shutil.rmtree("rle_out")
if os.path.exists("compressed.pck"):
    os.remove("compressed.pck")

os.makedirs("rle", exist_ok=True)
os.makedirs("rle_out", exist_ok=True)

# 写入 1000 个 'A'。如果不压缩占 1000 字节，RLE压缩后应该极小。
content = b"A" * 1000
with open("rle/big_file.txt", "wb") as f:
    f.write(content)

print(f"[Init] Created file with 1000 'A's. Size: {os.path.getsize('rle/big_file.txt')} bytes")

# 5. 执行打包 (开启 RLE)
src = "rle"
pck = b"./compressed.pck"
pwd = b"" # 不加密
enc_mode = 0 # None
comp_mode = 1 # 1 = RLE (我们刚写的)

print("-" * 30)
print("Running Pack with RLE Compression (compMode=1)...")

# 传参：filter 传 None (空指针)，compMode 传 1
result = lib.C_PackWithFilter(
    src.encode('utf-8'),
    pck,
    pwd,
    enc_mode,
    None,
    comp_mode
)

if result == 1:
    print("Pack Success!")
    # 验证文件大小
    pck_size = os.path.getsize(pck)
    print(f"Packed File Size: {pck_size} bytes")

    if pck_size < 500:
        print("✅ PASS: File size significantly reduced! RLE is working.")
    else:
        print("❌ FAIL: File size did not decrease much.")
else:
    print("❌ Pack Failed.")
    exit(1)

# 6. 执行解包 (验证还原)
print("-" * 30)
print("Running Unpack...")
dest = b"./rle_out"
lib.C_Unpack(pck, dest, pwd)

# 验证内容
restored_file = "rle_out/big_file.txt"
if os.path.exists(restored_file):
    with open(restored_file, "rb") as f:
        new_content = f.read()

    if new_content == content:
        print(f"✅ PASS: Content matches perfectly ({len(new_content)} bytes).")
    else:
        print("❌ FAIL: Content mismatch!")
else:
    print("❌ FAIL: Restored file not found.")