import ctypes
import os

# 1. 定义 C 结构体 (必须与 Bridge.cpp 里的顺序完全一致)
class CFilter(ctypes.Structure):
    _fields_ = [
        ("nameContains", ctypes.c_char_p),  # string
        ("pathContains", ctypes.c_char_p),  # string
        ("type", ctypes.c_int),             # int
        ("minSize", ctypes.c_ulonglong),    # uint64
        ("maxSize", ctypes.c_ulonglong),    # uint64
        ("startTime", ctypes.c_longlong),   # long long
        ("targetUid", ctypes.c_int)         # int
    ]

# 2. 加载 C++ 动态库
# 注意：在 Linux 下是 libcore.so
lib_path = os.path.abspath("./build/libcore.so")
print(f"Loading library: {lib_path}")
lib = ctypes.cdll.LoadLibrary(lib_path)

# 3. 定义函数签名 (防止传参错误导致 SegFault)
# int C_PackWithFilter(src, dest, pwd, mode, filter)
lib.C_PackWithFilter.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.POINTER(CFilter)  # <--- 重点：这里变成了指针类型
]
lib.C_PackWithFilter.restype = ctypes.c_int

# 4. 准备测试参数
src_dir = b"./filter_test_src"
dst_file = b"./filtered_result.pck"
password = b"" # 不加密
mode = 0       # 0=None

# 5. 【核心】构造筛选器：只备份包含 ".txt" 的文件
my_filter = CFilter()
my_filter.nameContains = b""
my_filter.pathContains = None
my_filter.type = -1
my_filter.minSize = 0
my_filter.maxSize = 0
my_filter.startTime = 0
my_filter.targetUid = -1

# 6. 调用 C++ 接口
print("-" * 30)
print("Python: Calling C++ to pack ONLY .txt files...")
result = lib.C_PackWithFilter(src_dir, dst_file, password, mode, ctypes.byref(my_filter)) # <--- 重点：byref

if result == 1:
    print("Python: Success! Pack created.")
else:
    print("Python: Failed to pack.")
    exit(1)

# 7. 验证环节：解包看看里面到底有什么
# 我们直接调用 C_Unpack (不需要 filter) 来验证
print("-" * 30)
print("Python: Unpacking to verify content...")
unpack_dest = b"./verify_filter_output"

# 这是一个复用旧接口的例子
lib.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.C_Unpack(dst_file, unpack_dest, password)

print("Python: Test Finished. Please check 'verify_filter_output' folder.")